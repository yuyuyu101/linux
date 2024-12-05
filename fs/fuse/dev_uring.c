// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE: Filesystem in Userspace
 * Copyright (c) 2023-2024 DataDirect Networks.
 */

#include <linux/fs.h>

#include "fuse_i.h"
#include "dev_uring_i.h"
#include "fuse_dev_i.h"

#include <linux/io_uring/cmd.h>

#ifdef CONFIG_FUSE_IO_URING
static bool __read_mostly enable_uring;
module_param(enable_uring, bool, 0644);
MODULE_PARM_DESC(enable_uring,
		 "Enable uring userspace communication through uring.");
#endif

bool fuse_uring_enabled(void)
{
	return enable_uring;
}

static int fuse_ring_ent_unset_userspace(struct fuse_ring_ent *ent)
{
	struct fuse_ring_queue *queue = ent->queue;

	lockdep_assert_held(&queue->lock);

	if (WARN_ON_ONCE(ent->state != FRRS_USERSPACE))
		return -EIO;

	ent->state = FRRS_COMMIT;
	list_move(&ent->list, &queue->ent_commit_queue);

	return 0;
}

void fuse_uring_destruct(struct fuse_conn *fc)
{
	struct fuse_ring *ring = fc->ring;
	int qid;

	if (!ring)
		return;

	for (qid = 0; qid < ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue = ring->queues[qid];

		if (!queue)
			continue;

		WARN_ON(!list_empty(&queue->ent_avail_queue));
		WARN_ON(!list_empty(&queue->ent_commit_queue));

		kfree(queue);
		ring->queues[qid] = NULL;
	}

	kfree(ring->queues);
	kfree(ring);
	fc->ring = NULL;
}

#define FUSE_URING_IOV_SEGS 2 /* header and payload */

/*
 * Basic ring setup for this connection based on the provided configuration
 */
static struct fuse_ring *fuse_uring_create(struct fuse_conn *fc)
{
	struct fuse_ring *ring = NULL;
	size_t nr_queues = num_possible_cpus();
	struct fuse_ring *res = NULL;

	ring = kzalloc(sizeof(*fc->ring) +
			       nr_queues * sizeof(struct fuse_ring_queue),
		       GFP_KERNEL_ACCOUNT);
	if (!ring)
		return NULL;

	ring->queues = kcalloc(nr_queues, sizeof(struct fuse_ring_queue *),
			       GFP_KERNEL_ACCOUNT);
	if (!ring->queues)
		goto out_err;

	spin_lock(&fc->lock);
	if (fc->ring) {
		/* race, another thread created the ring in the mean time */
		spin_unlock(&fc->lock);
		res = fc->ring;
		goto out_err;
	}

	fc->ring = ring;
	ring->nr_queues = nr_queues;
	ring->fc = fc;

	spin_unlock(&fc->lock);
	return ring;

out_err:
	if (ring)
		kfree(ring->queues);
	kfree(ring);
	return res;
}

static struct fuse_ring_queue *fuse_uring_create_queue(struct fuse_ring *ring,
						       int qid)
{
	struct fuse_conn *fc = ring->fc;
	struct fuse_ring_queue *queue;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL_ACCOUNT);
	if (!queue)
		return ERR_PTR(-ENOMEM);
	spin_lock(&fc->lock);
	if (ring->queues[qid]) {
		spin_unlock(&fc->lock);
		kfree(queue);
		return ring->queues[qid];
	}

	queue->qid = qid;
	queue->ring = ring;
	spin_lock_init(&queue->lock);

	INIT_LIST_HEAD(&queue->ent_avail_queue);
	INIT_LIST_HEAD(&queue->ent_commit_queue);

	WRITE_ONCE(ring->queues[qid], queue);
	spin_unlock(&fc->lock);

	return queue;
}

/*
 * Make a ring entry available for fuse_req assignment
 */
static void fuse_uring_ent_avail(struct fuse_ring_ent *ring_ent,
				 struct fuse_ring_queue *queue)
{
	list_move(&ring_ent->list, &queue->ent_avail_queue);
	ring_ent->state = FRRS_WAIT;
}

/*
 * fuse_uring_req_fetch command handling
 */
static void _fuse_uring_fetch(struct fuse_ring_ent *ring_ent,
			      struct io_uring_cmd *cmd,
			      unsigned int issue_flags)
{
	struct fuse_ring_queue *queue = ring_ent->queue;

	spin_lock(&queue->lock);
	fuse_uring_ent_avail(ring_ent, queue);
	ring_ent->cmd = cmd;
	spin_unlock(&queue->lock);
}

/*
 * sqe->addr is a ptr to an iovec array, iov[0] has the headers, iov[1]
 * the payload
 */
static int fuse_uring_get_iovec_from_sqe(const struct io_uring_sqe *sqe,
					 struct iovec iov[FUSE_URING_IOV_SEGS])
{
	struct iovec __user *uiov = u64_to_user_ptr(READ_ONCE(sqe->addr));
	struct iov_iter iter;
	ssize_t ret;

	if (sqe->len != FUSE_URING_IOV_SEGS)
		return -EINVAL;

	/*
	 * Direction for buffer access will actually be READ and WRITE,
	 * using write for the import should include READ access as well.
	 */
	ret = import_iovec(WRITE, uiov, FUSE_URING_IOV_SEGS,
			   FUSE_URING_IOV_SEGS, &iov, &iter);
	if (ret < 0)
		return ret;

	return 0;
}

static int fuse_uring_fetch(struct io_uring_cmd *cmd, unsigned int issue_flags,
			    struct fuse_conn *fc)
{
	const struct fuse_uring_cmd_req *cmd_req = io_uring_sqe_cmd(cmd->sqe);
	struct fuse_ring *ring = fc->ring;
	struct fuse_ring_queue *queue;
	struct fuse_ring_ent *ring_ent;
	int err;
	struct iovec iov[FUSE_URING_IOV_SEGS];

	err = fuse_uring_get_iovec_from_sqe(cmd->sqe, iov);
	if (err) {
		pr_info_ratelimited("Failed to get iovec from sqe, err=%d\n",
				    err);
		return err;
	}

	err = -ENOMEM;
	if (!ring) {
		ring = fuse_uring_create(fc);
		if (!ring)
			return err;
	}

	queue = ring->queues[cmd_req->qid];
	if (!queue) {
		queue = fuse_uring_create_queue(ring, cmd_req->qid);
		if (!queue)
			return err;
	}

	/*
	 * The created queue above does not need to be destructed in
	 * case of entry errors below, will be done at ring destruction time.
	 */

	ring_ent = kzalloc(sizeof(*ring_ent), GFP_KERNEL_ACCOUNT);
	if (ring_ent == NULL)
		return err;

	INIT_LIST_HEAD(&ring_ent->list);

	ring_ent->queue = queue;
	ring_ent->cmd = cmd;

	err = -EINVAL;
	if (iov[0].iov_len < sizeof(struct fuse_uring_req_header)) {
		pr_info_ratelimited("Invalid header len %zu\n", iov[0].iov_len);
		goto err;
	}

	ring_ent->headers = iov[0].iov_base;
	ring_ent->payload = iov[1].iov_base;
	ring_ent->max_arg_len = iov[1].iov_len;

	if (ring_ent->max_arg_len <
	    max_t(size_t, FUSE_MIN_READ_BUFFER, fc->max_write)) {
		pr_info_ratelimited("Invalid req payload len %zu\n",
				    ring_ent->max_arg_len);
		goto err;
	}

	spin_lock(&queue->lock);

	/*
	 * FUSE_URING_REQ_FETCH is an initialization exception, needs
	 * state override
	 */
	ring_ent->state = FRRS_USERSPACE;
	err = fuse_ring_ent_unset_userspace(ring_ent);
	spin_unlock(&queue->lock);
	if (WARN_ON_ONCE(err != 0))
		goto err;

	_fuse_uring_fetch(ring_ent, cmd, issue_flags);

	return 0;
err:
	list_del_init(&ring_ent->list);
	kfree(ring_ent);
	return err;
}

/*
 * Entry function from io_uring to handle the given passthrough command
 * (op cocde IORING_OP_URING_CMD)
 */
int fuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags)
{
	struct fuse_dev *fud;
	struct fuse_conn *fc;
	u32 cmd_op = cmd->cmd_op;
	int err;

	/* Disabled for now, especially as teardown is not implemented yet */
	pr_info_ratelimited("fuse-io-uring is not enabled yet\n");
	return -EOPNOTSUPP;

	if (!enable_uring) {
		pr_info_ratelimited("fuse-io-uring is disabled\n");
		return -EOPNOTSUPP;
	}

	fud = fuse_get_dev(cmd->file);
	if (!fud) {
		pr_info_ratelimited("No fuse device found\n");
		return -ENOTCONN;
	}
	fc = fud->fc;

	if (!fc->connected || fc->aborted)
		return fc->aborted ? -ECONNABORTED : -ENOTCONN;

	switch (cmd_op) {
	case FUSE_URING_REQ_FETCH:
		err = fuse_uring_fetch(cmd, issue_flags, fc);
		if (err) {
			pr_info_once("fuse_uring_fetch failed err=%d\n", err);
			return err;
		}
		break;
	default:
		return -EINVAL;
	}

	return -EIOCBQUEUED;
}

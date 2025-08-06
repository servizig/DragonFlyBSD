/*
 * Copyright (c) 2019-2020 Jonathan Gray <jsg@openbsd.org>
 * Copyright (c) 2020 François Tigeot <ftigeot@wolfpond.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/slab.h>
#include <linux/dma-fence.h>

static struct dma_fence dma_fence_stub;
static struct lock dma_fence_stub_lock = LOCK_INITIALIZER("dmafenstubl", 0, 0);


static const char *
dma_fence_stub_get_name(struct dma_fence *fence)
{

	return ("stub");
}

static const struct dma_fence_ops dma_fence_stub_ops = {
	.get_driver_name = dma_fence_stub_get_name,
	.get_timeline_name = dma_fence_stub_get_name,
};

/*
 * return a signaled fence
 */
struct dma_fence *
dma_fence_get_stub(void)
{
	lockmgr(&dma_fence_stub_lock, LK_EXCLUSIVE);
	if (dma_fence_stub.ops == NULL) {
		dma_fence_init(&dma_fence_stub,
		    &dma_fence_stub_ops,
		    &dma_fence_stub_lock,
		    0,
		    0);
		set_bit(DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT,
		    &dma_fence_stub.flags);
		dma_fence_signal_locked(&dma_fence_stub);
	}
	lockmgr(&dma_fence_stub_lock, LK_RELEASE);
	return (dma_fence_get(&dma_fence_stub));
}

void
dma_fence_init(struct dma_fence *fence, const struct dma_fence_ops *ops,
    spinlock_t *lock, u64 context, unsigned seqno)
{
	fence->ops = ops;
	fence->lock = lock;
	fence->context = context;
	fence->seqno = seqno;
	fence->flags = 0;
	fence->error = 0;
	kref_init(&fence->refcount);
	INIT_LIST_HEAD(&fence->cb_list);
}

void
dma_fence_release(struct kref *ref)
{
	struct dma_fence *fence = container_of(ref, struct dma_fence, refcount);

	if (fence->ops && fence->ops->release)
		fence->ops->release(fence);
	else
		kfree(fence);
}

long
dma_fence_wait_timeout(struct dma_fence *fence, bool intr, long timeout)
{
	if (timeout < 0)
		return -EINVAL;

	if (fence->ops->wait)
		return fence->ops->wait(fence, intr, timeout);
	else
		return dma_fence_default_wait(fence, intr, timeout);
}

static atomic64_t drm_fence_context_count = ATOMIC_INIT(1);

u64
dma_fence_context_alloc(unsigned num)
{
	return atomic64_add_return(num, &drm_fence_context_count) - num;
}

struct default_wait_cb {
	struct dma_fence_cb base;
	void *wake_id;
};

static void
dma_fence_default_wait_cb(struct dma_fence *fence, struct dma_fence_cb *cb)
{
	struct default_wait_cb *wait =
		container_of(cb, struct default_wait_cb, base);

	//wake_up_process(wait->task);
	wakeup(wait->wake_id);
}

long
dma_fence_default_wait(struct dma_fence *fence, bool intr, signed long timeout)
{
	long ret = timeout ? timeout : 1;
	int wake_id = 0;
	int err;
	struct default_wait_cb cb;
	bool was_set;

	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags))
		return ret;

	crit_enter();
	lockmgr(fence->lock, LK_EXCLUSIVE);

	was_set = test_and_set_bit(DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT,
	    &fence->flags);

	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags))
		goto out;

	if (!was_set && fence->ops->enable_signaling) {
		if (!fence->ops->enable_signaling(fence)) {
			dma_fence_signal_locked(fence);
			goto out;
		}
	}

	if (timeout == 0) {
		ret = 0;
		goto out;
	}

	cb.base.func = dma_fence_default_wait_cb;
	cb.wake_id = &wake_id;
	list_add(&cb.base.node, &fence->cb_list);

	tsleep_interlock(&wake_id, (intr ? PCATCH : 0));
	while (!test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags)) {
		/* can sleep with a crit section held */
		err = lksleep(&wake_id, fence->lock,
			      (intr ? PCATCH : 0) | PINTERLOCKED,
			      "dmafence", timeout);
		if (err == EINTR || err == ERESTART) {
			ret = -ERESTARTSYS;
			break;
		} else if (err == EWOULDBLOCK) {
			ret = 0;
			break;
		}
		tsleep_interlock(&wake_id, (intr ? PCATCH : 0));
	}

	if (!list_empty(&cb.base.node))
		list_del(&cb.base.node);
out:
	crit_exit();
	lockmgr(fence->lock, LK_RELEASE);
	return ret;
}

static bool
dma_fence_test_signaled_any(struct dma_fence **fences, uint32_t count,
			    uint32_t *idx)
{
	int i;

	for (i = 0; i < count; ++i) {
		struct dma_fence *fence = fences[i];
		if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags)) {
			if (idx)
				*idx = i;
			return true;
		}
	}
	return false;
}

long
dma_fence_wait_any_timeout(struct dma_fence **fences, uint32_t count,
			   bool intr, long timeout, uint32_t *idx)
{
	struct default_wait_cb *cb;
	long ret = timeout;
	int wake_id = 0;
	unsigned long end;
	int i, err;

	if (timeout == 0) {
		for (i = 0; i < count; i++) {
			if (dma_fence_is_signaled(fences[i])) {
				if (idx)
					*idx = i;
				return 1;
			}
		}
		return 0;
	}

	cb = kcalloc(count, sizeof(struct default_wait_cb), GFP_KERNEL);
	if (cb == NULL)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		struct dma_fence *fence = fences[i];
		cb[i].wake_id = &wake_id;
		if (dma_fence_add_callback(fence, &cb[i].base,
					   dma_fence_default_wait_cb))
	        {
			if (idx)
				*idx = i;
			goto cb_cleanup;
		}
	}

	end = jiffies + timeout;
	for (ret = timeout; ret > 0; ret = MAX(0, end - jiffies)) {
		tsleep_interlock(&wake_id, (intr ? PCATCH : 0));
		if (dma_fence_test_signaled_any(fences, count, idx))
			break;
		err = tsleep(&wake_id, (intr ? PCATCH : 0) | PINTERLOCKED,
			     "dfwat", ret);
		if (err == EINTR || err == ERESTART) {
			ret = -ERESTARTSYS;
			break;
		}
	}

cb_cleanup:
	while (i-- > 0)
		dma_fence_remove_callback(fences[i], &cb[i].base);
	kfree(cb);

	return ret;
}

int
dma_fence_signal_locked(struct dma_fence *fence)
{
#if 1
	struct dma_fence_cb *cur, *tmp;
	int ret = 0;

	if (fence == NULL)
		return -EINVAL;

	if (test_and_set_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags)) {
		ret = -EINVAL;
	} else {
		fence->timestamp = ktime_get();
		set_bit(DMA_FENCE_FLAG_TIMESTAMP_BIT, &fence->flags);
	}

	list_for_each_entry_safe(cur, tmp, &fence->cb_list, node) {
		INIT_LIST_HEAD(&cur->node);
		cur->func(fence, cur);
	}

	return ret;
#else
	struct dma_fence_cb *cur, *tmp;
	struct list_head cb_list;

	if (fence == NULL)
		return -EINVAL;

	if (test_and_set_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags))
		return -EINVAL;

	list_replace(&fence->cb_list, &cb_list);

	fence->timestamp = ktime_get();
	set_bit(DMA_FENCE_FLAG_TIMESTAMP_BIT, &fence->flags);

	list_for_each_entry_safe(cur, tmp, &cb_list, node) {
		INIT_LIST_HEAD(&cur->node);
		cur->func(fence, cur);
	}

	return 0;
#endif
}

int
dma_fence_signal(struct dma_fence *fence)
{
#if 1
	struct dma_fence_cb *cur, *tmp;

	if (fence == NULL)
		return -EINVAL;

	if (test_and_set_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags)) {
		return  -EINVAL;
	}

	fence->timestamp = ktime_get();
	set_bit(DMA_FENCE_FLAG_TIMESTAMP_BIT, &fence->flags);

	if (test_bit(DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT, &fence->flags)) {
		lockmgr(fence->lock, LK_EXCLUSIVE);
		list_for_each_entry_safe(cur, tmp, &fence->cb_list, node) {
			INIT_LIST_HEAD(&cur->node);
			cur->func(fence, cur);
		}
		lockmgr(fence->lock, LK_RELEASE);
	}
	return 0;
#else
	int r;

	if (fence == NULL)
		return -EINVAL;

	crit_enter();
	lockmgr(fence->lock, LK_EXCLUSIVE);
	r = dma_fence_signal_locked(fence);
	lockmgr(fence->lock, LK_RELEASE);
	crit_exit();

	return r;
#endif
}

void
dma_fence_enable_sw_signaling(struct dma_fence *fence)
{
	if (!test_and_set_bit(DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT, &fence->flags) &&
	    !test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags) &&
	    fence->ops->enable_signaling) {
		//crit_enter();
		lockmgr(fence->lock, LK_EXCLUSIVE);
		if (!fence->ops->enable_signaling(fence))
			dma_fence_signal_locked(fence);
		lockmgr(fence->lock, LK_RELEASE);
		//crit_exit();
	}
}

int
dma_fence_add_callback(struct dma_fence *fence, struct dma_fence_cb *cb,
    dma_fence_func_t func)
{
	int ret = 0;
	bool was_set;

	if (WARN_ON(!fence || !func))
		return -EINVAL;

	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags)) {
		INIT_LIST_HEAD(&cb->node);
		return -ENOENT;
	}

	crit_enter();
	lockmgr(fence->lock, LK_EXCLUSIVE);

	was_set = test_and_set_bit(DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT, &fence->flags);

	if (test_bit(DMA_FENCE_FLAG_SIGNALED_BIT, &fence->flags))
		ret = -ENOENT;
	else if (!was_set && fence->ops->enable_signaling) {
		if (!fence->ops->enable_signaling(fence)) {
			dma_fence_signal_locked(fence);
			ret = -ENOENT;
		}
	}

	if (!ret) {
		cb->func = func;
		list_add_tail(&cb->node, &fence->cb_list);
	} else
		INIT_LIST_HEAD(&cb->node);
	lockmgr(fence->lock, LK_RELEASE);
	crit_exit();

	return ret;
}

bool
dma_fence_remove_callback(struct dma_fence *fence, struct dma_fence_cb *cb)
{
	bool ret;

	crit_enter();
	lockmgr(fence->lock, LK_EXCLUSIVE);

	ret = !list_empty(&cb->node);
	if (ret)
		list_del_init(&cb->node);

	lockmgr(fence->lock, LK_RELEASE);
	crit_exit();

	return ret;
}

void
dma_fence_free(struct dma_fence *fence)
{
	kfree(fence);
}

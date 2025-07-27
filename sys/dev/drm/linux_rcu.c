/*
 * Copyright (c) 2020 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Brute-force implementation for linux RCU functions.  Just use a delay
 * line and per-cpu callouts.
 */
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/spinlock.h>
#include <sys/exislock.h>
#include <sys/spinlock2.h>
#include <sys/exislock2.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

#include <machine/atomic.h>

typedef struct rcu_elm {
	enum { RCU_NULL, RCU_CALL } type;
	void	(*func)(struct rcu_head *arg);
	void	*ptr;
} rcu_elm_t;

typedef struct rcu_pcpu {
	rcu_elm_t *elms;
	int	size;
	int	mask;
	int	s;
	int	e;
	int	running;
	int	unused01;
	struct callout timer_callout;
} rcu_pcpu_t;

static rcu_pcpu_t rcus;

/*
 * If this winds up being too much of a mess, just punt and use this
 * to actually implement RCU
 */
struct lock linux_rcu_lock = LOCK_INITIALIZER("rculk", 0, LK_CANRECURSE);

void
rcu_read_lock(void)
{
	lockmgr(&linux_rcu_lock, LK_SHARED);
	//exis_hold();
}

void
rcu_read_unlock(void)
{
	//exis_drop();
	lockmgr(&linux_rcu_lock, LK_RELEASE);
}

static void
rcu_callback_barrier(struct rcu_head *ptr)
{
	*(volatile long *)ptr = 1;
	wakeup(ptr);
}

void
rcu_barrier(void)
{
	volatile long wval = 0;

	call_rcu((void *)&wval, rcu_callback_barrier);
	while (wval == 0)
		tsleep(&wval, 0, "rcubar", hz);
}

#if 0
static inline void
synchronize_rcu_expedited(void)
{
	rcu_barrier();
}
#endif

static void
rcu_callback_kfree(struct rcu_head *ptr)
{
	kfree(ptr);
}

/*
 * Timer callout (pcpu)
 */
static void
rcu_timer(void *arg)
{
	rcu_pcpu_t *rcu = arg;
	rcu_elm_t *elm;

	if (lockmgr(&linux_rcu_lock, LK_EXCLUSIVE | LK_NOWAIT)) {
		callout_reset_bycpu(&rcu->timer_callout, 1, rcu_timer,
				    rcu, mycpuid);
		return;
	}

	while (rcu->s != rcu->e) {
		elm = &rcu->elms[rcu->s & rcu->mask];

		lockmgr(&linux_rcu_lock, LK_RELEASE);

		switch(elm->type) {
		case RCU_NULL:
			break;
		case RCU_CALL:
			elm->func(elm->ptr);
			break;
		}
		lockmgr(&linux_rcu_lock, LK_EXCLUSIVE);

		elm->type = RCU_NULL;
		++rcu->s;
	}
	if (rcu->s == rcu->e) {
		rcu->running = 0;
	} else {
		callout_reset_bycpu(&rcu->timer_callout, 1, rcu_timer,
				    rcu, mycpuid);
	}
	lockmgr(&linux_rcu_lock, LK_RELEASE);
}

/*
 * Expand the rcu array for the current cpu
 */
static void
rcu_expand(rcu_pcpu_t *rcu)
{
	rcu_elm_t *oelms;
	rcu_elm_t *nelms;
	int count;
	int nsize;
	int nmask;
	int n;

	count = rcu->e - rcu->s;	/* note: 2s complement underflow */
	while (unlikely(count == rcu->size)) {
		nsize = count ? count * 2 : 16;
		nelms = kzalloc(nsize * sizeof(*nelms), GFP_KERNEL);
		kprintf("drm: expand RCU cpu %d to %d\n", mycpuid, nsize);
		if (likely(count == rcu->size)) {
			nmask = nsize - 1;
			oelms = rcu->elms;
			n = rcu->s;
			while (n != rcu->e) {
				nelms[n & nmask] = oelms[n & rcu->mask];
				++n;
			}
			rcu->elms = nelms;
			rcu->size = nsize;
			rcu->mask = nmask;
			nelms = oelms;
		}
		if (likely(nelms != NULL))
			kfree(nelms);
		count = rcu->e - rcu->s;
	}
	KKASSERT(count >= 0 && count < rcu->size);
}

void
call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *))
{
	rcu_pcpu_t *rcu;
	rcu_elm_t *elm;

	rcu = &rcus;

	lockmgr(&linux_rcu_lock, LK_EXCLUSIVE);

	rcu_expand(rcu);
	elm = &rcu->elms[rcu->e & rcu->mask];
	++rcu->e;

	elm->type = RCU_CALL;
	elm->func = func;
	elm->ptr = head;

	if (rcu->running == 0) {
		rcu->running = 1;
		callout_reset_bycpu(&rcu->timer_callout, 1, rcu_timer,
				    rcu, mycpuid);
	}
	lockmgr(&linux_rcu_lock, LK_RELEASE);
}

void
__kfree_rcu(void *ptr)
{
	call_rcu(ptr, rcu_callback_kfree);
}

static int
init_rcu(void *dummy __unused)
{
	callout_init_mp(&rcus.timer_callout);

	return 0;
}

#if 0
/*
 * Timer callout (pcpu)
 */
static void
rcu_timer(void *arg)
{
	rcu_pcpu_t *rcu = arg;
	rcu_elm_t *elm;
	long delta;

	crit_enter();
	while (rcu->s != rcu->e) {
		elm = &rcu->elms[rcu->s & rcu->mask];

		delta = pseudo_ticks - elm->pticks;
		if (delta < 1)
			break;

		switch(elm->type) {
		case RCU_NULL:
			break;
		case RCU_CALL:
			elm->func(elm->ptr);
			break;
		case RCU_FREE:
			kfree(elm->ptr);
			break;
		}
		elm->type = RCU_NULL;
		++rcu->s;
	}
	if (rcu->s == rcu->e) {
		rcu->running = 0;
	} else {
		callout_reset_bycpu(&rcu->timer_callout, 1, rcu_timer,
				    rcu, mycpuid);
	}
	crit_exit();
}


/*
 * Ping timer callout (pcpu).
 *
 * Must be in critical section.
 */
static void
rcu_ping(rcu_pcpu_t *rcu)
{
	if (rcu->running == 0) {
		rcu->running = 1;
		callout_reset_bycpu(&rcu->timer_callout, hz / 10, rcu_timer,
				    rcu, mycpuid);
	}
}

/*
 * Expand the rcu array for the current cpu
 */
static void
rcu_expand(rcu_pcpu_t *rcu)
{
	rcu_elm_t *oelms;
	rcu_elm_t *nelms;
	int count;
	int nsize;
	int nmask;
	int n;

	count = rcu->e - rcu->s;	/* note: 2s complement underflow */
	while (unlikely(count == rcu->size)) {
		nsize = count ? count * 2 : 16;
		nelms = kzalloc(nsize * sizeof(*nelms), GFP_KERNEL);
		kprintf("drm: expand RCU cpu %d to %d\n", mycpuid, nsize);
		if (likely(count == rcu->size)) {
			nmask = nsize - 1;
			oelms = rcu->elms;
			n = rcu->s;
			while (n != rcu->e) {
				nelms[n & nmask] = oelms[n & rcu->mask];
				++n;
			}
			rcu->elms = nelms;
			rcu->size = nsize;
			rcu->mask = nmask;
			nelms = oelms;
		}
		if (likely(nelms != NULL))
			kfree(nelms);
		count = rcu->e - rcu->s;
	}
	KKASSERT(count >= 0 && count < rcu->size);
}

void
kfree_rcu(void *ptr, void *rcu __unused)
{
	rcu_pcpu_t *rcu;
	rcu_elm_t *elm;

	if (unlikely(rcupcpu == NULL)) {
		kfree(ptr);
		return;
	}
	rcu = &rcupcpu[mycpuid];

	crit_enter();
	rcu_expand(rcu);
	elm = &rcu->elms[rcu->e & rcu->mask];
	++rcu->e;

	elm->type = RCU_FREE;
	elm->pticks = pseudo_ticks;
	elm->ptr = ptr;

	rcu_ping(rcu);
	crit_exit();
}

void
call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *))
{
	rcu_pcpu_t *rcu;
	rcu_elm_t *elm;

	if (unlikely(rcupcpu == NULL)) {
		func(head);
		return;
	}
	rcu = &rcupcpu[mycpuid];

	crit_enter();
	rcu_expand(rcu);
	elm = &rcu->elms[rcu->e & rcu->mask];
	++rcu->e;

	elm->type = RCU_CALL;
	elm->pticks = pseudo_ticks;
	elm->func = func;
	elm->ptr = head;

	rcu_ping(rcu);
	crit_exit();
}

static int
init_rcu(void *dummy __unused)
{
	int i;

	rcupcpu = kzalloc(ncpus * sizeof(*rcupcpu), GFP_KERNEL);
	for (i = 0; i < ncpus; ++i) {
		callout_init_mp(&rcupcpu[i].timer_callout);
	}
	return 0;
}
#endif

SYSINIT(linux_rcu_init, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, init_rcu, NULL);

/*-
 * Copyright (c) 2017 Hans Petter Selasky
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/gtaskqueue.h>
#include <sys/proc.h>
#include <sys/sched.h>

#include <linux/compiler.h>
#include <linux/interrupt.h>
#include <linux/compat.h>
#include <linux/vmalloc.h>

#define	TASKLET_ST_IDLE 0
#define	TASKLET_ST_BUSY 1
#define	TASKLET_ST_EXEC 2
#define	TASKLET_ST_LOOP 3

#define	TASKLET_ST_CMPSET(ts, old, new)	\
	atomic_cmpset_int((volatile u_int *)&(ts)->tasklet_state, old, new)

#define	TASKLET_ST_SET(ts, new)	\
	WRITE_ONCE(*(volatile u_int *)&(ts)->tasklet_state, new)

#define	TASKLET_ST_GET(ts) \
	READ_ONCE(*(volatile u_int *)&(ts)->tasklet_state)

struct tasklet_worker {
	struct lock mtx;
	TAILQ_HEAD(tasklet_list, tasklet_struct) head;
	struct grouptask gtask;
}
#if 0
__aligned(CACHE_LINE_SIZE)
#endif
;

static struct tasklet_worker *tasklet_workers;

#define	TASKLET_WORKER_LOCK(tw) lockmgr(&(tw)->mtx, LK_EXCLUSIVE)
#define	TASKLET_WORKER_UNLOCK(tw) lockmgr(&(tw)->mtx, LK_RELEASE)

#if 0
DPCPU_DEFINE_STATIC(struct tasklet_worker, tasklet_worker);
#endif

static void
tasklet_handler(void *arg)
{
	struct tasklet_worker *tw = (struct tasklet_worker *)arg;
	struct tasklet_struct *ts;
	struct tasklet_struct *last;

#if 0
	linux_set_current(curthread);
#endif

	TASKLET_WORKER_LOCK(tw);
	last = TAILQ_LAST(&tw->head, tasklet_list);
	while (1) {
		ts = TAILQ_FIRST(&tw->head);
		if (ts == NULL)
			break;
		TAILQ_REMOVE(&tw->head, ts, entry);

		if (!atomic_read(&ts->count)) {
			TASKLET_WORKER_UNLOCK(tw);
			do {
				/* reset executing state */
				TASKLET_ST_SET(ts, TASKLET_ST_EXEC);

				if (ts->use_callback)
					ts->callback(ts);
				else
					ts->func(ts->data);

			} while (TASKLET_ST_CMPSET(ts, TASKLET_ST_EXEC,
			        TASKLET_ST_IDLE) == 0);
			TASKLET_WORKER_LOCK(tw);
		} else {
			TAILQ_INSERT_TAIL(&tw->head, ts, entry);
		}
		if (ts == last)
			break;
	}
	TASKLET_WORKER_UNLOCK(tw);
}

static void
tasklet_subsystem_init(void *arg __unused)
{
	struct tasklet_worker *tw;
	char buf[32];
	int i;

	tasklet_workers = vzalloc(sizeof(struct tasklet_worker) * ncpus);

	for ((i) = 0; (i) <= ncpus; (i)++) {
#if 0
		if (CPU_ABSENT(i))
			continue;
#endif

#if 0
		tw = DPCPU_ID_PTR(i, tasklet_worker);
#endif
		tw = &tasklet_workers[i];

		lockinit(&tw->mtx, "linux_tasklet", 0, LK_CANRECURSE);
		TAILQ_INIT(&tw->head);
		GROUPTASK_INIT(&tw->gtask, 0, tasklet_handler, tw);
		snprintf(buf, sizeof(buf), "softirq%d", i);
		taskqgroup_attach_cpu(qgroup_softirq, &tw->gtask,
		    "tasklet", i, NULL, NULL, buf);
       }
}
SYSINIT(linux_tasklet, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, tasklet_subsystem_init, NULL);

static void
tasklet_subsystem_uninit(void *arg __unused)
{
	struct tasklet_worker *tw;
	int i;

	taskqgroup_drain_all(qgroup_softirq);

	for (i = 0; i < ncpus; i++) {
#if 0
		if (CPU_ABSENT(i))
			continue;
#endif

#if 0
		tw = DPCPU_ID_PTR(i, tasklet_worker);
#endif
		tw = &tasklet_workers[i];

		taskqgroup_detach(qgroup_softirq, &tw->gtask);
		lockuninit(&tw->mtx);
	}

}
SYSUNINIT(linux_tasklet, SI_SUB_DRIVERS, SI_ORDER_THIRD, tasklet_subsystem_uninit, NULL);

void
tasklet_init(struct tasklet_struct *ts,
    tasklet_func_t *func, unsigned long data)
{
	ts->entry.tqe_prev = NULL;
	ts->entry.tqe_next = NULL;
	ts->func = func;
	ts->callback = NULL;
	ts->data = data;
	atomic_set_int(&ts->tasklet_state, TASKLET_ST_IDLE);
	atomic_set(&ts->count, 0);
	ts->use_callback = false;
}

void
tasklet_setup(struct tasklet_struct *ts, tasklet_callback_t *c)
{
	ts->entry.tqe_prev = NULL;
	ts->entry.tqe_next = NULL;
	ts->func = NULL;
	ts->callback = c;
	ts->data = 0;
	atomic_set_int(&ts->tasklet_state, TASKLET_ST_IDLE);
	atomic_set(&ts->count, 0);
	ts->use_callback = true;
}
#if 0
void
local_bh_enable(void)
{
}

void
local_bh_disable(void)
{
}
#endif

void
tasklet_schedule(struct tasklet_struct *ts)
{

	/* tasklet is paused */
	if (atomic_read(&ts->count))
		return;

	if (TASKLET_ST_CMPSET(ts, TASKLET_ST_EXEC, TASKLET_ST_LOOP)) {
		/* tasklet_handler() will loop */
	} else if (TASKLET_ST_CMPSET(ts, TASKLET_ST_IDLE, TASKLET_ST_BUSY)) {
		struct tasklet_worker *tw;

#if 0
		tw = &DPCPU_GET(tasklet_worker);
#endif
		tw = &tasklet_workers[mycpuid];

		/* tasklet_handler() was not queued */
		TASKLET_WORKER_LOCK(tw);
		/* enqueue tasklet */
		TAILQ_INSERT_TAIL(&tw->head, ts, entry);
		/* schedule worker */
		GROUPTASK_ENQUEUE(&tw->gtask);
		TASKLET_WORKER_UNLOCK(tw);
	} else {
		/*
		 * tasklet_handler() is already executing
		 *
		 * If the state is neither EXEC nor IDLE, it is either
		 * LOOP or BUSY. If the state changed between the two
		 * CMPSET's above the only possible transitions by
		 * elimination are LOOP->EXEC and BUSY->EXEC. If a
		 * EXEC->LOOP transition was missed that is not a
		 * problem because the callback function is then
		 * already about to be called again.
		 */
	}
}

void
tasklet_kill(struct tasklet_struct *ts)
{
#if 0
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "tasklet_kill() can sleep");
#endif

	/* wait until tasklet is no longer busy */
	while (TASKLET_ST_GET(ts) != TASKLET_ST_IDLE)
		tsleep(ts, 0, "tlstruct", 1);
#if 0
		pause("W", 1);
#endif
}

void
tasklet_enable(struct tasklet_struct *ts)
{

	atomic_dec(&ts->count);
}

void
tasklet_disable(struct tasklet_struct *ts)
{

	atomic_inc(&ts->count);
	tasklet_unlock_wait(ts);
}

void
tasklet_disable_nosync(struct tasklet_struct *ts)
{
	atomic_inc(&ts->count);
	barrier();
}

int
tasklet_trylock(struct tasklet_struct *ts)
{

	return (TASKLET_ST_CMPSET(ts, TASKLET_ST_IDLE, TASKLET_ST_BUSY));
}

void
tasklet_unlock(struct tasklet_struct *ts)
{

	TASKLET_ST_SET(ts, TASKLET_ST_IDLE);
}

void
tasklet_unlock_wait(struct tasklet_struct *ts)
{
#if 0
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "tasklet_kill() can sleep");
#endif

	/* wait until tasklet is no longer busy */
	while (TASKLET_ST_GET(ts) != TASKLET_ST_IDLE) {
#if 0
		pause("W", 1);
#endif
		tsleep(ts, 0, "tlstruct", 1);
	}
}


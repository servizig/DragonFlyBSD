/*
 * Copyright (c) 2017-2020 François Tigeot <ftigeot@wolfpond.org>
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
/*
 * See: https://www.kernel.org/doc/Documentation/RCU/whatisRCU.txt
 */

#ifndef _LINUX_RCUPDATE_H_
#define _LINUX_RCUPDATE_H_

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/spinlock.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/seqlock.h>
#include <linux/lockdep.h>
#include <linux/completion.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/ktime.h>

#include <asm/barrier.h>

#include <linux/rcutree.h>

#include <sys/exislock.h>
#include <sys/exislock2.h>

#define RCU_WARN_ONCE(c, ...)   do {			\
	WARN_ONCE((c), ##__VA_ARGS__);			\
} while(0)

#define __rcu_var_name(n, f, l)				\
        __CONCAT(__CONCAT(__CONCAT(rcu_, n), _), __COUNTER__)

#if 0
static inline void
rcu_read_lock(void)
{
    exis_hold();
}

static inline void
rcu_read_unlock(void)
{
    exis_drop();
}
#endif

#define __rcu_dereference_protected(p, c, n)			\
({								\
    RCU_WARN_ONCE(!(c), "%s:%d: condition for %s failed\n",	\
	__func__, __LINE__, __XSTRING(n));			\
    rcu_dereference(p);						\
})

#define rcu_dereference_protected(p, c)			\
    __rcu_dereference_protected((p), (c),		\
    __rcu_var_name(protected, __func__, __LINE__))

#define __rcu_dereference_check(p, c, n)				\
({									\
    __typeof(*p) *n = rcu_dereference(p);				\
    RCU_WARN_ONCE(!(c), "%s:%d: condition for %s failed\n",		\
        __func__, __LINE__, __XSTRING(n));				\
    n;									\
})

#define rcu_dereference_check(p, c)					\
    __rcu_dereference_check((p), (c) || rcu_read_lock_held(),		\
        __rcu_var_name(check, __func__, __LINE__))

#define rcu_dereference(p)                      \
        ((__typeof(*p) *)READ_ONCE(p))

#define rcu_dereference_raw(p)			\
	((__typeof(*p) *)READ_ONCE(p))

#define rcu_assign_pointer(p, v)				\
do {								\
	atomic_store_rel_ptr((volatile uintptr_t *)&(p),        \
			     (uintptr_t)(v));			\
} while (0)

#define RCU_INIT_POINTER(p, v)		\
do {					\
	p = v;				\
} while (0)

extern void __kfree_rcu(void *ptr);
extern void rcu_read_lock(void);
extern void rcu_read_unlock(void);

#define kfree_rcu(ptr, rcu_head)	\
do {					\
	__kfree_rcu(ptr);		\
} while (0)

extern void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *));

#define rcu_access_pointer(p)	((typeof(*p) *)READ_ONCE(p))

#define rcu_pointer_handoff(p)	(p)

#define synchronize_rcu()
#define cond_synchronize_rcu(x)  cpu_mfence()
#define get_state_synchronize_rcu()	0

#endif  /* _LINUX_RCUPDATE_H_ */

/*
 * Copyright (c) 2014-2020 François Tigeot <ftigeot@wolfpond.org>
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

#ifndef _LINUX_MUTEX_H_
#define _LINUX_MUTEX_H_

#include <asm/current.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <asm/processor.h>

struct mutex {
  struct lock lock;
};

#define mutex_init(mutex) lockinit(mutex.lock, #mutex, 0, LK_CANRECURSE)
#define mutex_destroy(mutex) lockuninit(mutex.lock)

#define mutex_is_locked(mutex)	(lockinuse(mutex.lock))

#define mutex_lock(mutex)	lockmgr(mutex.lock, LK_EXCLUSIVE)
#define mutex_unlock(mutex)	lockmgr(mutex.lock, LK_RELEASE)

#define mutex_trylock(mutex)	lockmgr_try(mutex.lock, LK_EXCLUSIVE)

static inline int
mutex_lock_interruptible(struct mutex *mutex)
{
	if (lockmgr(&mutex->lock, LK_EXCLUSIVE|LK_SLEEPFAIL|LK_PCATCH))
		return -EINTR;

	return 0;
}

#define DEFINE_MUTEX(mtx)	\
	struct mutex mtx;	\
	LOCK_SYSINIT(mtx, &mtx.lock, "lmutex", LK_CANRECURSE)

#define mutex_lock_nested(mutex, unused)	mutex_lock(mutex.lock)

enum mutex_trylock_recursive_enum {
	MUTEX_TRYLOCK_FAILED    = 0,
	MUTEX_TRYLOCK_SUCCESS   = 1,
	MUTEX_TRYLOCK_RECURSIVE,
};

static inline enum mutex_trylock_recursive_enum
mutex_trylock_recursive(struct lock *lock)
{
	if (lockowned(lock))
		return MUTEX_TRYLOCK_RECURSIVE;

	if (lockmgr_try(lock, LK_EXCLUSIVE))
		return MUTEX_TRYLOCK_SUCCESS;

	return MUTEX_TRYLOCK_FAILED;
}

#endif	/* _LINUX_MUTEX_H_ */

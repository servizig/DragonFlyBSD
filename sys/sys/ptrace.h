/*-
 * Copyright (c) 1984, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ptrace.h	8.2 (Berkeley) 1/4/94
 * $FreeBSD: src/sys/sys/ptrace.h,v 1.10.2.2 2003/01/02 20:39:13 kan Exp $
 */

#ifndef	_SYS_PTRACE_H_
#define	_SYS_PTRACE_H_

#ifndef _SYS_TYPES_H_
#include <sys/types.h>
#endif

#define         PT_TRACE_ME     0   /* child declares it's being traced */
#define         PT_READ_I       1   /* read word in child's I space */
#define         PT_READ_D       2   /* read word in child's D space */
/* was          PT_READ_U       3    * read word in child's user structure */
#define         PT_WRITE_I      4   /* write word in child's I space */
#define         PT_WRITE_D      5   /* write word in child's D space */
/* was          PT_WRITE_U      6    * write word in child's user structure */
#define         PT_CONTINUE     7   /* continue the child */
#define         PT_KILL         8   /* kill the child process */
#define         PT_STEP         9   /* single step the child */

#define         PT_ATTACH       10  /* trace some running process */
#define         PT_DETACH       11  /* stop tracing a process */
#define         PT_IO           12  /* do I/O to/from stopped process. */

#define	PT_TRACE_ME	0	/* child declares it's being traced */
#define	PT_READ_I	1	/* read word in child's I space */
#define	PT_READ_D	2	/* read word in child's D space */
/* was	PT_READ_U	3	 * read word in child's user structure */
#define	PT_WRITE_I	4	/* write word in child's I space */
#define	PT_WRITE_D	5	/* write word in child's D space */
/* was	PT_WRITE_U	6	 * write word in child's user structure */
#define	PT_CONTINUE	7	/* continue the child */
#define	PT_KILL		8	/* kill the child process */
#define	PT_STEP		9	/* single step the child */

#define	PT_ATTACH	10	/* trace some running process */
#define	PT_DETACH	11	/* stop tracing a process */
#define	PT_IO		12	/* do I/O to/from stopped process. */
#define         PT_GETNUMLWPS   13  /* number of user threads */
#define         PT_GETLWPLIST   14  /* array of user thread ids */
#define         PT_GETNEXTEVENT 15  /* wait for next event */
#define         PT_SUSPEND      16  /* stop single thread */
#define         PT_RESUME       17  /* continure single thread */
#define         PT_LWPINFO      18  /* get information about lwp */
#define         PT_LWPEVENT     19
#define         PT_WAIT         20

/* Don't forget to update PT_LASTGENERIC */

#define         PT_FIRSTMACH    32  /* for machine-specific requests */

#ifndef _MACHINE_PTRACE_H_
#include <machine/ptrace.h>	/* machine-specific requests, if any */
#endif

struct ptrace_lwpinfo {
	lwpid_t lwpid;
};

struct ptrace_io_desc {
	int      piod_op;       /* I/O operation */
	void    *piod_offs;     /* child offset */
	void    *piod_addr;     /* parent offset */
	size_t   piod_len;      /* request length */
};

enum ptrace_stat {
	PT_NONE          = 0, /* Nothing happened */
	PT_PROC_ZOMB     = 1, /* Traced process exiting */
	PT_LWP_SIGNAL    = 2, /* Thread signal pending */
	PT_LWP_CREATED   = 4, /* Thread created */
	PT_LWP_EXITED    = 8, /* Thread exited */
};

#define PT_STAT_ALL (PT_PROC_ZOMB | PT_LWP_SIGNAL \
	| PT_LWP_CREATED | PT_LWP_EXITED)

struct ptrace_event {
	enum ptrace_stat status;
	lwpid_t          lwpid;
	int              signal;
};

/*
 *  Operations in piod_op.
 */
#define	PIOD_READ_D	1	/* Read from D space */
#define	PIOD_WRITE_D	2	/* Write to D space */
#define	PIOD_READ_I	3	/* Read from I space */
#define	PIOD_WRITE_I	4	/* Write to I space */

#ifdef _KERNEL

#define PTRACE_PID_MASK         ((1LL << 32) - 1)
#define PTRACE_LWPID_MASK       (((1LL << 32) - 1) << 32)
#define PTRACE_GET_PID(ptid)    (ptid & PTRACE_PID_MASK)
#define PTRACE_GET_LWPID(ptid)  ((ptid & PTRACE_LWPID_MASK) >> 32)

#define PT_REQ_IS_GENERIC(req)  (PT_FIRSTGENERIC <= (req) && (req) <= PT_LASTGENERIC)
#ifdef PT_LASTMACH
#define PT_REQ_IS_MACH(req)     (PT_FIRSTMACH <= (req) && (req) <= PT_LASTMACH)
#endif

#define PT_FIRSTGENERIC PT_TRACE_ME
#define PT_LASTGENERIC  PT_WAIT

struct proc;
struct lwp;

void	proc_reparent (struct proc *child, struct proc *newparent);
int	ptrace_set_pc (struct lwp *p, unsigned long addr);
int	ptrace_single_step (struct lwp *lp);
int	kern_ptrace (int req, ptrace_ptid_t pid, void *addr,
		int data, int *res);

#else /* !_KERNEL */

#ifndef _SYS_CDEFS_H_
#include <sys/cdefs.h>
#endif

__BEGIN_DECLS
int	ptrace (int, ptrace_ptid_t, caddr_t, int);
__END_DECLS

#endif /* _KERNEL */

#endif	/* !_SYS_PTRACE_H_ */

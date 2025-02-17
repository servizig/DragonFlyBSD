/*
 * Copyright (c) 1994, Sean Eric Fagan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Sean Eric Fagan.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/kern/sys_process.c,v 1.51.2.6 2003/01/08 03:06:45 kan Exp $
 */

#include "sys/select.h"
#include "sys/signal.h"
#include "sys/signalvar.h"
#include "sys/proc_common.h"
#include "sys/select.h"
#include "sys/signal.h"
#include "sys/signalvar.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmsg.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/caps.h>
#include <sys/vnode.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/lock.h>
#include <sys/types.h>
#include <sys/malloc.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <vfs/procfs/procfs.h>

#include <sys/thread2.h>
#include <sys/spinlock2.h>
#include <sys/signal2.h>

static void
print_signals(struct proc *p)
{
	//return;
	
	struct lwp *tmplp;

	FOREACH_LWP_IN_PROC(tmplp, p) {
	
		kprintf("print_signals: %d/%d lwp_stat=%d lwp_xstat=%d tf_rflags=0x%lx rip=0x%lx signals:",
			p->p_pid, tmplp->lwp_tid, tmplp->lwp_stat, tmplp->lwp_xstat,
			tmplp->lwp_md.md_regs->tf_rflags,
			tmplp->lwp_md.md_regs->tf_rip);
		
	
		sigset_t sigset = lwp_sigpend(tmplp);
		for (int i = 1; i < _SIG_MAXSIG; i++)
			if (SIGISMEMBER(sigset, i))
				kprintf("%d ", i);
		kprintf("\n");
	}
}

static inline int
req_is_valid(int req)
{
	if (PT_REQ_IS_GENERIC(req))
		return 1;

#ifdef PT_LASTMACH
	if (PT_REQ_IS_MACH(req))
		return 1;
#endif

	return 0;
}

/*
 * Permissions check. Returns non-zero on error.
 * Called with PHOLD(p) and lwkt token held.
 * Request id must be valid.
 */
static int
ptrace_check_perms(struct proc *curp, struct proc *p, int req)
{
	struct proc *pp;
	int error;

	if (req == PT_TRACE_ME) {
		/* Always legal. */
		return 0;
	} else if (req == PT_ATTACH) {
		/* Self */
		if (p->p_pid == curp->p_pid) {
			return EINVAL;
		}

		/* Already traced */
		if (p->p_flags & P_TRACED) {
			return EBUSY;
		}

		if (curp->p_flags & P_TRACED) {
			for (pp = curp->p_pptr; pp != NULL; pp = pp->p_pptr) {
				if (pp == p) {
					return EINVAL;
				}
			}
		}

		/* not owned by you, has done setuid (unless you're root) */
		if ((p->p_ucred->cr_ruid != curp->p_ucred->cr_ruid) ||
		     (p->p_flags & P_SUGID)) {
			error = caps_priv_check(curp->p_ucred,
						SYSCAP_RESTRICTEDROOT);
			if (error) {
				return error;
			}
		}

		/* can't trace init when securelevel > 0 */
		if (securelevel > 0 && p->p_pid == 1) {
			return EPERM;
		}

		/* OK */
		return 0;
	} else if (req == PT_WAIT) {
		/* temporary hack */
		return 0;
	} else {
		/* not being traced... */
		if ((p->p_flags & P_TRACED) == 0) {
			kprintf("(p->p_flags & P_TRACED) == 0\n");
			return EPERM;
		}

		/* not being traced by YOU */
		if (p->p_pptr != curp) {
			kprintf("p->p_pptr != curp\n");
			return EBUSY;
		}

		if (req != PT_WAIT) {
			/* not currently stopped */
			if (p->p_stat != SSTOP) {
				kprintf("p_stat=%d != SSTOP\n", p->p_stat);
				return EBUSY;
			}
		}

		/* OK */
		return 0;
	}
}

static struct lwp*
get_signaled_lwp(struct proc *p)
{
	struct lwp *tmplp;
	int signal = 0;

	print_signals(p);

	FOREACH_LWP_IN_PROC(tmplp, p) {
		signal = CURSIG_NOBLOCK(tmplp);
		if (signal) {
			kprintf("get_signaled_lwp: choose %d/%d\n",
				p->p_pid, tmplp->lwp_tid);
			return tmplp;
		}
	}

	return NULL;
}

#if 0
static int
lwp_get_signal(struct lwp *lwp, int start_signal)
{
	int i;
	sigset_t sigset = lwp_sigpend(lwp);

	if (start_signal == 0)
		start_signal = 1;

	/* TODO: optimize with _SIG_WORD */
	for (i = start_signal; i < _SIG_MAXSIG; i++) {
		if (SIGISMEMBER(sigset, i))
			return i;
	}
	return 0;
}
#endif

static int
waitforevent(struct proc *p, struct lwp *lp, void *user_addr, int data,
	     struct ptrace_event *event)
{
	int error = 0;
	
	kprintf("waitforevent: [in] p_ptrace_events=%d p_stat=%d\n",
		p->p_ptrace_events, p->p_stat);

loop:
	print_signals(p);
	
	if (p->p_ptrace_events & PT_PROC_ZOMB) {
		atomic_set_int(&p->p_ptrace_events, PT_PROC_ZOMB);
		kprintf("waitforevent: [out] error=%d p_ptrace_events=%d p_stat=%d\n",
			error, p->p_ptrace_events, p->p_stat);
		return 0;
	}

	if (p->p_ptrace_events == 0) {
		cpu_ccfence();
		if (p->p_ptrace_events == 0) {
			
			error = tsleep(&p->p_ptrace_events,
				       PCATCH, "ptwait", 0);

			if (!error && p->p_ptrace_events == 0) {
				kprintf("waitforevent: loop 1\n");
				goto loop;
			}
		}
	}

	cpu_ccfence();

	if (p->p_stat == SZOMB) {
		/* TODO: is it a correct place? */
		kprintf("waitforevent: SZOMB 2\n");
		atomic_set_int(&p->p_ptrace_events, PT_PROC_ZOMB);
		return 0;
	}

	proc_wait_until_stopped(p);

	kprintf("waitforevent: [out] error=%d p_ptrace_events=%d p_stat=%d\n",
		error, p->p_ptrace_events, p->p_stat);

	return error;
}

static int
getnextevent(struct proc *p, struct lwp *lp, void *user_addr, int data,
	     struct ptrace_event *event)
{
	int error = 0;
	//int sig;
	struct lwp *tmplp;

	if (sizeof(*event) != data)
		return EINVAL;

	copyin(user_addr, event, sizeof(*event));

	event->status = PT_NONE;

	kprintf("getnextevent: [in] p_ptrace_events=%d p_stat=%d\n",
		p->p_ptrace_events, p->p_stat);

	if (p->p_ptrace_events == 0) {
		goto out;
	}

	if (p->p_ptrace_events & PT_PROC_ZOMB) {
		/* Process exiting */
		event->status = PT_PROC_ZOMB;
		atomic_clear_int(&p->p_ptrace_events, PT_STAT_ALL);
		goto out;
	}

	if (p->p_ptrace_events & PT_LWP_EXITED) {
		/* Thread exiting */
		FOREACH_LWP_IN_PROC(tmplp, p) {
			if (tmplp->lwp_mpflags & LWP_MP_EXITED) {
				atomic_clear_int(&tmplp->lwp_mpflags,
						 LWP_MP_SUSPEND | LWP_MP_CREATED | LWP_MP_EXITED);
				event->status = PT_LWP_EXITED;
				event->lwpid = tmplp->lwp_tid;
				//wakeup(p);
				goto out;
			}
		}

		atomic_clear_int(&p->p_ptrace_events, PT_LWP_EXITED);
	}

	if (p->p_ptrace_events & PT_LWP_CREATED) {
		/* Thread created */
		FOREACH_LWP_IN_PROC(tmplp, p) {
			if (tmplp->lwp_mpflags & LWP_MP_CREATED) {
				atomic_clear_int(&tmplp->lwp_mpflags,
						 LWP_MP_SUSPEND | LWP_MP_CREATED);
				event->status = PT_LWP_CREATED;
				event->lwpid = tmplp->lwp_tid;
				goto out;
			}
		}

		atomic_clear_int(&p->p_ptrace_events, PT_LWP_CREATED);
	}

	if (p->p_ptrace_events & PT_LWP_SIGNAL) {
		/* Signal pending */

		print_signals(p);
		FOREACH_LWP_IN_PROC(tmplp, p) {
			if (tmplp->lwp_xstat) {
				event->status = PT_LWP_SIGNAL;
				event->lwpid = tmplp->lwp_tid;
				event->signal = tmplp->lwp_xstat;
				error = 0;
				tmplp->lwp_xstat = 0;
				goto out;
			}
#if 0
			if (tmplp->lwp_tid > event->lwpid) {
				event->signal = 0;
			}
			sig = lwp_get_signal(tmplp, event->signal + 1);
			if (sig > event->signal) {
				event->status = PT_LWP_SIGNAL;
				event->lwpid = tmplp->lwp_tid;
				event->signal = sig;
				error = 0;
				goto out;
			}
#endif
		}

		atomic_clear_int(&p->p_ptrace_events, PT_LWP_SIGNAL);
	}

out:

	kprintf("getnextevent: [out] error=%d p_ptrace_events=%d "
		"status=%d lwpid=%d signal=%d\n",
		error, p->p_ptrace_events, event->status, event->lwpid, event->signal);

	if (error == 0) {
		copyout(event, user_addr, sizeof(*event));
	}
	return error;
}

/*
 * Performs generic ptrace request.
 * Request id was validated before.
 * Called with PHOLD(p), LWPHOLD(lwp), and lwkt token held.
 * NOTE! User addr points at userspace address.
 */
static int
ptrace_req_generic(int req, struct proc *p, struct lwp *lp, void *user_addr,
		   int data, int *res)
{
	struct proc *curp = curproc;
	struct iovec iov;
	struct uio uio;
	struct lwp *tmplp;
	int *buf;
	int write, tmp, nthreads;
	int error = 0;

	/*
	 * XXX this obfuscation is to reduce stack usage.
	 */
	union {
		struct ptrace_lwpinfo pl;
		struct ptrace_io_desc piod;
		struct ptrace_event event;
	} r;

	write = 0;
	switch (req) {
	case PT_TRACE_ME:
		/* set my trace flag and "owner" so it can read/write me */
		p->p_flags |= P_TRACED;
		//p->p_oppid = p->p_pptr->p_pid;
		return 0;

	case PT_ATTACH:
		/* security check done above */
		p->p_flags |= P_TRACED;
		p->p_oppid = p->p_pptr->p_pid;
		proc_reparent(p, curp);
		data = SIGSTOP;
		goto sendsig;	/* in PT_CONTINUE below */


	case PT_KILL:
		data = SIGKILL;
		goto sendsig;	/* in PT_CONTINUE below */

	case PT_STEP:
	case PT_CONTINUE:
	case PT_DETACH:
		/* Zero means do not send any signal */
		if (data < 0 || data >= _SIG_MAXSIG) {
			return EINVAL;
		}

		if (req == PT_STEP) {
			if ((error = ptrace_single_step (lp))) {
				return error;
			}
		}

		if (user_addr != (void *)1) {
			if ((error = ptrace_set_pc (lp, (u_long)user_addr))) {
				return error;
			}
		}

		if (req == PT_DETACH) {
			/* reset process parent */
			if (p->p_oppid != p->p_pptr->p_pid) {
				struct proc *pp;

				pp = pfind(p->p_oppid);
				if (pp) {
					proc_reparent(p, pp);
					PRELE(pp);
				}
			}

			p->p_flags &= ~(P_TRACED | P_WAITED);
			p->p_oppid = 0;

			/* should we send SIGCHLD? */
		}

	sendsig:
		kprintf("req=%d pid=%d stat=%d lwpid=%d, rip=0x%lx\n",
			req, p->p_pid, p->p_stat, lp->lwp_tid, lp->lwp_md.md_regs->tf_rip);
		print_signals(p);

		/*
		 * Deliver or queue signal.  If the process is stopped
		 * force it to be SACTIVE again.
		 */
		crit_enter();
		if (p->p_stat == SSTOP) {
			p->p_xstat = data;
			lp->lwp_xstat = data;
			proc_unstop(p, SSTOP);
		} else if (data) {
			kprintf("  = ksignal, data=%d\n", data);
			ksignal(p, data);
		}
		crit_exit();
		return 0;


	case PT_WRITE_I:
	case PT_WRITE_D:
		write = 1;
		/* fallthrough */
	case PT_READ_I:
	case PT_READ_D:
		/*
		 * NOTE! uio_offset represents the offset in the target
		 * process.  The iov is in the current process (the guy
		 * making the ptrace call) so uio_td must be the current
		 * process (though for a SYSSPACE transfer it doesn't
		 * really matter).
		 */
		tmp = 0;
		/* write = 0 set above */
		iov.iov_base = write ? (caddr_t)&user_addr : (caddr_t)&tmp;
		iov.iov_len = sizeof(int);
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = (off_t)(uintptr_t)user_addr;
		uio.uio_resid = sizeof(int);
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = write ? UIO_WRITE : UIO_READ;
		uio.uio_td = curthread;
		error = procfs_domem(curp, lp, NULL, &uio);
		if (uio.uio_resid != 0) {
			/*
			 * XXX procfs_domem() doesn't currently return ENOSPC,
			 * so I think write() can bogusly return 0.
			 * XXX what happens for short writes?  We don't want
			 * to write partial data.
			 * XXX procfs_domem() returns EPERM for other invalid
			 * addresses.  Convert this to EINVAL.  Does this
			 * clobber returns of EPERM for other reasons?
			 */
			if (error == 0 || error == ENOSPC || error == EPERM)
				error = EINVAL;	/* EOF */
		}
		if (!write)
			*res = tmp;
		return error;

	case PT_IO:
		/*
		 * NOTE! uio_offset represents the offset in the target
		 * process.  The iov is in the current process (the guy
		 * making the ptrace call) so uio_td must be the current
		 * process.
		 */
		error = copyin(user_addr, &r.piod, sizeof(r.piod));
		if (error)
			return error;
//		piod = addr;
		iov.iov_base = r.piod.piod_addr;
		iov.iov_len = r.piod.piod_len;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = (off_t)(uintptr_t)r.piod.piod_offs;
		uio.uio_resid = r.piod.piod_len;
		uio.uio_segflg = UIO_USERSPACE;
		uio.uio_td = curthread;
		switch (r.piod.piod_op) {
		case PIOD_READ_D:
		case PIOD_READ_I:
			uio.uio_rw = UIO_READ;
			break;
		case PIOD_WRITE_D:
		case PIOD_WRITE_I:
			uio.uio_rw = UIO_WRITE;
			break;
		default:
			return EINVAL;
		}
		/*
		  if (uio.uio_rw == UIO_WRITE) {
		  kprintf("PT_IO: offset=0x%lx\n", uio.uio_offset);
		  }
		 */
		error = procfs_domem(curp, lp, NULL, &uio);
		r.piod.piod_len -= uio.uio_resid;
		if (error == 0)
			copyout(&r.piod, user_addr, sizeof(r.piod));
		return error;

	case PT_GETNUMLWPS:
		*res = p->p_nthreads;
		break;
	case PT_GETLWPLIST:
		if (data <= 0)
			return EINVAL;
		nthreads = MIN(data, p->p_nthreads);
		tmp = 0;
		buf = kmalloc(nthreads * sizeof(lwpid_t), M_TEMP, M_WAITOK);
		FOREACH_LWP_IN_PROC(tmplp, p) {
			if (tmp >= nthreads)
				break;
			buf[tmp] = tmplp->lwp_tid;
			tmp++;
		}
		error = copyout(buf, user_addr, nthreads * sizeof(lwpid_t));
		kfree(buf, M_TEMP);
		if (!error)
			*res = nthreads;
		break;
	case PT_GETNEXTEVENT:
		error = getnextevent(p, lp, user_addr, data, &r.event);
		break;
	case PT_WAIT:
		error = waitforevent(p, lp, user_addr, data, &r.event);
		break;
	case PT_SUSPEND:
		kprintf("suspend %d/%d lwp_stat %d mpflags 0x%x\n",
			p->p_pid, lp->lwp_tid, lp->lwp_stat, lp->lwp_mpflags);
		atomic_set_int(&lp->lwp_mpflags, LWP_MP_SUSPEND);
		break;
	case PT_RESUME:
		kprintf("resume %d/%d lwp_stat %d mpflags 0x%x\n",
			p->p_pid, lp->lwp_tid, lp->lwp_stat, lp->lwp_mpflags);
		atomic_clear_int(&lp->lwp_mpflags, LWP_MP_SUSPEND);
		break;
	case PT_LWPINFO:
		if (data != sizeof(r.pl))
			return EINVAL;
		r.pl.lwpid = lp->lwp_tid;
		error = copyout(&r.pl, user_addr, sizeof (r.pl));
		break;
	case PT_LWPEVENT:
		tmplp = get_signaled_lwp(p);
		if (tmplp) {
			*res = tmplp->lwp_tid;
			return 0;
		} else {
			return ESRCH;
		}
		break;
	default:
		return EINVAL;
	}

	return error;
}

/*
 * Process debugging system call.
 *
 * MPALMOSTSAFE
 */
int
sys_ptrace(struct sysmsg *sysmsg, const struct ptrace_args *uap)
{
	int error = 0;

	error = kern_ptrace(uap->req, uap->pid, uap->addr, uap->data,
			    &sysmsg->sysmsg_result);
	return (error);
}

int
kern_ptrace(int req, ptrace_ptid_t ptid, void *user_addr, int data, int *res)
{
	struct proc *curp = curproc;
	struct proc *p;
	struct lwp *lp;
	int error = 0;
	pid_t pid = PTRACE_GET_PID(ptid);
	lwpid_t lwpid = PTRACE_GET_LWPID(ptid);

#if 0
	kprintf("req=%d, pid=%d, lwpid=%d\n", req, pid, lwpid);
#endif
	/*
	 * Validate request id.
	 */
	if (!req_is_valid(req)) {
		kprintf("!req_is_valid\n");
		return EINVAL;
	}

	if (req == PT_TRACE_ME) {
		p = curp;
		PHOLD(p);
	} else {
		if ((p = pfind(pid)) == NULL) {
			if ((p = zpfind(pid)) == NULL)
				return ESRCH;
		}
	}
	if (!PRISON_CHECK(curp->p_ucred, p->p_ucred)) {
		error = ESRCH;
		goto err_proc;
	}
	if (p->p_flags & P_SYSTEM) {
		error = EINVAL;
		goto err_proc;
	}

	lwkt_gettoken(&p->p_token);
	/* Can't trace a process that's currently exec'ing. */
	if ((p->p_flags & P_INEXEC) != 0) {
		error = EAGAIN;
		goto err_lwkt;
	}

	/*
	 * Permissions check
	 */
	error = ptrace_check_perms(curp, p, req);
	if (error)
		goto err_lwkt;

	/* XXX lwp */
	lp = NULL;
	if (lwpid == 0) {
		lp = FIRST_LWP_IN_PROC(p);
		if (lp != NULL)
			LWPHOLD(lp);
	} else {
		lp = lwpfind(p, lwpid);
	}
	if (lp == NULL) {
		error = EINVAL;
		kprintf("lp == NULL\n");
		goto err_lwkt;
	}

#ifdef FIX_SSTEP
	/*
	 * Single step fixup ala procfs
	 */
	FIX_SSTEP(lp);
#endif

	/*
	 * Actually do the requests
	 */

	*res = 0;

	if (PT_REQ_IS_GENERIC(req)) {
		error = ptrace_req_generic(req, p, lp, user_addr, data, res);
	}
#ifdef PT_LASTMACH
	else if (PT_REQ_IS_MACH(req)) {
		error = ptrace_req_mach(req, p, lp, user_addr, data, res);
	}
#endif

	LWPRELE(lp);
err_lwkt:
	lwkt_reltoken(&p->p_token);
err_proc:
	PRELE(p);
	return error;
}

int
trace_req(struct proc *p)
{
	return 1;
}

/*
 * stopevent()
 *
 * Stop a process because of a procfs event.  Stay stopped until p->p_step
 * is cleared (cleared by PIOCCONT in procfs).
 *
 * MPSAFE
 */
void
stopevent(struct proc *p, unsigned int event, unsigned int val) 
{
	/*
	 * Set event info.  Recheck p_stops in case we are
	 * racing a close() on procfs.
	 */
	spin_lock(&p->p_spin);
	if ((p->p_stops & event) == 0) {
		spin_unlock(&p->p_spin);
		return;
	}
	p->p_xstat = val;
	p->p_stype = event;
	p->p_step = 1;
	tsleep_interlock(&p->p_step, 0);
	spin_unlock(&p->p_spin);

	/*
	 * Wakeup any PIOCWAITing procs and wait for p_step to
	 * be cleared.
	 */
	for (;;) {
		wakeup(&p->p_stype);
		tsleep(&p->p_step, PINTERLOCKED, "stopevent", 0);
		spin_lock(&p->p_spin);
		if (p->p_step == 0) {
			spin_unlock(&p->p_spin);
			break;
		}
		tsleep_interlock(&p->p_step, 0);
		spin_unlock(&p->p_spin);
	}
}


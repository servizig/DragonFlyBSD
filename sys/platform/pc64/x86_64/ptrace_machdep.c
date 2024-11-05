/*
 * Copyright (c) 2024 The DragonFly Project.  All rights reserved.
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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/caps.h>
#include <sys/ptrace.h>
#include <sys/reg.h>

#include <vfs/procfs/procfs.h>

/*
 * Performs machine dependent ptrace request.
 * Request id was validated before.
 * Called with PHOLD(p), LWPHOLD(lwp), and lwkt token held.
 * NOTE! User addr points at userspace address.
 */
int
ptrace_req_mach(int req, struct proc *p, struct lwp *lp, void *user_addr,
		int data, int *res)
{
	/*
	 * XXX this obfuscation is to reduce stack usage, but the register
	 * structs may be too large to put on the stack anyway.
	 */
	union {
		struct dbreg dbreg;
		struct fpreg fpreg;
		struct reg reg;
	} r;
	register_t fsbase;
	struct proc *curp = curproc;
	struct iovec iov;
	struct uio uio;
	int write = 0;
	int error;

	error = EINVAL;
	switch (req) {
	case PT_SETREGS:
		error = copyin(user_addr, &r.reg, sizeof(r.reg));
		if (error)
			return error;
		write = 1;
		/* fallthrough */
	case PT_GETREGS:
		if (procfs_validregs(lp)) {
			iov.iov_base = &r.reg;
			iov.iov_len = sizeof(struct reg);
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = sizeof(struct reg);
			uio.uio_segflg = UIO_SYSSPACE;
			uio.uio_rw = write ? UIO_WRITE : UIO_READ;
			uio.uio_td = curthread;
			error = procfs_doregs(curp, lp, NULL, &uio);
			if (error == 0 && write == 0)
				error = copyout(&r.reg, user_addr, sizeof(r.reg));
		}
		break;

	case PT_SETFPREGS:
		error = copyin(user_addr, &r.fpreg, sizeof(r.fpreg));
		if (error)
			return error;
		write = 1;
		/* fallthrough */
	case PT_GETFPREGS:
		if (procfs_validfpregs(lp)) {
			iov.iov_base = &r.fpreg;
			iov.iov_len = sizeof(struct fpreg);
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = sizeof(struct fpreg);
			uio.uio_segflg = UIO_SYSSPACE;
			uio.uio_rw = write ? UIO_WRITE : UIO_READ;
			uio.uio_td = curthread;
			error = procfs_dofpregs(curp, lp, NULL, &uio);
			if (error == 0 && write == 0)
				error = copyout(&r.fpreg, user_addr, sizeof(r.fpreg));
		}
		break;

	case PT_SETDBREGS:
		error = copyin(user_addr, &r.dbreg, sizeof(r.dbreg));
		if (error)
			return error;
		write = 1;
		/* fallthrough */
	case PT_GETDBREGS:
		if (procfs_validdbregs(lp)) {
			iov.iov_base = &r.dbreg;
			iov.iov_len = sizeof(struct dbreg);
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = sizeof(struct dbreg);
			uio.uio_segflg = UIO_SYSSPACE;
			uio.uio_rw = write ? UIO_WRITE : UIO_READ;
			uio.uio_td = curthread;
			error = procfs_dodbregs(curp, lp, NULL, &uio);
			if (error == 0 && write == 0)
				error = copyout(&r.dbreg, user_addr, sizeof(r.dbreg));
		}
		break;

	case PT_GETFSBASE:
		fsbase = lp->lwp_thread->td_pcb->pcb_fsbase;
		error = copyout(&fsbase, user_addr, sizeof(fsbase));
		break;
	}
	
	return error;
}

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
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
 * @(#)freopen.c	8.1 (Berkeley) 6/4/93
 * $FreeBSD: src/lib/libc/stdio/freopen.c,v 1.21 2008/04/17 22:17:54 jhb Exp $
 */

#include "namespace.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "un-namespace.h"
#include "libc_private.h"
#include "local.h"

/*
 * Re-direct an existing, open (probably) file to some other file.
 * ANSI is written such that the original file gets closed if at
 * all possible, no matter what.
 */
FILE *
freopen(const char * __restrict file, const char * __restrict mode, FILE *fp)
{
	int f;
	int dflags, fdflags, flags, isopen, oflags, sverrno, wantfd;

	if ((flags = __sflags(mode, &oflags)) == 0) {
		sverrno = errno;
		fclose(fp);
		errno = sverrno;
		return (NULL);
	}

	FLOCKFILE(fp);

	if (!__sdidinit)
		__sinit();

	/*
	 * If the filename is a NULL pointer, the caller is asking us to
	 * re-open the same file with a different mode. We allow this only
	 * if the modes are compatible.
	 */
	if (file == NULL) {
		/* See comment below regarding freopen() of closed files. */
		if (fp->pub._flags == 0) {
			FUNLOCKFILE(fp);
			errno = EINVAL;
			return (NULL);
		}
		if ((dflags = _fcntl(fp->pub._fileno, F_GETFL)) < 0) {
			sverrno = errno;
			fclose(fp);
			FUNLOCKFILE(fp);
			errno = sverrno;
			return (NULL);
		}
		if ((dflags & O_ACCMODE) != O_RDWR && (dflags & O_ACCMODE) !=
		    (oflags & O_ACCMODE)) {
			fclose(fp);
			FUNLOCKFILE(fp);
			errno = EINVAL;
			return (NULL);
		}
		if (fp->pub._flags & __SWR)
			__sflush(fp);
		if ((oflags ^ dflags) & O_APPEND) {
			dflags &= ~O_APPEND;
			dflags |= oflags & O_APPEND;
			if (_fcntl(fp->pub._fileno, F_SETFL, dflags) < 0) {
				sverrno = errno;
				fclose(fp);
				FUNLOCKFILE(fp);
				errno = sverrno;
				return (NULL);
			}
		}
		if (oflags & O_TRUNC)
			ftruncate(fp->pub._fileno, (off_t)0);
		if (!(oflags & O_APPEND))
			_sseek(fp, (fpos_t)0, SEEK_SET);
		if ((oflags & O_CLOEXEC) != 0 &&
		    (fdflags = _fcntl(fileno(fp), F_GETFD, 0)) != -1 &&
		    (fdflags & FD_CLOEXEC) == 0)
			(void)_fcntl(fileno(fp), F_SETFD, fdflags | FD_CLOEXEC);

		f = fp->pub._fileno;
		isopen = 0;
		wantfd = -1;
		goto finish;
	}

	/*
	 * There are actually programs that depend on being able to "freopen"
	 * descriptors that weren't originally open.  Keep this from breaking.
	 * Remember whether the stream was open to begin with, and which file
	 * descriptor (if any) was associated with it.  If it was attached to
	 * a descriptor, defer closing it; freopen("/dev/stdin", "r", stdin)
	 * should work.  This is unnecessary if it was not a Unix file.
	 */
	if (fp->pub._flags == 0) {
		fp->pub._flags = __SEOF;	/* hold on to it */
		isopen = 0;
		wantfd = -1;
	} else {
		/* flush the stream; ANSI doesn't require this. */
		if (fp->pub._flags & __SWR)
			__sflush(fp);
		/* if close is NULL, closing is a no-op, hence pointless */
		isopen = fp->_close != NULL;
		if ((wantfd = fp->pub._fileno) < 0 && isopen) {
			(*fp->_close)(fp->_cookie);
			isopen = 0;
		}
	}

	/* Get a new descriptor to refer to the new file. */
	f = _open(file, oflags, DEFFILEMODE);
	if (f < 0 && isopen) {
		/* If out of fd's close the old one and try again. */
		if (errno == ENFILE || errno == EMFILE) {
			(*fp->_close)(fp->_cookie);
			isopen = 0;
			f = _open(file, oflags, DEFFILEMODE);
		}
	}
	sverrno = errno;

finish:
	/*
	 * Finish closing fp.  Even if the open succeeded above, we cannot
	 * keep fp->_base: it may be the wrong size.  This loses the effect
	 * of any setbuffer calls, but stdio has always done this before.
	 */
	if (isopen)
		(*fp->_close)(fp->_cookie);
	if (fp->pub._flags & __SMBF)
		free((char *)fp->_bf._base);
	fp->pub._w = 0;
	fp->pub._r = 0;
	fp->pub._p = NULL;
	fp->_bf._base = NULL;
	fp->_bf._size = 0;
	fp->pub._lbfsize = 0;
	if (HASUB(fp))
		FREEUB(fp);
	fp->_ub._size = 0;
	if (HASLB(fp))
		FREELB(fp);
	fp->_lb._size = 0;
	memset(WCIO_GET(fp), 0, sizeof(struct wchar_io_data));

	if (f < 0) {			/* did not get it after all */
		fp->pub._flags = 0;		/* set it free */
		FUNLOCKFILE(fp);
		errno = sverrno;	/* restore in case _close clobbered */
		return (NULL);
	}

	/*
	 * If reopening something that was open before on a real file, try
	 * to maintain the descriptor.  Various C library routines (perror)
	 * assume stderr is always fd STDERR_FILENO, even if being freopen'd.
	 */
	if (wantfd >= 0 && f != wantfd) {
		if (oflags & O_CLOEXEC) {
			if (_fcntl(f, F_DUP2FD_CLOEXEC, wantfd) >= 0) {
				_close(f);
				f = wantfd;
			}
		} else {
			if (_dup2(f, wantfd) >= 0) {
				_close(f);
				f = wantfd;
			}
		}
	}

	fp->pub._flags = flags;
	fp->pub._fileno = f;
	fp->_cookie = fp;
	fp->_read = __sread;
	fp->_write = __swrite;
	fp->_seek = __sseek;
	fp->_close = __sclose;
	/*
	 * When opening in append mode, even though we use O_APPEND,
	 * we need to seek to the end so that ftell() gets the right
	 * answer.  If the user then alters the seek pointer, or
	 * the file extends, this will fail, but there is not much
	 * we can do about this.  (We could set __SAPP and check in
	 * fseek and ftell.)
	 */
	if (oflags & O_APPEND)
		_sseek(fp, (fpos_t)0, SEEK_END);
	FUNLOCKFILE(fp);
	return (fp);
}

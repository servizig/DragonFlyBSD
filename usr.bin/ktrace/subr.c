/*-
 * Copyright (c) 1988, 1993
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
 * @(#)subr.c	8.1 (Berkeley) 6/6/93
 * $FreeBSD: src/usr.bin/ktrace/subr.c,v 1.6 1999/08/28 01:02:34 peter Exp $
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/ktrace.h>

#include <stdio.h>

#include "ktrace.h"

int
getpoints(char *s)
{
	int facs = 0;

	while (*s) {
		switch (*s) {
		case 'c':
			facs |= KTRFAC_SYSCALL | KTRFAC_SYSRET;
			break;
		case 'n':
			facs |= KTRFAC_NAMEI;
			break;
		case 'i':
			facs |= KTRFAC_GENIO;
			break;
		case 's':
			facs |= KTRFAC_PSIG;
			break;
		case 'u':
			facs |= KTRFAC_USER;
			break;
		case 'w':
			facs |= KTRFAC_CSW;
			break;
		case 'y':
			facs |= KTRFAC_SYSCTL;
			break;
		case '+':
			facs |= DEF_POINTS;
			break;
		default:
			return(-1);
		}
		s++;
	}
	return (facs);
}

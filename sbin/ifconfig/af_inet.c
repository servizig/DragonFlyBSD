/*
 * Copyright (c) 1983, 1993
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
 * $FreeBSD: src/sbin/ifconfig/af_inet.c,v 1.2 2005/06/16 19:37:09 ume Exp $
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>		/* for struct ifaddr */
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <err.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ifconfig.h"

static struct ifaliasreq in_addreq;
static struct ifreq in_ridreq;
static char addr_buf[NI_MAXHOST];  /* for getnameinfo() */

static void
in_status(int s __unused, const struct ifaddrs *ifa)
{
	struct sockaddr_in *sin, null_sin;
	int error, n_flags;

	memset(&null_sin, 0, sizeof(null_sin));

	sin = (struct sockaddr_in *)ifa->ifa_addr;
	if (sin == NULL)
		return;

	if (f_addr != NULL && strcmp(f_addr, "fqdn") == 0)
		n_flags = 0;
	else if (f_addr != NULL && strcmp(f_addr, "host") == 0)
		n_flags = NI_NOFQDN;
	else
		n_flags = NI_NUMERICHOST;

	error = getnameinfo((struct sockaddr *)sin, sin->sin_len, addr_buf,
			    sizeof(addr_buf), NULL, 0, n_flags);
	if (error != 0)
		inet_ntop(AF_INET, &sin->sin_addr, addr_buf, sizeof(addr_buf));

	printf("\tinet %s", addr_buf);

	if (ifa->ifa_flags & IFF_POINTOPOINT) {
		sin = (struct sockaddr_in *)ifa->ifa_dstaddr;
		if (sin == NULL)
			sin = &null_sin;
		printf(" --> %s", inet_ntoa(sin->sin_addr));
	}

	sin = (struct sockaddr_in *)ifa->ifa_netmask;
	if (sin == NULL)
		sin = &null_sin;
	if (f_inet != NULL && strcmp(f_inet, "cidr") == 0) {
		int cidr = 32;
		unsigned long smask = ntohl(sin->sin_addr.s_addr);

		while ((smask & 1) == 0) {
			smask >>= 1;
			cidr--;
			if (cidr == 0)
				break;
		}
		printf("/%d", cidr);
	} else if (f_inet != NULL && strcmp(f_inet, "dotted") == 0) {
		printf(" netmask %s", inet_ntoa(sin->sin_addr));
	} else {
		printf(" netmask 0x%lx",
			(unsigned long)ntohl(sin->sin_addr.s_addr));
	}

	if (ifa->ifa_flags & IFF_BROADCAST) {
		sin = (struct sockaddr_in *)ifa->ifa_broadaddr;
		if (sin != NULL && sin->sin_addr.s_addr != 0)
			printf(" broadcast %s", inet_ntoa(sin->sin_addr));
	}
	putchar('\n');
}

#define SIN(x) ((struct sockaddr_in *) &(x))
static struct sockaddr_in *sintab[] = {
	SIN(in_ridreq.ifr_addr), SIN(in_addreq.ifra_addr),
	SIN(in_addreq.ifra_mask), SIN(in_addreq.ifra_broadaddr)
};

static void
in_getaddr(const char *s, int which)
{
	struct sockaddr_in *sin = sintab[which];
	struct hostent *hp;
	struct netent *np;

	sin->sin_len = sizeof(*sin);
	if (which != MASK)
		sin->sin_family = AF_INET;

	if (which == ADDR) {
		char *p = NULL;

		if ((p = strrchr(s, '/')) != NULL) {
			/* address is `name/masklen' */
			int masklen, ret;
			struct sockaddr_in *min = sintab[MASK];

			*p = '\0';
			ret = sscanf(p+1, "%u", &masklen);
			if (ret != 1 || (masklen < 0 || masklen > 32)) {
				*p = '/';
				errx(1, "%s: bad value", s);
			}
			min->sin_len = sizeof(*min);
			min->sin_addr.s_addr =
			    htonl(rounddown2(0xffffffff, 1LL << (32 - masklen)));
		}
	}

	if (inet_aton(s, &sin->sin_addr))
		return;
	if ((hp = gethostbyname(s)) != NULL)
		memcpy(&sin->sin_addr, hp->h_addr,
		       MIN((size_t)hp->h_length, sizeof(sin->sin_addr)));
	else if ((np = getnetbyname(s)) != NULL)
		sin->sin_addr = inet_makeaddr(np->n_net, INADDR_ANY);
	else
		errx(1, "%s: bad value", s);
}

static void
in_status_tunnel(int s)
{
	char src[NI_MAXHOST];
	char dst[NI_MAXHOST];
	struct ifreq ifr;
	const struct sockaddr *sa = (const struct sockaddr *) &ifr.ifr_addr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, IfName, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFPSRCADDR, &ifr) < 0)
		return;
	if (sa->sa_family != AF_INET)
		return;
	if (getnameinfo(sa, sa->sa_len, src, sizeof(src), 0, 0,
			NI_NUMERICHOST) != 0)
		src[0] = '\0';

	if (ioctl(s, SIOCGIFPDSTADDR, &ifr) < 0)
		return;
	if (sa->sa_family != AF_INET)
		return;
	if (getnameinfo(sa, sa->sa_len, dst, sizeof(dst), 0, 0,
			NI_NUMERICHOST) != 0)
		dst[0] = '\0';

	printf("\ttunnel inet %s --> %s\n", src, dst);
}

static void
in_set_tunnel(int s, struct addrinfo *srcres, struct addrinfo *dstres)
{
	struct ifaliasreq addreq;

	memset(&addreq, 0, sizeof(addreq));
	strlcpy(addreq.ifra_name, IfName, sizeof(addreq.ifra_name));
	memcpy(&addreq.ifra_addr, srcres->ai_addr, srcres->ai_addr->sa_len);
	memcpy(&addreq.ifra_dstaddr, dstres->ai_addr, dstres->ai_addr->sa_len);

	if (ioctl(s, SIOCSIFPHYADDR, &addreq) < 0)
		warn("SIOCSIFPHYADDR");
}

static struct afswtch af_inet = {
	.af_name	= "inet",
	.af_af		= AF_INET,
	.af_status	= in_status,
	.af_getaddr	= in_getaddr,
	.af_status_tunnel = in_status_tunnel,
	.af_settunnel	= in_set_tunnel,
	.af_difaddr	= SIOCDIFADDR,
	.af_aifaddr	= SIOCAIFADDR,
	.af_ridreq	= &in_ridreq,
	.af_addreq	= &in_addreq,
};

__constructor(112)
static void
inet_ctor(void)
{
	af_register(&af_inet);
}

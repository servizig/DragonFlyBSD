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
 * $FreeBSD: src/sbin/ifconfig/af_inet6.c,v 1.3 2005/06/16 19:37:09 ume Exp $
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>		/* for struct ifaddr */
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>	/* Define ND6_INFINITE_LIFETIME */
#include <arpa/inet.h>
#include <netdb.h>

#include <err.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ifconfig.h"

static	struct in6_ifreq in6_ridreq;
static	struct in6_aliasreq in6_addreq =
  { { 0 },
    { 0 },
    { 0 },
    { 0 },
    0,
    { 0, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME } };
static	int ip6lifetime;

static	void in6_fillscopeid(struct sockaddr_in6 *sin6);
static	int prefix(void *, int);
static	char *sec2str(time_t);
static	int explicit_prefix = 0;

static 	char addr_buf[NI_MAXHOST];  /* for getnameinfo() */

static void
setifprefixlen(const char *addr, int dummy __unused, int s __unused,
    const struct afswtch *afp)
{
        if (afp->af_getprefix != NULL)
                afp->af_getprefix(addr, MASK);
	explicit_prefix = 1;
}

static void
setip6flags(const char *addr __unused, int flag, int s __unused,
    const struct afswtch *afp)
{
	if (afp->af_af != AF_INET6)
		err(1, "address flags can be set only for inet6 addresses");

	if (flag < 0)
		in6_addreq.ifra_flags &= ~(-flag);
	else
		in6_addreq.ifra_flags |= flag;
}

static void
setip6lifetime(const char *cmd, const char *val, int s __unused,
    const struct afswtch *afp)
{
	struct timespec now;
	time_t newval;
	char *ep;

	clock_gettime(CLOCK_MONOTONIC_FAST, &now);
	newval = (time_t)strtoul(val, &ep, 0);
	if (val == ep)
		errx(1, "invalid %s", cmd);
	if (afp->af_af != AF_INET6)
		errx(1, "%s not allowed for the AF", cmd);
	if (strcmp(cmd, "vltime") == 0) {
		in6_addreq.ifra_lifetime.ia6t_expire = now.tv_sec + newval;
		in6_addreq.ifra_lifetime.ia6t_vltime = newval;
	} else if (strcmp(cmd, "pltime") == 0) {
		in6_addreq.ifra_lifetime.ia6t_preferred = now.tv_sec + newval;
		in6_addreq.ifra_lifetime.ia6t_pltime = newval;
	}
}

static void
setip6pltime(const char *seconds, int dummy __unused, int s,
    const struct afswtch *afp)
{
	setip6lifetime("pltime", seconds, s, afp);
}

static void
setip6vltime(const char *seconds, int dummy __unused, int s,
    const struct afswtch *afp)
{
	setip6lifetime("vltime", seconds, s, afp);
}

static void
setip6eui64(const char *cmd, int dummy __unused, int s __unused,
    const struct afswtch *afp)
{
	struct ifaddrs *ifap, *ifa;
	const struct sockaddr_in6 *sin6 = NULL;
	const struct in6_addr *lladdr = NULL;
	struct in6_addr *in6;

	if (afp->af_af != AF_INET6)
		errx(EXIT_FAILURE, "%s not allowed for the AF", cmd);
	in6 = (struct in6_addr *)&in6_addreq.ifra_addr.sin6_addr;
	if (memcmp(&in6addr_any.s6_addr[8], &in6->s6_addr[8], 8) != 0)
		errx(EXIT_FAILURE, "interface index is already filled");
	if (getifaddrs(&ifap) != 0)
		err(EXIT_FAILURE, "getifaddrs");
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_INET6 &&
		    strcmp(ifa->ifa_name, IfName) == 0) {
			sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
				lladdr = &sin6->sin6_addr;
				break;
			}
		}
	}
	if (!lladdr)
		errx(EXIT_FAILURE, "could not determine link local address");

	memcpy(&in6->s6_addr[8], &lladdr->s6_addr[8], 8);

	freeifaddrs(ifap);
}

static void
in6_fillscopeid(struct sockaddr_in6 *sin6)
{
#if defined(__KAME__) && defined(KAME_SCOPEID)
	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
		sin6->sin6_scope_id =
			ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
		sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
	}
#else
	(void)sin6;
#endif
}

static void
in6_status(int s __unused, const struct ifaddrs *ifa)
{
	struct sockaddr_in6 *sin, null_sin;
	struct in6_ifreq ifr6;
	int s6;
	u_int32_t flags6;
	struct in6_addrlifetime lifetime;
	struct timespec now;
	int n_flags, prefixlen;
	int error;
	u_int32_t scopeid;

	clock_gettime(CLOCK_MONOTONIC_FAST, &now);

	memset(&null_sin, 0, sizeof(null_sin));

	sin = (struct sockaddr_in6 *)ifa->ifa_addr;
	if (sin == NULL)
		return;

	strlcpy(ifr6.ifr_name, IfName, sizeof(ifr6.ifr_name));
	if ((s6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		warn("socket(AF_INET6,SOCK_DGRAM)");
		return;
	}
	ifr6.ifr_addr = *sin;
	if (ioctl(s6, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
		warn("ioctl(SIOCGIFAFLAG_IN6)");
		close(s6);
		return;
	}
	flags6 = ifr6.ifr_ifru.ifru_flags6;
	memset(&lifetime, 0, sizeof(lifetime));
	ifr6.ifr_addr = *sin;
	if (ioctl(s6, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
		warn("ioctl(SIOCGIFALIFETIME_IN6)");
		close(s6);
		return;
	}
	lifetime = ifr6.ifr_ifru.ifru_lifetime;
	close(s6);

	/* XXX: embedded link local addr check */
	if (IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr) &&
	    *(u_short *)&sin->sin6_addr.s6_addr[2] != 0) {
		u_short index;

		index = *(u_short *)&sin->sin6_addr.s6_addr[2];
		*(u_short *)&sin->sin6_addr.s6_addr[2] = 0;
		if (sin->sin6_scope_id == 0)
			sin->sin6_scope_id = ntohs(index);
	}
	scopeid = sin->sin6_scope_id;

	if (f_addr != NULL && strcmp(f_addr, "fqdn") == 0)
		n_flags = 0;
	else if (f_addr != NULL && strcmp(f_addr, "host") == 0)
		n_flags = NI_NOFQDN;
	else
		n_flags = NI_NUMERICHOST;

	error = getnameinfo((struct sockaddr *)sin, sin->sin6_len, addr_buf,
			    sizeof(addr_buf), NULL, 0, n_flags);
	if (error != 0)
		inet_ntop(AF_INET6, &sin->sin6_addr, addr_buf,
			  sizeof(addr_buf));
	printf("\tinet6 %s", addr_buf);

	if (ifa->ifa_flags & IFF_POINTOPOINT) {
		sin = (struct sockaddr_in6 *)ifa->ifa_dstaddr;
		/*
		 * some of the interfaces do not have valid destination
		 * address.
		 */
		if (sin != NULL && sin->sin6_family == AF_INET6) {
			/* XXX: embedded link local addr check */
			if (IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr) &&
			    *(u_short *)&sin->sin6_addr.s6_addr[2] != 0) {
				u_short index;

				index = *(u_short *)&sin->sin6_addr.s6_addr[2];
				*(u_short *)&sin->sin6_addr.s6_addr[2] = 0;
				if (sin->sin6_scope_id == 0)
					sin->sin6_scope_id = ntohs(index);
			}

			error = getnameinfo((struct sockaddr *)sin,
					    sin->sin6_len, addr_buf,
					    sizeof(addr_buf), NULL, 0,
					    NI_NUMERICHOST);
			if (error != 0)
				inet_ntop(AF_INET6, &sin->sin6_addr, addr_buf,
					  sizeof(addr_buf));
			printf(" --> %s", addr_buf);
		}
	}

	sin = (struct sockaddr_in6 *)ifa->ifa_netmask;
	if (sin == NULL)
		sin = &null_sin;
	prefixlen = prefix(&sin->sin6_addr, sizeof(struct in6_addr));
	if (f_inet6 != NULL && strcmp(f_inet6, "cidr") == 0)
		printf("/%d", prefixlen);
	else
		printf(" prefixlen %d", prefixlen);

	if ((flags6 & IN6_IFF_ANYCAST) != 0)
		printf(" anycast");
	if ((flags6 & IN6_IFF_TENTATIVE) != 0)
		printf(" tentative");
	if ((flags6 & IN6_IFF_DUPLICATED) != 0)
		printf(" duplicated");
	if ((flags6 & IN6_IFF_DETACHED) != 0)
		printf(" detached");
	if ((flags6 & IN6_IFF_DEPRECATED) != 0)
		printf(" deprecated");
	if ((flags6 & IN6_IFF_AUTOCONF) != 0)
		printf(" autoconf");
	if ((flags6 & IN6_IFF_TEMPORARY) != 0)
		printf(" temporary");

        if (scopeid)
		printf(" scopeid 0x%x", scopeid);

	if (ip6lifetime && (lifetime.ia6t_preferred || lifetime.ia6t_expire)) {
		printf(" pltime");
		if (lifetime.ia6t_preferred) {
			printf(" %s", lifetime.ia6t_preferred < now.tv_sec
				? "0" : sec2str(lifetime.ia6t_preferred - now.tv_sec));
		} else {
			printf(" infty");
		}

		printf(" vltime");
		if (lifetime.ia6t_expire) {
			printf(" %s", lifetime.ia6t_expire < now.tv_sec
				? "0" : sec2str(lifetime.ia6t_expire - now.tv_sec));
		} else {
			printf(" infty");
		}
	}

	putchar('\n');
}

#define	SIN6(x) ((struct sockaddr_in6 *) &(x))
static struct	sockaddr_in6 *sin6tab[] = {
	SIN6(in6_ridreq.ifr_addr), SIN6(in6_addreq.ifra_addr),
	SIN6(in6_addreq.ifra_prefixmask), SIN6(in6_addreq.ifra_dstaddr)
};

static void
in6_getprefix(const char *plen, int which)
{
	struct sockaddr_in6 *sin = sin6tab[which];
	u_char *cp;
	int len = atoi(plen);

	if ((len < 0) || (len > 128))
		errx(1, "%s: bad value", plen);
	sin->sin6_len = sizeof(*sin);
	if (which != MASK)
		sin->sin6_family = AF_INET6;
	if ((len == 0) || (len == 128)) {
		memset(&sin->sin6_addr, 0xff, sizeof(struct in6_addr));
		return;
	}
	memset(&sin->sin6_addr, 0x00, sizeof(sin->sin6_addr));
	for (cp = (u_char *)&sin->sin6_addr; len > 7; len -= 8)
		*cp++ = 0xff;
	*cp = 0xff << (8 - len);
}

static void
in6_getaddr(const char *s, int which)
{
	struct sockaddr_in6 *sin = sin6tab[which];
	struct addrinfo hints, *res;
	int error = -1;

	newaddr = true;

	sin->sin6_len = sizeof(*sin);
	if (which != MASK)
		sin->sin6_family = AF_INET6;

	if (which == ADDR) {
		char *p = NULL;
		if((p = strrchr(s, '/')) != NULL) {
			*p = '\0';
			in6_getprefix(p + 1, MASK);
			explicit_prefix = 1;
		}
	}

	if (sin->sin6_family == AF_INET6) {
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_INET6;
		error = getaddrinfo(s, NULL, &hints, &res);
	}
	if (error != 0) {
		if (inet_pton(AF_INET6, s, &sin->sin6_addr) != 1)
			errx(1, "%s: bad value", s);
	} else
		memcpy(sin, res->ai_addr, res->ai_addrlen);
}

static int
prefix(void *val, int size)
{
        u_char *name = (u_char *)val;
        int byte, bit, plen = 0;

        for (byte = 0; byte < size; byte++, plen += 8)
                if (name[byte] != 0xff)
                        break;
	if (byte == size)
		return (plen);
	for (bit = 7; bit != 0; bit--, plen++)
                if (!(name[byte] & (1 << bit)))
                        break;
        for (; bit != 0; bit--)
                if (name[byte] & (1 << bit))
                        return(0);
        byte++;
        for (; byte < size; byte++)
                if (name[byte])
                        return(0);
        return (plen);
}

static char *
sec2str(time_t total)
{
	static char result[256];
	int days, hours, mins, secs;
	int first = 1;
	char *p = result;

	if (0) {
		days = total / 3600 / 24;
		hours = (total / 3600) % 24;
		mins = (total / 60) % 60;
		secs = total % 60;

		if (days) {
			first = 0;
			p += sprintf(p, "%dd", days);
		}
		if (!first || hours) {
			first = 0;
			p += sprintf(p, "%dh", hours);
		}
		if (!first || mins) {
			first = 0;
			p += sprintf(p, "%dm", mins);
		}
		sprintf(p, "%ds", secs);
	} else
		sprintf(result, "%lu", (unsigned long)total);

	return(result);
}

static void
in6_postproc(int s, const struct afswtch *afp)
{
	if (explicit_prefix == 0) {
		/* Aggregatable address architecture defines all prefixes
		   are 64. So, it is convenient to set prefixlen to 64 if
		   it is not specified. */
		setifprefixlen("64", 0, s, afp);
		/* in6_getprefix("64", MASK) if MASK is available here... */
	}
}

static void
in6_status_tunnel(int s)
{
	char src[NI_MAXHOST];
	char dst[NI_MAXHOST];
	struct in6_ifreq in6_ifr;
	const struct sockaddr *sa = (const struct sockaddr *) &in6_ifr.ifr_addr;

	memset(&in6_ifr, 0, sizeof(in6_ifr));
	strlcpy(in6_ifr.ifr_name, IfName, sizeof(in6_ifr.ifr_name));

	if (ioctl(s, SIOCGIFPSRCADDR_IN6, &in6_ifr) < 0)
		return;
	if (sa->sa_family != AF_INET6)
		return;
	in6_fillscopeid(&in6_ifr.ifr_addr);
	if (getnameinfo(sa, sa->sa_len, src, sizeof(src), 0, 0,
	    NI_NUMERICHOST) != 0)
		src[0] = '\0';

	if (ioctl(s, SIOCGIFPDSTADDR_IN6, &in6_ifr) < 0)
		return;
	if (sa->sa_family != AF_INET6)
		return;
	in6_fillscopeid(&in6_ifr.ifr_addr);
	if (getnameinfo(sa, sa->sa_len, dst, sizeof(dst), 0, 0,
	    NI_NUMERICHOST) != 0)
		dst[0] = '\0';

	printf("\ttunnel inet6 %s --> %s\n", src, dst);
}

static void
in6_set_tunnel(int s, struct addrinfo *srcres, struct addrinfo *dstres)
{
	struct in6_aliasreq addreq;

	memset(&addreq, 0, sizeof(addreq));
	strlcpy(addreq.ifra_name, IfName, sizeof(addreq.ifra_name));
	memcpy(&addreq.ifra_addr, srcres->ai_addr, srcres->ai_addr->sa_len);
	memcpy(&addreq.ifra_dstaddr, dstres->ai_addr, dstres->ai_addr->sa_len);

	if (ioctl(s, SIOCSIFPHYADDR_IN6, &addreq) < 0)
		warn("SIOCSIFPHYADDR_IN6");
}

static struct cmd inet6_cmds[] = {
	DEF_CMD_ARG("prefixlen",			setifprefixlen),
	DEF_CMD("anycast",	IN6_IFF_ANYCAST,	setip6flags),
	DEF_CMD("tentative",	IN6_IFF_TENTATIVE,	setip6flags),
	DEF_CMD("-tentative",	-IN6_IFF_TENTATIVE,	setip6flags),
	DEF_CMD("deprecated",	IN6_IFF_DEPRECATED,	setip6flags),
	DEF_CMD("-deprecated", -IN6_IFF_DEPRECATED,	setip6flags),
	DEF_CMD("autoconf",	IN6_IFF_AUTOCONF,	setip6flags),
	DEF_CMD("-autoconf",	-IN6_IFF_AUTOCONF,	setip6flags),
	DEF_CMD_ARG("pltime",				setip6pltime),
	DEF_CMD_ARG("vltime",				setip6vltime),
	DEF_CMD("eui64",	0,			setip6eui64),
};

static struct afswtch af_inet6 = {
	.af_name	= "inet6",
	.af_af		= AF_INET6,
	.af_status	= in6_status,
	.af_getaddr	= in6_getaddr,
	.af_getprefix	= in6_getprefix,
	.af_postproc	= in6_postproc,
	.af_status_tunnel = in6_status_tunnel,
	.af_settunnel	= in6_set_tunnel,
	.af_difaddr	= SIOCDIFADDR_IN6,
	.af_aifaddr	= SIOCAIFADDR_IN6,
	.af_ridreq	= &in6_ridreq,
	.af_addreq	= &in6_addreq,
};

static void
in6_Lopt_cb(const char *arg __unused)
{
	ip6lifetime++;	/* print IPv6 address lifetime */
}
static struct option in6_Lopt = { "L", "[-L]", in6_Lopt_cb, NULL };

__constructor(113)
static void
inet6_ctor(void)
{
	size_t i;

	for (i = 0; i < nitems(inet6_cmds);  i++)
		cmd_register(&inet6_cmds[i]);

	af_register(&af_inet6);
	opt_register(&in6_Lopt);
}

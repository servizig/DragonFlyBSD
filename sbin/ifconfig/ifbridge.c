/*-
 * Copyright 2001 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
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
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/ifconfig/ifbridge.c,v 1.1.2.2 2005/12/28 04:12:58 thompsa Exp $
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/route.h>
#include <net/ethernet.h>
#include <net/bridge/if_bridgevar.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "ifconfig.h"

static int
get_val(const char *cp, u_long *valp)
{
	char *endptr;
	u_long val;

	errno = 0;
	val = strtoul(cp, &endptr, 0);
	if (cp[0] == '\0' || endptr[0] != '\0' || errno == ERANGE)
		return (-1);

	*valp = val;
	return (0);
}

static int
do_cmd(int sock, u_long op, void *arg, size_t argsize, int set)
{
	struct ifdrv ifd;

	memset(&ifd, 0, sizeof(ifd));

	strlcpy(ifd.ifd_name, IfName, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = argsize;
	ifd.ifd_data = arg;

	return (ioctl(sock, set ? SIOCSDRVSPEC : SIOCGDRVSPEC, &ifd));
}

static void
do_bridgeflag(int sock, const char *ifs, int flag, int set)
{
	struct ifbreq req;

	strlcpy(req.ifbr_ifsname, ifs, sizeof(req.ifbr_ifsname));

	if (do_cmd(sock, BRDGGIFFLGS, &req, sizeof(req), 0) < 0)
		err(1, "unable to get bridge flags");

	if (set)
		req.ifbr_ifsflags |= flag;
	else
		req.ifbr_ifsflags &= ~flag;

	if (do_cmd(sock, BRDGSIFFLGS, &req, sizeof(req), 1) < 0)
		err(1, "unable to set bridge flags");
}

static void
bridge_interfaces(int s, const char *prefix)
{
	static const char *stpstates[] = {
		"disabled",
		"listening",
		"learning",
		"forwarding",
		"blocking",
		"bonded",
		"blocking (link1)"
	};
	struct ifbifconf bifc;
	struct ifbreq *req;
	char *inbuf = NULL, *ninbuf;
	char *p, *pad;
	size_t i, len = 8192;

	pad = strdup(prefix);
	if (pad == NULL)
		err(1, "strdup");
	/* replace the prefix with whitespace */
	for (p = pad; *p != '\0'; p++) {
		if(isprint(*p))
			*p = ' ';
	}

	for (;;) {
		ninbuf = realloc(inbuf, len);
		if (ninbuf == NULL)
			err(1, "unable to allocate interface buffer");
		bifc.ifbic_len = len;
		bifc.ifbic_buf = inbuf = ninbuf;
		if (do_cmd(s, BRDGGIFS, &bifc, sizeof(bifc), 0) < 0)
			err(1, "unable to get interface list");
		if ((bifc.ifbic_len + sizeof(*req)) < len)
			break;
		len *= 2;
	}

	for (i = 0; i < bifc.ifbic_len / sizeof(*req); i++) {
		req = bifc.ifbic_req + i;
		printf("%s%s ", prefix, req->ifbr_ifsname);
		printb("flags", req->ifbr_ifsflags, IFBIFBITS);
		printf("\n");

		if (req->ifbr_ifsflags & IFBIF_STP) {
			printf("%s", pad);
			printf("port %u priority %u",
			    req->ifbr_portno, req->ifbr_priority);
			printf(" pathcost %u", req->ifbr_path_cost);
			if (req->ifbr_state < nitems(stpstates))
				printf(" %s", stpstates[req->ifbr_state]);
			else
				printf(" <unknown state %d>",
				    req->ifbr_state);
			printf("\n");
			printf("%sbondweight %u\n",
				pad, req->ifbr_bond_weight);
			printf("%sdesignated root:   %016jx\n",
				pad, (uintmax_t)req->ifbr_designated_root);
			printf("%sdesignated bridge: %016jx\n",
				pad, (uintmax_t)req->ifbr_designated_bridge);
			printf("%sdesignated cost:   %u\n",
				pad, req->ifbr_designated_cost);
			printf("%sdesignated port:   %u\n",
				pad, req->ifbr_designated_port);
			if (verbose) {
				printf("%speer root:   %016jx\n",
					pad, (uintmax_t)req->ifbr_peer_root);
				printf("%speer bridge: %016jx\n",
					pad, (uintmax_t)req->ifbr_peer_bridge);
				printf("%speer cost:   %u\n",
					pad, req->ifbr_peer_cost);
				printf("%speer port:   %u\n",
					pad, req->ifbr_peer_port);
			}
		}
	}

	free(inbuf);
}

static void
bridge_addresses(int s, const char *prefix)
{
	struct ifbaconf ifbac;
	struct ifbareq *ifba;
	struct ether_addr ea;
	char *inbuf = NULL, *ninbuf;
	size_t i, len = 8192;

	for (;;) {
		ninbuf = realloc(inbuf, len);
		if (ninbuf == NULL)
			err(1, "unable to allocate address buffer");
		ifbac.ifbac_len = len;
		ifbac.ifbac_buf = inbuf = ninbuf;
		if (do_cmd(s, BRDGRTS, &ifbac, sizeof(ifbac), 0) < 0)
			err(1, "unable to get address cache");
		if ((ifbac.ifbac_len + sizeof(*ifba)) < len)
			break;
		len *= 2;
	}

	for (i = 0; i < ifbac.ifbac_len / sizeof(*ifba); i++) {
		ifba = ifbac.ifbac_req + i;
		memcpy(ea.octet, ifba->ifba_dst,
		    sizeof(ea.octet));
		printf("%s%s %s %lu ", prefix, ether_ntoa(&ea),
		    ifba->ifba_ifsname, ifba->ifba_expire);
		printb("flags", ifba->ifba_flags, IFBAFBITS);
		printf("\n");
	}

	free(inbuf);
}

static void
bridge_status(int s)
{
	struct ifbrparam param;
	u_int16_t pri;
	u_int8_t ht, fd, ma;

	if (do_cmd(s, BRDGGPRI, &param, sizeof(param), 0) < 0)
		return;
	pri = param.ifbrp_prio;

	if (do_cmd(s, BRDGGHT, &param, sizeof(param), 0) < 0)
		return;
	ht = param.ifbrp_hellotime;

	if (do_cmd(s, BRDGGFD, &param, sizeof(param), 0) < 0)
		return;
	fd = param.ifbrp_fwddelay;

	if (do_cmd(s, BRDGGMA, &param, sizeof(param), 0) < 0)
		return;
	ma = param.ifbrp_maxage;

	printf("\tpriority %u hellotime %u fwddelay %u maxage %u\n",
	    pri, ht, fd, ma);

	bridge_interfaces(s, "\tmember: ");

	return;

}

static void
setbridge_add(const char *val, int d __unused, int s,
	      const struct afswtch *afp __unused)
{
	struct ifbreq req;

	memset(&req, 0, sizeof(req));
	strlcpy(req.ifbr_ifsname, val, sizeof(req.ifbr_ifsname));
	if (do_cmd(s, BRDGADD, &req, sizeof(req), 1) < 0)
		err(1, "BRDGADD %s",  val);
}

static void
setbridge_delete(const char *val, int d __unused, int s,
		 const struct afswtch *afp __unused)
{
	struct ifbreq req;

	memset(&req, 0, sizeof(req));
	strlcpy(req.ifbr_ifsname, val, sizeof(req.ifbr_ifsname));
	if (do_cmd(s, BRDGDEL, &req, sizeof(req), 1) < 0)
		err(1, "BRDGDEL %s",  val);
}

static void
setbridge_discover(const char *val, int d __unused, int s,
		   const struct afswtch *afp __unused)
{
	do_bridgeflag(s, val, IFBIF_DISCOVER, 1);
}

static void
unsetbridge_discover(const char *val, int d __unused, int s,
		     const struct afswtch *afp __unused)
{
	do_bridgeflag(s, val, IFBIF_DISCOVER, 0);
}

static void
setbridge_learn(const char *val, int d __unused, int s,
		const struct afswtch *afp __unused)
{
	do_bridgeflag(s, val, IFBIF_LEARNING,  1);
}

static void
unsetbridge_learn(const char *val, int d __unused, int s,
		  const struct afswtch *afp __unused)
{
	do_bridgeflag(s, val, IFBIF_LEARNING,  0);
}

static void
setbridge_span(const char *val, int d __unused, int s,
	       const struct afswtch *afp __unused)
{
	struct ifbreq req;

	memset(&req, 0, sizeof(req));
	strlcpy(req.ifbr_ifsname, val, sizeof(req.ifbr_ifsname));
	if (do_cmd(s, BRDGADDS, &req, sizeof(req), 1) < 0)
		err(1, "BRDGADDS %s",  val);
}

static void
unsetbridge_span(const char *val, int d __unused, int s,
		 const struct afswtch *afp __unused)
{
	struct ifbreq req;

	memset(&req, 0, sizeof(req));
	strlcpy(req.ifbr_ifsname, val, sizeof(req.ifbr_ifsname));
	if (do_cmd(s, BRDGDELS, &req, sizeof(req), 1) < 0)
		err(1, "BRDGDELS %s",  val);
}

static void
setbridge_stp(const char *val, int d __unused, int s,
	      const struct afswtch *afp __unused)
{
	do_bridgeflag(s, val, IFBIF_STP, 1);
}

static void
unsetbridge_stp(const char *val, int d __unused, int s,
		const struct afswtch *afp __unused)
{
	do_bridgeflag(s, val, IFBIF_STP, 0);
}

static void
setbridge_flush(const char *val __unused, int d __unused, int s,
		const struct afswtch *afp __unused)
{
	struct ifbreq req;

	memset(&req, 0, sizeof(req));
	req.ifbr_ifsflags = IFBF_FLUSHDYN;
	if (do_cmd(s, BRDGFLUSH, &req, sizeof(req), 1) < 0)
		err(1, "BRDGFLUSH");
}

static void
setbridge_flushall(const char *val __unused, int d __unused, int s,
		   const struct afswtch *afp __unused)
{
	struct ifbreq req;

	memset(&req, 0, sizeof(req));
	req.ifbr_ifsflags = IFBF_FLUSHALL;
	if (do_cmd(s, BRDGFLUSH, &req, sizeof(req), 1) < 0)
		err(1, "BRDGFLUSH");
}

static void
setbridge_static(const char *val, const char *mac, int s,
		 const struct afswtch *afp __unused)
{
	struct ifbareq req;
	struct ether_addr *ea;

	memset(&req, 0, sizeof(req));
	strlcpy(req.ifba_ifsname, val, sizeof(req.ifba_ifsname));

	ea = ether_aton(mac);
	if (ea == NULL)
		errx(1, "%s: invalid address: %s", val, mac);

	memcpy(req.ifba_dst, ea->octet, sizeof(req.ifba_dst));
	req.ifba_flags = IFBAF_STATIC;

	if (do_cmd(s, BRDGSADDR, &req, sizeof(req), 1) < 0)
		err(1, "BRDGSADDR %s",  val);
}

static void
setbridge_deladdr(const char *val, int d __unused, int s,
		  const struct afswtch *afp __unused)
{
	struct ifbareq req;
	struct ether_addr *ea;

	memset(&req, 0, sizeof(req));

	ea = ether_aton(val);
	if (ea == NULL)
		errx(1, "invalid address: %s",  val);

	memcpy(req.ifba_dst, ea->octet, sizeof(req.ifba_dst));

	if (do_cmd(s, BRDGDADDR, &req, sizeof(req), 1) < 0)
		err(1, "BRDGDADDR %s",  val);
}

static void
getbridge_addr(const char *val __unused, int d __unused, int s,
	       const struct afswtch *afp __unused)
{
	bridge_addresses(s, "");
}

static void
setbridge_maxaddr(const char *arg, int d __unused, int s,
		  const struct afswtch *afp __unused)
{
	struct ifbrparam param;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xffffffff) != 0)
		errx(1, "invalid value: %s",  arg);

	param.ifbrp_csize = val & 0xffffffff;

	if (do_cmd(s, BRDGSCACHE, &param, sizeof(param), 1) < 0)
		err(1, "BRDGSCACHE %s",  arg);
}

static void
setbridge_hellotime(const char *arg, int d __unused, int s,
		    const struct afswtch *afp __unused)
{
	struct ifbrparam param;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xff) != 0)
		errx(1, "invalid value: %s",  arg);

	param.ifbrp_hellotime = val & 0xff;

	if (do_cmd(s, BRDGSHT, &param, sizeof(param), 1) < 0)
		err(1, "BRDGSHT %s",  arg);
}

static void
setbridge_fwddelay(const char *arg, int d __unused, int s,
		   const struct afswtch *afp __unused)
{
	struct ifbrparam param;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xff) != 0)
		errx(1, "invalid value: %s",  arg);

	param.ifbrp_fwddelay = val & 0xff;

	if (do_cmd(s, BRDGSFD, &param, sizeof(param), 1) < 0)
		err(1, "BRDGSFD %s",  arg);
}

static void
setbridge_maxage(const char *arg, int d __unused, int s,
		 const struct afswtch *afp __unused)
{
	struct ifbrparam param;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xff) != 0)
		errx(1, "invalid value: %s",  arg);

	param.ifbrp_maxage = val & 0xff;

	if (do_cmd(s, BRDGSMA, &param, sizeof(param), 1) < 0)
		err(1, "BRDGSMA %s",  arg);
}

static void
setbridge_priority(const char *arg, int d __unused, int s,
		   const struct afswtch *afp __unused)
{
	struct ifbrparam param;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xffff) != 0)
		errx(1, "invalid value: %s",  arg);

	param.ifbrp_prio = val & 0xffff;

	if (do_cmd(s, BRDGSPRI, &param, sizeof(param), 1) < 0)
		err(1, "BRDGSPRI %s",  arg);
}

static void
setbridge_ifpriority(const char *ifn, const char *pri, int s,
		     const struct afswtch *afp __unused)
{
	struct ifbreq req;
	u_long val;

	memset(&req, 0, sizeof(req));

	if (get_val(pri, &val) < 0 || (val & ~0xff) != 0)
		errx(1, "invalid value: %s",  pri);

	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	req.ifbr_priority = val & 0xff;

	if (do_cmd(s, BRDGSIFPRIO, &req, sizeof(req), 1) < 0)
		err(1, "BRDGSIFPRIO %s",  pri);
}

static void
setbridge_ifpathcost(const char *ifn, const char *cost, int s,
		     const struct afswtch *afp __unused)
{
	struct ifbreq req;
	u_long val;

	memset(&req, 0, sizeof(req));

	if (get_val(cost, &val) < 0 || (val & ~0xff) != 0)
		errx(1, "invalid value: %s",  cost);

	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	req.ifbr_path_cost = val & 0xffff;

	if (do_cmd(s, BRDGSIFCOST, &req, sizeof(req), 1) < 0)
		err(1, "BRDGSIFCOST %s",  cost);
}

static void
setbridge_ifbondweight(const char *ifn, const char *cost, int s,
		       const struct afswtch *afp __unused)
{
	struct ifbreq req;
	u_long val;

	memset(&req, 0, sizeof(req));

	if (get_val(cost, &val) < 0 || (val & ~0xff) != 0)
		errx(1, "invalid value: %s",  cost);

	strlcpy(req.ifbr_ifsname, ifn, sizeof(req.ifbr_ifsname));
	if (val > 65535)
		val = 65535;
	req.ifbr_bond_weight = (uint16_t)val;

	if (do_cmd(s, BRDGSBONDWGHT, &req, sizeof(req), 1) < 0)
		err(1, "BRDGSBONDWGHT %s",  cost);
}

static void
setbridge_timeout(const char *arg, int d __unused, int s,
		  const struct afswtch *afp __unused)
{
	struct ifbrparam param;
	u_long val;

	if (get_val(arg, &val) < 0 || (val & ~0xffffffff) != 0)
		errx(1, "invalid value: %s",  arg);

	param.ifbrp_ctime = val & 0xffffffff;

	if (do_cmd(s, BRDGSTO, &param, sizeof(param), 1) < 0)
		err(1, "BRDGSTO %s",  arg);
}

static struct cmd bridge_cmds[] = {
	DEF_CMD_ARG("addm",		setbridge_add),
	DEF_CMD_ARG("deletem",		setbridge_delete),
	DEF_CMD_ARG("discover",		setbridge_discover),
	DEF_CMD_ARG("-discover",	unsetbridge_discover),
	DEF_CMD_ARG("learn",		setbridge_learn),
	DEF_CMD_ARG("-learn",		unsetbridge_learn),
	DEF_CMD_ARG("span",		setbridge_span),
	DEF_CMD_ARG("-span",		unsetbridge_span),
	DEF_CMD_ARG("stp",		setbridge_stp),
	DEF_CMD_ARG("-stp",		unsetbridge_stp),
	DEF_CMD("flush", 0,		setbridge_flush),
	DEF_CMD("flushall", 0,		setbridge_flushall),
	DEF_CMD_ARG2("static",		setbridge_static),
	DEF_CMD_ARG("deladdr",		setbridge_deladdr),
	DEF_CMD("addr",	 1,		getbridge_addr),
	DEF_CMD_ARG("maxaddr",		setbridge_maxaddr),
	DEF_CMD_ARG("hellotime",	setbridge_hellotime),
	DEF_CMD_ARG("fwddelay",		setbridge_fwddelay),
	DEF_CMD_ARG("maxage",		setbridge_maxage),
	DEF_CMD_ARG("priority",		setbridge_priority),
	DEF_CMD_ARG2("ifpriority",	setbridge_ifpriority),
	DEF_CMD_ARG2("ifpathcost",	setbridge_ifpathcost),
	DEF_CMD_ARG2("ifbondweight",	setbridge_ifbondweight),
	DEF_CMD_ARG("timeout",		setbridge_timeout),
};
static struct afswtch af_bridge = {
	.af_name	= "af_bridge",
	.af_af		= AF_UNSPEC,
	.af_other_status = bridge_status,
};

__constructor(141)
static void
bridge_ctor(void)
{
	size_t i;

	for (i = 0; i < nitems(bridge_cmds);  i++)
		cmd_register(&bridge_cmds[i]);

	af_register(&af_bridge);
}

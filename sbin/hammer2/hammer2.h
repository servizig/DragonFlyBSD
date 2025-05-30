/*
 * Copyright (c) 2011-2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 * by Venkatesh Srinivas <vsrinivas@dragonflybsd.org>
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

#ifndef HAMMER2_HAMMER2_H_
#define HAMMER2_HAMMER2_H_

/*
 * Rollup headers for hammer2 utility
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ttycom.h>
#include <sys/endian.h>
#include <sys/sysctl.h>
#include <sys/udev.h>
#include <sys/diskslice.h>
#include <sys/dtype.h>
#include <dmsg.h>
#include <dirent.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <vfs/hammer2/hammer2_disk.h>
#include <vfs/hammer2/hammer2_mount.h>
#include <vfs/hammer2/hammer2_ioctl.h>
#include <vfs/hammer2/hammer2_xxhash.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <uuid.h>
#include <assert.h>
#include <pthread.h>
#include <poll.h>

#include <libutil.h>

#include "hammer2_subs.h"

#define HAMMER2_DEFAULT_DIR	"/etc/hammer2"
#define HAMMER2_PATH_REMOTE	HAMMER2_DEFAULT_DIR "/remote"
#ifndef UDEV_DEVICE_PATH
#define UDEV_DEVICE_PATH	"/dev/udev"
#endif

#if 0
struct hammer2_idmap {
	struct hammer2_idmap *next;
	uint32_t ran_beg;	/* inclusive */
	uint32_t ran_end;	/* inclusive */
};

typedef struct hammer2_idmap hammer2_idmap_t;

/*
 * UDP broadcast structure (must be endian neutral)
 */
struct hammer2_udppkt {
	char	key[8];		/* HAMMER2.01 */
	char	gen[8];
	char	label[64];
};

typedef struct hammer2_udppkt hammer2_udppkt_t;
#endif

extern int DebugOpt;
extern int VerboseOpt;
extern int QuietOpt;
extern int ForceOpt;
extern int RecurseOpt;
extern int NormalExit;
extern size_t MemOpt;

/*
 * Hammer2 command APIs
 */
void hammer2_demon(void *(*func)(void *), void *arg);

int cmd_remote_connect(const char *sel_path, const char *url);
int cmd_remote_disconnect(const char *sel_path, const char *url);
int cmd_remote_status(const char *sel_path, int all_opt);

int cmd_pfs_getid(const char *sel_path, const char *name, int privateid);
int cmd_pfs_list(int ac, char **av);
int cmd_pfs_create(const char *sel_path, const char *name,
			uint8_t pfs_type, const char *uuid_str);
int cmd_pfs_delete(const char *sel_path, char **av, int ac);
int cmd_pfs_snapshot(const char *sel_path, const char *name, const char *label,
			uint32_t pfs_flags);

int cmd_service(void);
int cmd_hash(int ac, const char **av);
int cmd_dhash(int ac, const char **av);
int cmd_info(int ac, const char **av);
int cmd_mountall(int ac, const char **av);
int cmd_stat(int ac, const char **av);
int cmd_leaf(const char *sel_path);
int cmd_shell(const char *hostname);
int cmd_debugspan(const char *hostname);
int cmd_destroy_path(int ac, const char **av);
int cmd_destroy_inum(const char *sel_path, int ac, const char **av);
int cmd_dumpchain(const char *path, u_int flags);
int cmd_emergency_mode(const char *sel_path, int enable,
			int ac, const char **av);
int cmd_growfs(const char *sel_path, int ac, const char **av);
int cmd_show(const char *devpath, int which);
int cmd_volume_list(int ac, char **av);
int cmd_rsainit(const char *dir_path);
int cmd_rsaenc(const char **keys, int nkeys);
int cmd_rsadec(const char **keys, int nkeys);
int cmd_setcomp(const char *comp_str, char **paths);
int cmd_setcheck(const char *comp_str, char **paths);
int cmd_bulkfree(const char *dir_path);
int cmd_cleanup(const char *dir_path);
int cmd_recover(const char *devpath, const char *filename,
			const char *destdir, int strict, int isafile);
#if 0
int cmd_bulkfree_async(const char *dir_path);
#endif

void hammer2_shell_parse(dmsg_msg_t *msg, int unmanaged);
void print_inode(const char *path);

#endif /* !HAMMER2_HAMMER2_H_ */

#	@(#)Makefile	8.1 (Berkeley) 6/5/93
#	$FreeBSD: src/share/man/man5/Makefile 211725 2010-08-23 22:24:11Z imp $

MAN=	acct.5 \
	a.out.5 \
	autofs.5 \
	compilers.conf.5 \
	core.5 \
	crypttab.5 \
	devfs.5 \
	devtab.5 \
	dir.5 \
	dirfs.5 \
	disktab.5 \
	elf.5 \
	ethers.5 \
	eui64.5 \
	ext2fs.5 \
	fbtab.5 \
	ffs.5 \
	forward.5 \
	fs.5 \
	fstab.5 \
	group.5 \
	hammer.5 \
	hosts.5 \
	hosts.equiv.5 \
	hosts.lpd.5 \
	intro.5 \
	libmap.conf.5 \
	kernconf.5 \
	link.5 \
	loader.conf.5 \
	mailer.conf.5 \
	make.conf.5 \
	motd.5 \
	msdos.5 \
	networks.5 \
	nfs.5 \
	nsmb.conf.5 \
	nsswitch.conf.5 \
	null.5 \
	passwd.5 \
	periodic.conf.5 \
	pf.conf.5 \
	pf.os.5 \
	phones.5 \
	procfs.5 \
	protocols.5 \
	rc.conf.5 \
	regdomain.5 \
	remote.5 \
	resident.conf.5 \
	resolver.5 \
	services.5 \
	shells.5 \
	smbfs.5 \
	sysctl.conf.5 \
	tmpfs.5 \
	utmpx.5 \
	uuids.5 \
	varsym.conf.5 \
	wg.conf.5

.if defined(WANT_HESIOD)
MAN+=	hesiod.conf.5
.endif

MLINKS=	dir.5 dirent.5
MLINKS+=ffs.5 ufs.5 \
	ffs.5 UFS.5
MLINKS+=fs.5 inode.5
MLINKS+=hammer.5 HAMMER.5
MLINKS+=null.5 nullfs.5
MLINKS+=hosts.equiv.5 rhosts.5
MLINKS+=passwd.5 master.passwd.5
MLINKS+=resolver.5 resolv.conf.5
MLINKS+=utmpx.5 lastlogx.5 \
	utmpx.5 wtmpx.5
MLINKS+=wg.conf.5 wireguard.conf.5

.include <bsd.prog.mk>

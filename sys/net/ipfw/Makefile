# $FreeBSD: src/sys/modules/ipfw/Makefile,v 1.11.2.1 2003/02/14 14:09:21 maxim Exp $

KMOD=	ipfw
SRCS=	ip_fw2.c
SRCS+=	opt_ipfw.h opt_inet.h

.ifndef KERNBUILDDIR
opt_inet.h:
	echo '#define INET 1' > ${.OBJDIR}/${.TARGET}

opt_ipfw.h:
	echo '#define IPFIREWALL 1' > ${.OBJDIR}/${.TARGET}
	# Debug prints
	#echo '#define IPFIREWALL_DEBUG 1' >> ${.OBJDIR}/${.TARGET}
	#
	# If you want it verbose
	#echo '#define IPFIREWALL_VERBOSE 1' >> ${.OBJDIR}/${.TARGET}
	#echo '#define IPFIREWALL_VERBOSE_LIMIT 100' >> ${.OBJDIR}/${.TARGET}
	#
	# If you want it to pass all packets by default
	#echo '#define IPFIREWALL_DEFAULT_TO_ACCEPT 1' >> ${.OBJDIR}/${.TARGET}
.endif

.include <bsd.kmod.mk>

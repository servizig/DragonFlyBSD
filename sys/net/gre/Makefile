.PATH: ${.CURDIR}/../../net ${.CURDIR}/../../netinet 

KMOD=	if_gre
SRCS=	if_gre.c ip_gre.c opt_inet.h
SRCS+=	device_if.h bus_if.h

.if !defined(KERNBUILDDIR)
opt_inet.h:
	echo "#define INET 1" > ${.TARGET}
.endif

.include <bsd.kmod.mk>

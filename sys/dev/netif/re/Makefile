KMOD	= if_re
SRCS	= if_re.c re.c
SRCS	+= device_if.h bus_if.h pci_if.h pcidevs.h
SRCS	+= opt_ifpoll.h

.ifndef KERNBUILDDIR
opt_ifpoll.h:
	echo '#define IFPOLL_ENABLE 1' > ${.OBJDIR}/${.TARGET}
.endif

.include <bsd.kmod.mk>

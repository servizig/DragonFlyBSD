KMOD	= if_ix
SRCS	= if_ix.c
SRCS	+= device_if.h bus_if.h pci_if.h
SRCS	+= opt_ix.h opt_ifpoll.h

SRCS	+= ixgbe_common.c ixgbe_api.c ixgbe_phy.c ixgbe_mbx.c
SRCS	+= ixgbe_osdep_pf.c
SRCS	+= ixgbe_dcb.c ixgbe_dcb_82598.c ixgbe_dcb_82599.c
SRCS	+= ixgbe_82598.c ixgbe_82599.c ixgbe_x540.c ixgbe_x550.c

.ifndef KERNBUILDDIR

opt_ix.h:
	touch ${.OBJDIR}/${.TARGET}

opt_ifpoll.h:
	echo '#define IFPOLL_ENABLE 1' > ${.OBJDIR}/${.TARGET}

.endif

.include <bsd.kmod.mk>

.include "../Makefile.inc"
.include "../libgcc/Makefile.src"

LIB=		gcc_eh

# this is a special case
NOSHARED=	YES

CFLAGS+=	-fpic

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.OBJDIR}
CFLAGS+=	-I${GCCDIR}/libgcc
CFLAGS+=	-I../csu
CFLAGS+=	-fbuilding-libgcc
CFLAGS+=	-fno-stack-protector
CFLAGS+=	-fexceptions
CFLAGS+=	-fvisibility=hidden
CFLAGS+=	-DIN_GCC
CFLAGS+=	-DIN_LIBGCC2
CFLAGS+=	-DHAVE_CC_TLS
CFLAGS+=	-DHIDE_EXPORTS

SRCS=		${LIB2ADDEH:T}

# generated sources
SRCS+=		unwind.h md-unwind-support.h gthr-default.h

SRCS+=		auto-target.h
CLEANFILES+=	auto-target.h
auto-target.h: ${.CURDIR}/../libgcc/auto-target.h
	cp ${.ALLSRC} ${.TARGET}

.include <bsd.lib.mk>

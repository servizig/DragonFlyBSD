.include "../Makefile.inc"

LIB=		common-target
INTERNALLIB=	YES

.PATH: ${GCCDIR}/gcc/common
.PATH: ${GCCDIR}/gcc/common/config/i386

common_out_object_file=	${common_out_file:T:.cc=.o}

# Verbatim from gcc/Makefile.in, except that 'selftest.o' is moved under
# -DTOOLCHAIN_CHECKING.
OBJS-libcommon-target = $(common_out_object_file) prefix.o \
	opts.o opts-common.o options.o vec.o hooks.o common/common-targhooks.o \
	hash-table.o file-find.o spellcheck.o opt-suggestions.o

.if ${CFLAGS:M-DTOOLCHAIN_CHECKING}
OBJS-libcommon-target+=	selftest.o
.endif

SRCS=		${OBJS-libcommon-target:T:.o=.cc}

CFLAGS+=	-DPREFIX=\"${TOOLS_PREFIX}/usr\"

FLAGS_GROUPS=		warn
warn_FLAGS_FILES=	opts-common.cc options.cc
.if (${CCVER:Mgcc80} || ${CCVER:Mgcc120})
warn_FLAGS=	-Wno-narrowing
.elif ${CCVER:Mclang*}
warn_FLAGS=	-Wno-c++11-narrowing
.endif

.include <bsd.lib.mk>

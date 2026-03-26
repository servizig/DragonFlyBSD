GCC_LANG_DIR=	gcc/cp
.include "../Makefile.inc"
.include "../../Makefile.langs"
.include "../../../Makefile.cco"

PROG_CXX=	c++
LINKS=		${BINDIR}/c++ ${BINDIR}/g++
LINKS+=		${BINDIR}/c++ ${BINDIR}/CC
NOMAN=		# man pages installed by cc (MLINK)

objs=		${GCC_OBJS} g++spec.o ${EXTRA_GCC_OBJS}
SRCS=		${objs:.o=.cc}

CFLAGS+=	-DCONFIGURE_SPECS="\"\"" \
		-DACCEL_DIR_SUFFIX="\"\"" \
		-DDEFAULT_REAL_TARGET_MACHINE="\"${target_machine}\""

.include <bsd.prog.mk>

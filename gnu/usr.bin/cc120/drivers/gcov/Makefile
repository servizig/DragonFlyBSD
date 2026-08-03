.include "../Makefile.inc"
.include "../../Makefile.langs"
.include "../../../Makefile.cco"

PROG_CXX=	gcov
MFILE=		gcov${MANPAGEVER}.1
MAN=		${MFILE}

SRCS=		gcov.cc

LDADD+=		${LIBZ}
DPADD+=		${LIBZ}

${MFILE}: ${GCCDIR}/gcc/doc/gcov.1
	cp ${.ALLSRC} ${.TARGET}

CLEANFILES+=	${MFILE}

.if defined(IS_PRIMARY)
MLINKS+= ${MFILE} gcov.1
.endif

.include <bsd.prog.mk>

# If we defined SRCS, the mkdep fails because it evaluates files with .c
# extension with cc instead of c++ (go figure).  To avoid that, we need
# to define OBJS directly

TOP_PREFIX=	../../

.include "../../../Makefile.inc"
.include "../../../Makefile.langs"

PROG_CXX=	collect2
NOMAN=		yes

###CFLAGS+=	-static-libstdc++

# from gcc/Makefile.in
# - excluded 'collect-aix.o' (effective when CROSS_AIX_SUPPORT)
# - excluded 'selftest.o' (effective when CHECKING_P)
COLLECT2_OBJS = collect2.o tlink.o vec.o ggc-none.o \
  collect-utils.o file-find.o hash-table.o

OBJS=		${COLLECT2_OBJS:T}
SRCS=
LIBS=		${LIBCOMMON} ${LIBCPP} ${LIBBACKTRACE} ${LIBIBERTY} \
		${LIBDECNUMBER}
LDADD=		${LIBS}
DPADD=		${LIBS}


# hack to force c++ compiler to compile *.c files to create library
.for ofile in ${OBJS}
${ofile}: ${ofile:.o=.c}
	${CXX} ${STATIC_CXXFLAGS} ${CXXFLAGS} -c ${.IMPSRC} -o ${.TARGET}
.endfor

.include <bsd.prog.mk>

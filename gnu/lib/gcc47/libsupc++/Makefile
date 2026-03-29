GCC_NO_INC=	yes
.include "../Makefile.inc"
.include "Makefile.src"
.PATH: ${GCCDIR}/libstdc++-v3/libsupc++
.PATH: ${GCCDIR}/libgcc
.PATH: ${GCCDIR}/libiberty

LIB=	supc++

CFLAGS+=	-DIN_GLIBCPP_V3 -DHAVE_CONFIG_H \
		-I${.OBJDIR} -I${GCCDIR}/include
CXXFLAGS+=	-fno-implicit-templates
CXXFLAGS+=	-fdiagnostics-show-location=once
CXXFLAGS+=	-ffunction-sections -fdata-sections
CXXFLAGS+=	-I${GCCDIR}/libgcc
CXXFLAGS+=	-I${GCCDIR}/libstdc++-v3/libsupc++
CXXFLAGS+=	-I${GCCDIR}/libstdc++-v3/include/c_std
CXXFLAGS+=	-I.

# SUPCXX comes from Makefile.src
# libstdc++ includes must be installed first (make installincludes)
# Almost all of the objects have already been built by libstdc++, reuse
OBJS+=	${SUPCXX:S/^/..\/libstdc++\//:.cc=.o}

# from libiberty
SRCS=	cp-demangle.c

# generated
SRCS+=	unwind.h config.h

unwind.h: unwind-generic.h
	cp ${.ALLSRC} ${.TARGET}

# Copy the config.h for cp-demangle.c
config.h: ${CCDIR}/libiberty/config.h
	cp ${.ALLSRC} ${.TARGET}

CLEANFILES+=	unwind.h config.h

.include <bsd.lib.mk>

RELUP=	/../..
.include "../../Makefile.inc"
SRCDIR=	${GCCDIR}/libstdc++-v3
.include "Makefile.src"

LIB=			cxx20convenience
INTERNALLIB=		yes
INTERNALLIBPROF=	yes
# build the PIC archive for libstdc++.so
INSTALL_PIC_ARCHIVE=	yes

.PATH:	${SRCDIR}/src/c++20

# for now do not let the use of -flto (-Wodr...)
.if ${CFLAGS:M-flto}
CFLAGS+=	-fno-lto
LDFLAGS+=	-flto
.endif

CFLAGS+=		-I${.OBJDIR}/../../headers
CFLAGS+=		-I${SRCDIR}/include \
			-I${SRCDIR}/include/std \
			-I${SRCDIR}/include/c_global \
			-I${SRCDIR}/libsupc++
CXXFLAGS+=		-std=gnu++20 -nostdinc++ -fimplicit-templates
CXXFLAGS+=		-fdiagnostics-show-location=once
CXXFLAGS+=		-ffunction-sections -fdata-sections
SHARED_CXXFLAGS=	-D_GLIBCXX_SHARED

SRCS=	${libc__20convenience_la_SOURCES}

.include <bsd.lib.mk>

GCC_NO_INC=	yes
.include "../Makefile.inc"

SRCDIR=	${GCCDIR}/libstdc++-v3
.PATH:	${SRCDIR}/src/filesystem

LIB=		std++fs

NOSHARED=	yes

# for now do not let the use of -flto (???)
.if ${CFLAGS:M-flto}
CFLAGS+=	-fno-lto
LDFLAGS+=	-flto
.endif

CFLAGS+=	-I${.OBJDIR}/../libstdcxx/headers
CFLAGS+=	-I${SRCDIR}/include \
		-I${SRCDIR}/include/std \
		-I${SRCDIR}/include/c_global \
		-I${SRCDIR}/libsupc++

CXXFLAGS+=	-std=gnu++17 -nostdinc++
CXXFLAGS+=	-fdiagnostics-show-location=once
CXXFLAGS+=	-ffunction-sections -fdata-sections
# build as PIC to allow being linked with shared libraries
CXXFLAGS+=	-fPIC -DPIC -D_GLIBCXX_SHARED

# From libstdc++-v3/src/filesystem/Makefile.am
cxx11_abi_sources = \
	cow-dir.cc \
	cow-ops.cc \
	cow-path.cc
sources = \
	dir.cc \
	ops.cc \
	path.cc \
	${cxx11_abi_sources}

SRCS=	${sources}

# Headers are installed by libstdcxx/headers/Makefile.

.include <bsd.lib.mk>

RELUP=	/../..
.include "../../Makefile.inc"
SRCDIR=	${GCCDIR}/libstdc++-v3
.include "Makefile.src"

LIB=			cxx98convenience
INTERNALLIB=		yes
INTERNALLIBPROF=	yes
# build the PIC archive for libstdc++.so
INSTALL_PIC_ARCHIVE=	yes

.PATH:	${SRCDIR}/src/c++98

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
CXXFLAGS+=		-nostdinc++
CXXFLAGS+=		-fdiagnostics-show-location=once
CXXFLAGS+=		-ffunction-sections -fdata-sections
SHARED_CXXFLAGS=	-D_GLIBCXX_SHARED

SRCS=	${libc__98convenience_la_SOURCES}

FLAGS_GROUPS=		default deprecated gnu11 cow concept parallel implicit
default_FLAGS=		-std=gnu++98 -fno-implicit-templates
deprecated_FLAGS=	${default_FLAGS} -I${SRCDIR}/include/backward \
			-Wno-deprecated
deprecated_FLAGS_FILES=	strstream.cc
gnu11_FLAGS=		${default_FLAGS} -std=gnu++11 -fchar8_t
gnu11_FLAGS_FILES=	locale_init.cc localename.cc
cow_FLAGS=		${default_FLAGS} -D_GLIBCXX_USE_CXX11_ABI=0 \
			-fimplicit-templates
cow_FLAGS_FILES=	${cow_string_host_sources}
concept_FLAGS=		${default_FLAGS} -D_GLIBCXX_CONCEPT_CHECKS \
			-fimplicit-templates
concept_FLAGS_FILES=	concept-inst.cc
parallel_FLAGS=		${default_FLAGS} -D_GLIBCXX_PARALLEL
parallel_FLAGS_FILES=	${parallel_sources}
implicit_FLAGS=		${default_FLAGS} -fimplicit-templates
implicit_FLAGS_FILES=	c++locale.cc

REFERENCED_FILES=	${deprecated_FLAGS_FILES} \
			${gnu11_FLAGS_FILES} \
			${cow_FLAGS_FILES} \
			${concept_FLAGS_FILES} \
			${parallel_FLAGS_FILES} \
			${implicit_FLAGS_FILES}

.for F in ${SRCS}
. if ! ${REFERENCED_FILES:M${F}}
default_FLAGS_FILES+=	${F}
. endif
.endfor

CLEANFILES+=	${GENFILES}
beforedepend:	${GENFILES}

.include <bsd.lib.mk>

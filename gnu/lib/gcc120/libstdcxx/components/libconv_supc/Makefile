RELUP=	/../..
.include "../../Makefile.inc"
SRCDIR=	${GCCDIR}/libstdc++-v3
.include "Makefile.src"

LIB=			supcxxconvenience
INTERNALLIB=		yes
INTERNALLIBPROF=	yes
# build the PIC archive for libstdc++.so
INSTALL_PIC_ARCHIVE=	yes

.PATH:	${GCCDIR}/libiberty
.PATH:	${SRCDIR}/libsupc++

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
CFLAGS+=		-I${GCCDIR}/libgcc
CXXFLAGS+=		-nostdinc++
CXXFLAGS+=		-fno-implicit-templates
CXXFLAGS+=		-fdiagnostics-show-location=once
CXXFLAGS+=		-ffunction-sections -fdata-sections
SHARED_CXXFLAGS=	-D_GLIBCXX_SHARED

FLAGS_GROUPS=		gnu11 gnu14 gnu1z iberty
gnu11_FLAGS=		-std=gnu++11
gnu11_FLAGS_FILES=	bad_array_length.cc bad_array_new.cc eh_ptr.cc \
			eh_aux_runtime.cc eh_terminate.cc eh_throw.cc \
			guard.cc atexit_thread.cc nested_exception.cc \
			new_handler.cc new_op.cc new_opnt.cc
gnu14_FLAGS=		-std=gnu++14 -Wno-sized-deallocation
gnu14_FLAGS_FILES=	del_ops.cc del_opvs.cc
gnu1z_FLAGS=		-std=gnu++1z
gnu1z_FLAGS_FILES=	del_opsa.cc del_opvsa.cc \
			del_opa.cc del_opant.cc del_opva.cc del_opvant.cc \
			new_opa.cc new_opant.cc new_opva.cc new_opvant.cc
iberty_FLAGS=		-DHAVE_CONFIG_H -DIN_GLIBCPP_V3 \
			-I${.OBJDIR} -I${GCCDIR}/include
iberty_FLAGS_FILES=	cp-demangle.c

SRCS=			${libsupc__convenience_la_SOURCES}

# Copy the config.h for cp-demangle.c
GENFILES+=	config.h
config.h: ${CCDIR}/support-libs/libiberty/config.h
	cp ${.ALLSRC} ${.TARGET}

CLEANFILES=	${GENFILES}
beforedepend:	${GENFILES}

.include <bsd.lib.mk>

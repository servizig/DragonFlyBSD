RELUP=	/../..
.include "../../Makefile.inc"
SRCDIR=	${GCCDIR}/libstdc++-v3
.include "Makefile.src"

LIB=			cxx11convenience
INTERNALLIB=		yes
INTERNALLIBPROF=	yes
# build the PIC archive for libstdc++.so
INSTALL_PIC_ARCHIVE=	yes

.PATH:	${SRCDIR}/src/c++11

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
CXXFLAGS+=		-std=gnu++11 -nostdinc++
CXXFLAGS+=		-fdiagnostics-show-location=once
CXXFLAGS+=		-ffunction-sections -fdata-sections
SHARED_CXXFLAGS=	-D_GLIBCXX_SHARED

SRCS=		${libc__11convenience_la_SOURCES}

SRCS:=		${SRCS:Ncxx11-ios_failure.cc}
OBJS+=		cxx11-ios_failure.o	# custom rules below
CLEANFILES+=	cxx11-ios_failure.*.s*

FLAGS_GROUPS=		default implicit char8 supcxx
default_FLAGS=		-fno-implicit-templates
implicit_FLAGS=		${default_FLAGS} -fimplicit-templates
implicit_FLAGS_FILES=	hashtable_c++0x.cc
char8_FLAGS=		${default_FLAGS} -fchar8_t
char8_FLAGS_FILES=	codecvt.cc limits.cc
supcxx_FLAGS=		${default_FLAGS} -I${SRCDIR}/libsupc++
supcxx_FLAGS_FILES=	thread.cc

REFERENCED_FILES=	${implicit_FLAGS_FILES} \
			${char8_FLAGS_FILES} \
			${supcxx_FLAGS_FILES}

.for F in ${SRCS}
. if ! ${REFERENCED_FILES:M${F}}
default_FLAGS_FILES+=	${F}
. endif
.endfor

# Derived from libstdc++-v3/src/c++11/Makefile.am:
# Rewrite the type info for __ios_failure.
rewrite_ios_failure_typeinfo = sed -e '/^_*_ZTISt13__ios_failure:/,/_ZTVN10__cxxabiv120__si_class_type_infoE/s/_ZTVN10__cxxabiv120__si_class_type_infoE/_ZTVSt19__iosfail_type_info/'

cxx11-ios_failure.o: cxx11-ios_failure.cc
	${CXX} ${STATIC_CXXFLAGS} ${CXXFLAGS} ${default_FLAGS} \
		-gno-as-loc-support -S -o ${.TARGET}.s.tmp ${.ALLSRC}
	${rewrite_ios_failure_typeinfo} < ${.TARGET}.s.tmp > ${.TARGET}.s
	${CXX} ${STATIC_CXXFLAGS} ${CXXFLAGS} ${default_FLAGS} \
		-g0 -c ${.TARGET}.s -o ${.TARGET}

cxx11-ios_failure.po: cxx11-ios_failure.cc
	${CXX} ${PO_FLAG} ${STATIC_CXXFLAGS} ${PO_CXXFLAGS} ${default_FLAGS} \
		-gno-as-loc-support -S -o ${.TARGET}.s.tmp ${.ALLSRC}
	${rewrite_ios_failure_typeinfo} < ${.TARGET}.s.tmp > ${.TARGET}.s
	${CXX} ${PO_FLAG} ${STATIC_CXXFLAGS} ${PO_CXXFLAGS} ${default_FLAGS} \
		-g0 -c ${.TARGET}.s -o ${.TARGET}

cxx11-ios_failure.So: cxx11-ios_failure.cc
	${CXX} ${PICFLAG} -DPIC ${SHARED_CXXFLAGS} ${CXXFLAGS} ${default_FLAGS} \
		-gno-as-loc-support -S -o ${.TARGET}.s.tmp ${.ALLSRC}
	${rewrite_ios_failure_typeinfo} < ${.TARGET}.s.tmp > ${.TARGET}.s
	${CXX} ${PICFLAG} -DPIC ${SHARED_CXXFLAGS} ${CXXFLAGS} ${default_FLAGS} \
		-g0 -c ${.TARGET}.s -o ${.TARGET}

CLEANFILES+=	${GENFILES}
beforedepend:	${GENFILES}

.include <bsd.lib.mk>

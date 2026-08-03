GCC_NO_PATH=	yes
LOCAL_CONFIG=	yes
.include "../Makefile.inc"

# We could tailor the source list for the tools, but just reuse the whole
# source list for simplicity.
.include "${.CURDIR}/../../support-libs/libiberty/Makefile.src"

LIB=		iberty

GOOD_CONFIG=	${.CURDIR}/../../support-libs/libiberty/config.h

config.h: ${GOOD_CONFIG}
	cp ${.ALLSRC} .

beforedepend: config.h
afterdepend: libiberty.na

CLEANFILES=	config.h

.include <bsd.hostlib.mk>

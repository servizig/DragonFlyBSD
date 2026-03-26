GCC_NO_PATH=	yes
GCC_NO_LIBS=	yes
LOCAL_CONFIG=	yes
.include "../Makefile.inc"
.PATH: ${GCCDIR}/libcody

LIB=		cody
INTERNALLIB=	YES

CFLAGS+=	-DSRCDIR="\"${GCCDIR}\""

# From libcody/Makefile.in
LIBCODY.O=	\
	buffer.o client.o fatal.o netclient.o netserver.o \
	resolver.o packet.o server.o

SRCS=	${LIBCODY.O:.o=.cc}

.include <bsd.lib.mk>

GCC_NO_LIBS=	yes
TOP_PREFIX=	../../

.include "../../../Makefile.inc"
.include "../../../Makefile.langs"

LIB=		guts-common
INTERNALLIB=	yes

SRCS=		${C_COMMON_OBJS:T:.o=.cc}
SRCS+=		main.cc

.include <bsd.lib.mk>

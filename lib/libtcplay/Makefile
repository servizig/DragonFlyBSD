LIB=		tcplay
MAJ_VER=	3
MIN_VER=	3
SHLIB_MAJOR?=	${MAJ_VER}
SHLIB_MINOR?=	${MIN_VER}
MAN=		tcplay.3

MLINKS+=	tcplay.3	tc_api_init.3
MLINKS+=	tcplay.3	tc_api_uninit.3
MLINKS+=	tcplay.3	tc_api_has.3
MLINKS+=	tcplay.3	tc_api_cipher_iterate.3
MLINKS+=	tcplay.3	tc_api_prf_iterate.3
MLINKS+=	tcplay.3	tc_api_task_init.3
MLINKS+=	tcplay.3	tc_api_task_uninit.3
MLINKS+=	tcplay.3	tc_api_task_set.3
MLINKS+=	tcplay.3	tc_api_task_do.3
MLINKS+=	tcplay.3	tc_api_task_info_get.3
MLINKS+=	tcplay.3	tc_api_task_get_error.3

CFLAGS+=	-DMAJ_VER=${MAJ_VER} -DMIN_VER=${MIN_VER}
CFLAGS+=	-D_FILE_OFFSET_BITS=64
CFLAGS+=	-I${.CURDIR}/../../crypto/libressl/include
CFLAGS+=	-I${.CURDIR}/../../sys

SRCS+=		tcplay.c crc32.c safe_mem.c io.c hdr.c humanize.c
SRCS+=		crypto.c generic_xts.c
SRCS+=		pbkdf2-openssl.c
SRCS+=		tcplay_api.c
SRCS+=		crypto-api.c

.PATH:		${.CURDIR}/../../sys/crypto/cryptoapi
SRCS+=		cryptoapi.c
.PATH:		${.CURDIR}/../../sys/crypto/rijndael
SRCS+=		rijndael-alg-fst.c rijndael-api.c
.PATH:		${.CURDIR}/../../sys/crypto/serpent
SRCS+=		serpent.c
.PATH:		${.CURDIR}/../../sys/crypto/twofish
SRCS+=		twofish.c

INCS+=		tcplay_api.h

LDFLAGS+=	-Wl,-version-script=${.CURDIR}/tcplay.map

.include <bsd.lib.mk>

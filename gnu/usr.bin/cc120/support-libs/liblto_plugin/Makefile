# include helpers to decide if lto plugin needs to be installed and where
.include "../../../Makefile.buo"
.include "../../../Makefile.cco"

# liblto_plugin.so needs to linked to a PIC version of libiberty
# A special tailed version of libiberty has been created for this purpose

GCC_NO_LIBS=	# defined
.include "../Makefile.inc"
.PATH: ${GCCDIR}/lto-plugin

LIB=		lto_plugin
SHLIB_MAJOR=	0
NOPROFILE=	yes
NOINSTALLLIB=	yes
# For gcc -print-prog-name=liblto_plugin.so to work
LIBMODE=	555

# GCC driver looks for LTO plugin library in libexec, not lib
TARGET_LIBDIR=		/usr/libexec/gcc120
TARGET_SHLIBDIR=	/usr/libexec/gcc120

SRCS=		lto-plugin.c
LDADD=		../libiberty_pic/libiberty_pic.a

# SYMLINK lto plugin to primary/backup binutils bfd-plugin dirs
.if ${CC_PRIMARY} == "gcc120" # we are default gcc compiler
LTOPLUGIN=	liblto_plugin.so
.if exists(${DESTDIR}/usr/libexec/${BU_PRIMARY}/bfd-plugins)
BFDPLUGINS=	/usr/libexec/${BU_PRIMARY}/bfd-plugins
SYMLINKS+=	../../${CC_PRIMARY}/${LTOPLUGIN} ${BFDPLUGINS}/${LTOPLUGIN}
.endif
.if exists(${DESTDIR}/usr/libexec/${BU_BACKUP}/bfd-plugins)
BFDPLUGINSB=	/usr/libexec/${BU_BACKUP}/bfd-plugins
SYMLINKS+=	../../${CC_PRIMARY}/${LTOPLUGIN} ${BFDPLUGINSB}/${LTOPLUGIN}
.endif
.endif

.include <bsd.lib.mk>

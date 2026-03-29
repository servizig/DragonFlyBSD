GCC_NO_PATH=	yes
GCC_NO_LIBS=	yes
LOCAL_CONFIG=	yes
.include "../Makefile.inc"
.PATH: ${GCCDIR}/libbacktrace

LIB=		backtrace
INTERNALLIB=	YES

CFLAGS+=	-I${GCCDIR}/libbacktrace
## CFLAGS+=	-funwind-tables -frandom-seed=${.IMPSRC}

# From gcc-build/libbacktrace/Makefile
BACKTRACE_FILE = backtrace.lo simple.lo
FORMAT_FILE = elf.lo
VIEW_FILE = mmapio.lo
ALLOC_FILE = mmap.lo
# From libbacktrace/Makefile.am
libbacktrace_la_LIBADD = \
	$(BACKTRACE_FILE) \
	$(FORMAT_FILE) \
	$(VIEW_FILE) \
	$(ALLOC_FILE)
libbacktrace_la_SOURCES = \
	backtrace.h \
	atomic.c \
	dwarf.c \
	fileline.c \
	internal.h \
	posix.c \
	print.c \
	sort.c \
	state.c

SRCS=	${libbacktrace_la_LIBADD:.lo=.c}
SRCS+=	${libbacktrace_la_SOURCES:M*.c}

beforedepend:	unwind.h

unwind.h: ${GCCDIR}/libgcc/unwind-generic.h
	cp ${.ALLSRC} ${.TARGET}

CLEANFILES=	unwind.h

.include <bsd.lib.mk>

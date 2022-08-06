PREFIX?=	/usr/local
LOCALBASE?=	/usr/local
BINDIR=		${PREFIX}/sbin
MANDIR=		${PREFIX}/man/man
LIBDIR=		${PREFIX}/lib
LDADD+=		-lcasper -lcap_sysctl

PROG=		egress-monitor
SRCS=		egress-monitor.c

.include <bsd.prog.mk>

#	$OpenBSD: Makefile,v 1.1 2019/01/19 02:57:04 jsing Exp $

PROG=		recordtest
LDADD=		${SSL_INT} -lcrypto
DPADD=		${LIBSSL} ${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-DLIBRESSL_INTERNAL -Wall -Wundef -Werror
CFLAGS+=	-I${.CURDIR}/../../../../lib/libssl

benchmark: recordtest
	./recordtest --benchmark
.PHONY: benchmark

.include <bsd.regress.mk>

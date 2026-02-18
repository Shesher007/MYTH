# MYTH Desktop — FreeBSD Port Makefile (Binary)
# Install: pkg install myth

PORTNAME=       myth
PORTVERSION=    1.1.3
CATEGORIES=     security net
MASTER_SITES=   https://github.com/shesher010/MYTH/releases/download/v${PORTVERSION}/
DISTFILES=      myth_${PORTVERSION}_amd64.deb

MAINTAINER=     shesher0007@gmail.com
COMMENT=        High-Performance Offensive Intelligence Engine (Binary)
WWW=            https://github.com/shesher010/MYTH

LICENSE=        Proprietary
LICENSE_NAME=   Proprietary
LICENSE_TEXT=    Commercial software.
LICENSE_PERMS=  no-dist-sell no-pkg-sell auto-accept

RUN_DEPENDS=    python3:lang/python3 \
                webkit2-gtk3>0:www/webkit2-gtk3

NO_BUILD=       yes

do-install:
	${INSTALL_PROGRAM} ${DISTDIR}/MYTH_freebsd_x64 \
		${STAGEDIR}${PREFIX}/bin/MYTH

.include <bsd.port.mk>


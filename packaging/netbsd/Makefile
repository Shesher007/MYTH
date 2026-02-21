# MYTH Desktop — NetBSD pkgsrc Makefile (Binary)
# Install: pkgin install myth

DISTNAME=       myth-1.1.6
CATEGORIES=     security net
MASTER_SITES=   https://github.com/Shesher007/MYTH/releases/download/v1.1.6/
DISTFILES=      myth_1.1.6_amd64.deb

MAINTAINER=     shesher0007@gmail.com
HOMEPAGE=       https://github.com/Shesher007/MYTH
COMMENT=        High-Performance Offensive Intelligence Engine (Binary)
LICENSE=        proprietary

DEPENDS+=       python3>=3.10:../../lang/python310

NO_BUILD=       yes

do-install:
	${INSTALL_PROGRAM} ${DISTDIR}/myth_1.1.6_amd64.deb \
		${DESTDIR}${PREFIX}/bin/myth

.include "../../mk/bsd.pkg.mk"

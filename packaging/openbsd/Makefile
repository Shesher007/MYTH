# MYTH Desktop — OpenBSD Package Build (Binary)
# Install: pkg_add myth

COMMENT =       Multi-Yield Tactical Hub — AI Cybersecurity Agent (Binary)

V =             1.1.1
DISTNAME =      myth-${V}

CATEGORIES =    security net

HOMEPAGE =      https://github.com/Start-MYTH/MYTH

MAINTAINER =    admin@myth-tools.com

# Proprietary
PERMIT_PACKAGE =        Yes

MASTER_SITES =  https://github.com/Start-MYTH/MYTH/releases/download/v${V}/
DISTFILES =     MYTH_openbsd_x64

RUN_DEPENDS =   lang/python/3 \
                www/webkit2gtk4

NO_BUILD =      Yes

do-install:
	${INSTALL_PROGRAM} ${DISTDIR}/MYTH_openbsd_x64 \
		${PREFIX}/bin/MYTH

.include <bsd.port.mk>

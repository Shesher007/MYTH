# Copyright 2024-2025 Shesher Hasan
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DESCRIPTION="High-Performance Offensive Intelligence Engine"
HOMEPAGE="https://github.com/hasan0004/MYTH"
SRC_URI="https://github.com/shesher010/MYTH/releases/download/v${PV}/myth-${PV}.tar.gz"

LICENSE="Proprietary"
SLOT="0"
KEYWORDS="~amd64 ~arm64"

DEPEND="
    net-libs/webkit-gtk:4
    dev-libs/libappindicator
"
RDEPEND="${DEPEND}"
BDEPEND="
    virtual/rust
    net-libs/nodejs
"

src_compile() {
    cd ui || die
    npm install || die
    npm run tauri build || die
}

src_install() {
    dobin ui/src-tauri/target/release/myth
}

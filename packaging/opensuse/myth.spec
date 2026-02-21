# MYTH Desktop — OpenSUSE RPM Spec File (Binary Version)
# Install: sudo zypper install myth

Name:           myth
Version:        1.1.6
Release:        1
Summary:        Industrial-Grade Sovereign Security Agent
License:        Proprietary
Group:          Productivity/Security
URL:            https://github.com/Shesher007/MYTH
Source0:        https://github.com/Shesher007/MYTH/releases/download/v%{version}/myth_%{version}_amd64.deb

BuildRequires:  cpio
BuildRequires:  binutils

Requires:       libwebkit2gtk-4_1-0
Requires:       libopenssl1_1
Requires:       python3
Requires:       gtk3

%description
MYTH (Multi-Yield Tactical Hub) is an industry-grade autonomous AI
cybersecurity agent. This package installs the pre-compiled binary.

%prep
# No source code to prep

%build
# No source code to build

%install
# Extract the deb payload
ar x %{SOURCE0} data.tar.xz
tar -xf data.tar.xz -C %{buildroot}/
mv %{buildroot}/usr/bin/myth %{buildroot}/usr/bin/MYTH || true

%files
%{_bindir}/MYTH
%{_datadir}/applications/myth.desktop
%{_datadir}/icons/hicolor/512x512/apps/myth.png

%changelog
* Sat Feb 14 2026 Shesher Hasan <shesher0007@gmail.com> - 1.1.6-1
- Binary-only release 1.1.6

# MYTH Desktop — Mageia RPM Spec File (Binary Version)

Name:           myth
Version:        1.1.6
Release:        1
Summary:        Industrial-Grade Sovereign Security Agent
License:        Proprietary
Group:          Networking/Other
URL:            https://github.com/shesher010/MYTH
Source0:        https://github.com/shesher010/MYTH/releases/download/v%{version}/myth_%{version}_amd64.deb

BuildRequires:  binutils
BuildRequires:  tar

Requires:       lib64webkit2gtk4.1
Requires:       lib64openssl
Requires:       python3
Requires:       lib64gtk+3.0

%description
MYTH is an industry-grade autonomous AI cybersecurity agent.
This package installs the pre-compiled binary.

%prep
# No prep needed

%build
# No build needed

%install
ar x %{SOURCE0} data.tar.xz
tar -xf data.tar.xz -C %{buildroot}/
mv %{buildroot}/usr/bin/myth %{buildroot}/usr/bin/MYTH || true

%files
%{_bindir}/MYTH
%{_datadir}/applications/myth.desktop
%{_datadir}/icons/hicolor/512x512/apps/myth.png

%changelog
* Sat Feb 14 2026 Shesher Hasan <shesher0007@gmail.com> - 1.1.6-1.mga9
- Initial Mageia binary release

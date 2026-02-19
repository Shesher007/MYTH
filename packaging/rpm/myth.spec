Name:           myth
Version:        1.1.6
Release:        1%{?dist}
Summary:        High-Performance Offensive Intelligence Engine

License:        Proprietary
URL:            https://github.com/hasan0004/MYTH
Source0:        myth-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  nodejs
BuildRequires:  npm
BuildRequires:  webkit2gtk3-devel
BuildRequires:  libappindicator3-devel

Requires:       webkit2gtk3
Requires:       libappindicator3

%description
A powerful desktop application for professional security researchers and automation engineers.

%prep
%setup -q

%build
cd ui
npm install
npm run tauri build

%install
mkdir -p %{buildroot}%{_bindir}
install -m 755 ui/src-tauri/target/release/myth %{buildroot}%{_bindir}/myth

%files
%{_bindir}/myth
%doc readme.md

%changelog
* Sun Feb 15 2026 Shesher Hasan <shesher0007@gmail.com> - 1.1.6-1
- Initial standalone release for MYTH.

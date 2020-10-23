%define debug_package %{nil}

%define mybuildnumber %{?build_number}%{?!build_number:1}

Name:           seedvault-backup-parser
Version:        2020.10.23
Release:        %{mybuildnumber}%{?dist}
Summary:        Parse Seedvault backups
BuildArch:      noarch

License:        GPLv2+
URL:            https://github.com/Rudd-O/seedvault_backup_parser
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  coreutils
BuildRequires:  python3-rpm-macros
%global pythoninterp %{_bindir}/python3

Requires:       python3
Requires:       python3-crypto

%description
This program lets you decrypt and reencrypt Seedvault backups.

%prep
%setup -q

%build
true

%install
rm -rf $RPM_BUILD_ROOT
# variables must be kept in sync with build
mkdir -p "$RPM_BUILD_ROOT"/%{_bindir}
cp -f parse.py "$RPM_BUILD_ROOT"/%{_bindir}/%{name}
chmod 755 "$RPM_BUILD_ROOT"/%{_bindir}/%{name}

%files
%attr(0755, root, root) %{_bindir}/%{name}
%doc README.md LICENSE

%changelog
* Fri Oct 23 2020 Manuel Amador (Rudd-O) <rudd-o@rudd-o.com>
- Initial build

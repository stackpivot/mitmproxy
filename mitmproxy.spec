Name:		mitmproxy
Version:	0.1
Release:	1%{?dist}
Summary:	A collection of multi-protocol logging proxy servers and replay utilities for Telnet, HTTP, SSL and SSH.

Group:		Development/Tools
License:	GPLv2
URL:		https://github.com/saironiq/mitmproxy
Source0:	https://github.com/saironiq/mitmproxy/archive/%{version}.tar.gz

Requires:	python-twisted python-twisted-core python-twisted-conch

%description
A collection of multi-protocol logging proxy servers and replay utilities.

Supported protocols:
 * Telnet
 * HTTP
 * SSL
 * SSH


%prep
%setup -q -c


%build
cd %{name}-%{version}
%{__python} setup.py build


%install
cd %{name}-%{version}
%{__python} setup.py install --root=%RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root)
$doc README.md
%{python_sitelib}
%{_bindir}

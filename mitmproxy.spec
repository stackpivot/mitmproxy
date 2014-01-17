Name:		mitmproxy
Version:	0.1
Release:	1%{?dist}
Summary:	A collection of multi-protocol logging proxy servers and replay utilities for Telnet, HTTP, SSL, SSH and SNMP.

Group:		Development/Tools
License:	GPLv2
URL:		https://github.com/saironiq/mitmproxy
Source0:	%{name}-%{version}.tar.gz

Requires:	filesystem bash python-twisted-core python-twisted-conch

%description
A collection of multi-protocol logging proxy servers and replay utilities.

Supported protocols:
 * Telnet
 * HTTP
 * SSL
 * SSH
 * SNMP


%prep
%setup -qc


%build
cd %{name}-%{version}
%{__python} setup.py build


%install
cd %{name}-%{version}
%{__python} setup.py install --root=%{buildroot}


%clean
rm -rf ${buildroot}


%files
%defattr(-,root,root)
%{python_sitelib}
%{_bindir}/*

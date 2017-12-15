Name:    xtomp
Version: 0.2
Release: 1%{?dist}
Summary: A STOMP Message Broker 👢

License: BSD like
Source0: xtomp-0.2.tar.gz
BuildArch: x86_64

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%define debug_package %{nil}

%description
%{summary}

%prep
%setup -q

%build
./configure
make

%install
rm -rf %{buildroot}
DESTDIR=%{buildroot} make install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/%{name}.conf
/usr/lib/xtomp/bin/xtomp
/usr/lib/xtomp/bin/xtomp-kill
/lib/systemd/system/xtomp.service
/usr/share/man/man8/xtomp.8.gz
/var/log/xtomp/error.log

%changelog
* Wed May 10 2017  teknopaul <me@teknopaul.com> 0.2-1
- First Build

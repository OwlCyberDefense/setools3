Summary: The BWidget Toolkit is a high-level Widgets Set for Tcl/Tk
Name: BWidget
Version: 1.4.1
Release: 2
License: LGPL
Group: Development/Languages
Source: http://prdownloads.sorceforge.net/tcllib/BWidget-1.4.1.tar.gz
Source0: %{name}-%{version}.tar.gz
Requires: tcl >= 8.1.1
Requires: tk >= 8.3
Obsoletes: bwidget
Provides: bwidget
BuildRoot: %{_tmppath}/%{name}-root
BuildArch: noarch

%description
The BWidget Toolkit is a high-level Widgets Set for Tcl/Tk built using
native Tcl/Tk 8.x namespaces. 
The BWidgets have a professional look&feel as in other well known Toolkits
(Tix or Incr Widget) but the concept is radically different because everything is
native so no platform compilation, no compiled extension library are needed.
The code is 100% Pure Tcl/Tk.

%prep
%setup -q
# -n %name
%install
install -d $RPM_BUILD_ROOT/usr/share/tcl8.3/%name
install -p -m 0644 *.tcl $RPM_BUILD_ROOT/usr/share/tcl8.3/%name
cp -a demo images lang $RPM_BUILD_ROOT/usr/share/tcl8.3/%name

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%doc ChangeLog *.txt BWman
/usr/share/tcl8.3/%name

%changelog
* Mon Dec 15 2003 Karl MacMillan <kmacmillan@tresys.com> 1.4.1-2
- Moved from /usr/lib to /usr/lib/tcl8.3 to make it work with Fedora Core 1


* Wed Sep 16 2003 Karl MacMillan <kmacmillan@tresys.com> 1.4.1
- Reverted to 1.4.1

* Tue Sep 16 2003 Dan Walsh <dwalsh@redhat.com> 1.6.0-2
- Fix to install in /usr/lib

* Wed Jun 11 2003 Dan Walsh <dwalsh@redhat.com> 1.6.0-1
- update to 1.6.0

* Thu Nov 14 2002 Alexandr D. Kanevskiy <kad@asplinux.ru>
- update to 1.4.1

* Mon Jun 10 2002 Alexandr D. Kanevskiy <kad@asplinux.ru>
- inject

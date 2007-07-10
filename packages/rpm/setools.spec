Name: setools
Version: 3.3
Release: pre3
Vendor: Tresys Technology, LLC
Packager: Jason Tang <selinux@tresys.com>
License: GPL
URL: http://oss.tresys.com/projects/setools
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Source: setools-3.3.tar.gz
AutoReqProv: no
Summary: Policy analysis tools for SELinux
Group: System Environment/Base
Requires: setools-libs = %{version} setools-gui = %{version} setools-console = %{version}

# disable auto dependency generation because they are explicitly listed
%define __find_requires %{nil}

%define libqpol_ver 1.3
%define libapol_ver 4.1
%define libpoldiff_ver 1.3
%define libseaudit_ver 4.2
%define libsefs_ver 4.0

%description
SETools is a collection of graphical tools, command-line tools, and
libraries designed to facilitate SELinux policy analysis.

This meta-package depends upon the main packages necessary to run
SETools.

%package libs
License: LGPL
Summary: Policy analysis support libraries for SELinux
Group: System Environment/Libraries
Requires: libselinux >= 1.30 libsepol >= 1.12.27 sqlite >= 3.2.0 libxml2
Provides: libqpol = %{libqpol_ver} libapol = %{libapol_ver} libpoldiff = %{libpoldiff_ver} libseaudit = %{libseaudit_ver} libsefs = %{libsefs_ver} 
BuildRequires: flex, bison, pkgconfig
BuildRequires: libselinux-devel >= 1.30 libsepol-devel >= 1.12.27
BuildRequires: sqlite-devel >= 3.2.0 libxml2-devel
BuildRequires: tcl-devel >= 8.4.9
BuildRequires: libxml2-devel
BuildRequires: autoconf >= 2.59 automake

%description libs
SETools is a collection of graphical tools, command-line tools, and
libraries designed to facilitate SELinux policy analysis.

This package includes the following run-time libraries:

  libapol       policy analysis library
  libpoldiff    semantic policy difference library
  libqpol       library that abstracts policy internals
  libseaudit    parse and filter SELinux audit messages in log files
  libsefs       SELinux file contexts library

%package libs-python
License: LGPL
Summary: Python bindings for SELinux policy analysis
Group: Development/Languages
Requires: setools-libs = %{version} python2 >= 2.3
Provides: libqpol-python = %{libqpol_ver} libapol-python = %{libapol_ver}
Provides: libpoldiff-python = %{libpoldiff_ver}
Provides: libseaudit-python = %{libseaudit_ver} libsefs-python = %{libsefs_ver}
BuildRequires: python2-devel >= 2.3 swig >= 1.3.28

%description libs-python
SETools is a collection of graphical tools, command-line tools, and
libraries designed to facilitate SELinux policy analysis.

This package includes Python bindings for the following libraries:

  libapol       policy analysis library
  libpoldiff    semantic policy difference library
  libqpol       library that abstracts policy internals
  libseaudit    parse and filter SELinux audit messages in log files
  libsefs       SELinux file contexts library

%package libs-java
License: LGPL
Summary: Java bindings for SELinux policy analysis
Group: Development/Languages
Requires: setools-libs = %{version} java >= 1.2
Provides: libqpol-java = %{libqpol_ver} libapol-java = %{libapol_ver}
Provides: libpoldiff-java = %{libpoldiff_ver}
Provides: libseaudit-java = %{libseaudit_ver} libsefs-java = %{libsefs_ver}
BuildRequires: java-devel >= 1.2 swig >= 1.3.28

%description libs-java
SETools is a collection of graphical tools, command-line tools, and
libraries designed to facilitate SELinux policy analysis.

This package includes Java bindings for the following libraries:

  libapol       policy analysis library
  libpoldiff    semantic policy difference library
  libqpol       library that abstracts policy internals
  libseaudit    parse and filter SELinux audit messages in log files
  libsefs       SELinux file contexts library

%package libs-tcl
License: LGPL
Summary: Tcl bindings for SELinux policy analysis
Group: Development/Languages
Requires: setools-libs = %{version} tcl >= 8.4.9
Provides: libqpol-tcl = %{libqpol_ver} libapol-tcl = %{libapol_ver}
Provides: libpoldiff-tcl = %{libpoldiff_ver}
Provides: libseaudit-tcl = %{libseaudit_ver} libsefs-tcl = %{libsefs_ver}
BuildRequires: tcl-devel >= 8.4.9 swig >= 1.3.28

%description libs-tcl
SETools is a collection of graphical tools, command-line tools, and
libraries designed to facilitate SELinux policy analysis.

This package includes Tcl bindings for the following libraries:

  libapol       policy analysis library
  libpoldiff    semantic policy difference library
  libqpol       library that abstracts policy internals
  libseaudit    parse and filter SELinux audit messages in log files
  libsefs       SELinux file contexts library

%package devel
License: LGPL
Summary: Policy analysis development files for SELinux
Group: Development/Libraries
Requires: libselinux-devel >= 1.30 libsepol-devel >= 1.12.27   setools-libs = %{version}
BuildRequires: sqlite-devel >= 3.2.0 libxml2-devel

%description devel
SETools is a collection of graphical tools, command-line tools, and
libraries designed to facilitate SELinux policy analysis.

This package includes header files and archives for the following
libraries:

  libapol       policy analysis library
  libpoldiff    semantic policy difference library
  libqpol       library that abstracts policy internals
  libseaudit    parse and filter SELinux audit messages in log files
  libsefs       SELinux file contexts library

%package console
AutoReqProv: no
Summary: Policy analysis command-line tools for SELinux
Group: System Environment/Base
Requires: libqpol >= 1.1 libapol >= 4.0 libpoldiff >= 1.3 libsefs >= 3.1 libseaudit >= 4.0 libsefs >= 4.0
Requires: libselinux >= 1.30

%description console
SETools is a collection of graphical tools, command-line tools, and
libraries designed to facilitate SELinux policy analysis.

This package includes the following console tools:

  seaudit-report  audit log analysis tool
  sechecker       SELinux policy checking tool
  secmds          command line tools: seinfo, sesearch, findcon,
                  replcon, indexcon, and searchcon
  sediff          semantic policy difference tool

%package gui
AutoReqProv: no
Summary: Policy analysis graphical tools for SELinux
Group: System Environment/Base
Requires: libqpol >= 1.2 libapol >= 4.1 libpoldiff >= 1.3 libseaudit >= 4.1
Requires: tcl >= 8.4.9 tk >= 8.4.9 bwidget >= 1.8
Requires: setools-libs-tcl >= 3.3
Requires: glib2 gtk2 >= 2.8 libxml2 libglade2
BuildRequires: gtk2-devel >= 2.8 libglade2-devel libxml2-devel

%description gui
SETools is a collection of graphical tools, command-line tools, and
libraries designed to facilitate SELinux policy analysis.

This package includes the following graphical tools:

  apol          Tcl/Tk-based policy analysis tool
  seaudit       audit log analysis tool
  sediffx       semantic policy difference tool

%define setoolsdir %{_datadir}/setools-%{version}
%define pkgpyexecdir %{_libdir}/python?.?/site-packages/setools
%define pkgpythondir %{_exec_prefix}/lib*/python?.?/site-packages/setools
%define javalibdir %{_libdir}/setools
%define tcllibdir %{_libdir}/setools

%prep
%setup -q

%build
%configure --disable-bwidget-check --disable-selinux-check --enable-swig-python --enable-swig-java --enable-swig-tcl
make %{?_smp_mflags}

%install
rm -rf ${RPM_BUILD_ROOT}
make DESTDIR=${RPM_BUILD_ROOT} install
mkdir -p ${RPM_BUILD_ROOT}/usr/share/applications
mkdir -p ${RPM_BUILD_ROOT}/usr/share/pixmaps
install -d -m 755 ${RPM_BUILD_ROOT}%{_sysconfdir}/pam.d
install -m 644 packages/rpm/seaudit.pam ${RPM_BUILD_ROOT}%{_sysconfdir}/pam.d/seaudit
install -d -m 755 ${RPM_BUILD_ROOT}%{_sysconfdir}/security/console.apps
install -m 644 packages/rpm/seaudit.console ${RPM_BUILD_ROOT}%{_sysconfdir}/security/console.apps/seaudit
install -d -m 755 ${RPM_BUILD_ROOT}%{_datadir}/applications
install -m 664 packages/rpm/apol.desktop ${RPM_BUILD_ROOT}/usr/share/applications/apol.desktop
install -m 664 packages/rpm/seaudit.desktop ${RPM_BUILD_ROOT}/usr/share/applications/seaudit.desktop
install -m 664 packages/rpm/sediffx.desktop ${RPM_BUILD_ROOT}/usr/share/applications/sediffx.desktop
install -m 664 apol/apol.png ${RPM_BUILD_ROOT}/usr/share/pixmaps/apol.png
install -m 664 seaudit/seaudit.png ${RPM_BUILD_ROOT}/usr/share/pixmaps/seaudit.png
install -m 664 sediff/sediffx.png ${RPM_BUILD_ROOT}/usr/share/pixmaps/sediffx.png
cd $RPM_BUILD_ROOT/%{_bindir}/
ln -sf /usr/bin/consolehelper seaudit

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%doc AUTHORS ChangeLog COPYING COPYING.GPL COPYING.LGPL KNOWN-BUGS NEWS README

%files libs
%defattr(755,root,root)
%{_libdir}/libqpol.so.%{libqpol_ver}
%{_libdir}/libqpol.so.1
%{_libdir}/libqpol.so
%{_libdir}/libapol.so.%{libapol_ver}
%{_libdir}/libapol.so.4
%{_libdir}/libapol.so
%{_libdir}/libpoldiff.so.%{libpoldiff_ver}
%{_libdir}/libpoldiff.so.1
%{_libdir}/libpoldiff.so
%{_libdir}/libsefs.so.%{libsefs_ver}
%{_libdir}/libsefs.so.4
%{_libdir}/libsefs.so
%{_libdir}/libseaudit.so.%{libseaudit_ver}
%{_libdir}/libseaudit.so.4
%{_libdir}/libseaudit.so
%defattr(-, root, root)
%{setoolsdir}/seaudit-report.conf
%{setoolsdir}/seaudit-report.css

%files libs-python
%defattr(-,root,root)
%{pkgpythondir}/__init__.py
%{pkgpythondir}/__init__.pyc
%{pkgpythondir}/__init__.pyo
%{pkgpythondir}/qpol.py
%{pkgpythondir}/qpol.pyc
%{pkgpythondir}/qpol.pyo
%{pkgpyexecdir}/_qpol.so.%{libqpol_ver}
%{pkgpyexecdir}/_qpol.so.1
%attr(755,root,root) %{pkgpyexecdir}/_qpol.so
%{pkgpythondir}/apol.py
%{pkgpythondir}/apol.pyc
%{pkgpythondir}/apol.pyo
%{pkgpyexecdir}/_apol.so.%{libapol_ver}
%{pkgpyexecdir}/_apol.so.4
%attr(755,root,root) %{pkgpyexecdir}/_apol.so
%{pkgpythondir}/poldiff.py
%{pkgpythondir}/poldiff.pyc
%{pkgpythondir}/poldiff.pyo
%{pkgpyexecdir}/_poldiff.so.%{libpoldiff_ver}
%{pkgpyexecdir}/_poldiff.so.1
%attr(755,root,root) %{pkgpyexecdir}/_poldiff.so
%{pkgpythondir}/seaudit.py
%{pkgpythondir}/seaudit.pyc
%{pkgpythondir}/seaudit.pyo
%{pkgpyexecdir}/_seaudit.so.%{libseaudit_ver}
%{pkgpyexecdir}/_seaudit.so.4
%attr(755,root,root) %{pkgpyexecdir}/_seaudit.so
%{pkgpythondir}/sefs.py
%{pkgpythondir}/sefs.pyc
%{pkgpythondir}/sefs.pyo
%{pkgpyexecdir}/_sefs.so.%{libsefs_ver}
%{pkgpyexecdir}/_sefs.so.4
%attr(755,root,root) %{pkgpyexecdir}/_sefs.so

%files libs-java
%defattr(-,root,root)
%{_libdir}/libjqpol.so.%{libqpol_ver}
%{_libdir}/libjqpol.so.1
%{_libdir}/libjqpol.so
%{_libdir}/libjapol.so.%{libapol_ver}
%{_libdir}/libjapol.so.4
%{_libdir}/libjapol.so
%{_libdir}/libjpoldiff.so.%{libpoldiff_ver}
%{_libdir}/libjpoldiff.so.1
%{_libdir}/libjpoldiff.so
%{_libdir}/libjseaudit.so.%{libseaudit_ver}
%{_libdir}/libjseaudit.so.4
%{_libdir}/libjseaudit.so
%{_libdir}/libjsefs.so.%{libsefs_ver}
%{_libdir}/libjsefs.so.4
%{_libdir}/libjsefs.so
%{javalibdir}/qpol.jar
%{javalibdir}/apol.jar
%{javalibdir}/poldiff.jar
%{javalibdir}/seaudit.jar
%{javalibdir}/sefs.jar

%files libs-tcl
%defattr(-,root,root)
%{tcllibdir}/qpol/libtqpol.so.%{libqpol_ver}
%{tcllibdir}/qpol/pkgIndex.tcl
%{tcllibdir}/apol/libtapol.so.%{libapol_ver}
%{tcllibdir}/apol/pkgIndex.tcl
%{tcllibdir}/poldiff/libtpoldiff.so.%{libpoldiff_ver}
%{tcllibdir}/poldiff/pkgIndex.tcl
%{tcllibdir}/seaudit/libtseaudit.so.%{libseaudit_ver}
%{tcllibdir}/seaudit/pkgIndex.tcl
%{tcllibdir}/sefs/libtsefs.so.%{libsefs_ver}
%{tcllibdir}/sefs/pkgIndex.tcl

%files devel
%defattr(-,root,root)
%{_libdir}/libqpol.a
%{_libdir}/libapol.a
%{_libdir}/libpoldiff.a
%{_libdir}/libseaudit.a
%{_libdir}/libsefs.a
%{_libdir}/pkgconfig/libqpol.pc
%{_libdir}/pkgconfig/libapol.pc
%{_libdir}/pkgconfig/libpoldiff.pc
%{_libdir}/pkgconfig/libseaudit.pc
%{_libdir}/pkgconfig/libsefs.pc
%{_includedir}/qpol/avrule_query.h
%{_includedir}/qpol/bool_query.h
%{_includedir}/qpol/class_perm_query.h
%{_includedir}/qpol/cond_query.h
%{_includedir}/qpol/constraint_query.h
%{_includedir}/qpol/context_query.h
%{_includedir}/qpol/fs_use_query.h
%{_includedir}/qpol/genfscon_query.h
%{_includedir}/qpol/isid_query.h
%{_includedir}/qpol/iterator.h
%{_includedir}/qpol/mls_query.h
%{_includedir}/qpol/mlsrule_query.h
%{_includedir}/qpol/module.h
%{_includedir}/qpol/netifcon_query.h
%{_includedir}/qpol/nodecon_query.h
%{_includedir}/qpol/policy.h
%{_includedir}/qpol/policy_extend.h
%{_includedir}/qpol/portcon_query.h
%{_includedir}/qpol/rbacrule_query.h
%{_includedir}/qpol/role_query.h
%{_includedir}/qpol/syn_rule_query.h
%{_includedir}/qpol/terule_query.h
%{_includedir}/qpol/type_query.h
%{_includedir}/qpol/user_query.h
%{_includedir}/qpol/util.h
%{_includedir}/apol/avrule-query.h
%{_includedir}/apol/bool-query.h
%{_includedir}/apol/bst.h
%{_includedir}/apol/class-perm-query.h
%{_includedir}/apol/condrule-query.h
%{_includedir}/apol/constraint-query.h
%{_includedir}/apol/context-query.h
%{_includedir}/apol/domain-trans-analysis.h
%{_includedir}/apol/fscon-query.h
%{_includedir}/apol/infoflow-analysis.h
%{_includedir}/apol/isid-query.h
%{_includedir}/apol/mls_level.h
%{_includedir}/apol/mls-query.h
%{_includedir}/apol/mls_range.h
%{_includedir}/apol/netcon-query.h
%{_includedir}/apol/perm-map.h
%{_includedir}/apol/policy.h
%{_includedir}/apol/policy-path.h
%{_includedir}/apol/policy-query.h
%{_includedir}/apol/range_trans-query.h
%{_includedir}/apol/rbacrule-query.h
%{_includedir}/apol/relabel-analysis.h
%{_includedir}/apol/render.h
%{_includedir}/apol/role-query.h
%{_includedir}/apol/terule-query.h
%{_includedir}/apol/type-query.h
%{_includedir}/apol/types-relation-analysis.h
%{_includedir}/apol/user-query.h
%{_includedir}/apol/util.h
%{_includedir}/apol/vector.h
%{_includedir}/poldiff/poldiff.h
%{_includedir}/poldiff/attrib_diff.h
%{_includedir}/poldiff/avrule_diff.h
%{_includedir}/poldiff/bool_diff.h
%{_includedir}/poldiff/cat_diff.h
%{_includedir}/poldiff/class_diff.h
%{_includedir}/poldiff/level_diff.h
%{_includedir}/poldiff/range_diff.h
%{_includedir}/poldiff/range_trans_diff.h
%{_includedir}/poldiff/rbac_diff.h
%{_includedir}/poldiff/role_diff.h
%{_includedir}/poldiff/terule_diff.h
%{_includedir}/poldiff/user_diff.h
%{_includedir}/poldiff/type_diff.h
%{_includedir}/poldiff/type_map.h
%{_includedir}/poldiff/util.h
%{_includedir}/seaudit/avc_message.h
%{_includedir}/seaudit/bool_message.h
%{_includedir}/seaudit/filter.h
%{_includedir}/seaudit/load_message.h
%{_includedir}/seaudit/log.h
%{_includedir}/seaudit/message.h
%{_includedir}/seaudit/model.h
%{_includedir}/seaudit/parse.h
%{_includedir}/seaudit/report.h
%{_includedir}/seaudit/sort.h
%{_includedir}/seaudit/util.h
%{_includedir}/sefs/db.hh
%{_includedir}/sefs/entry.hh
%{_includedir}/sefs/fcfile.hh
%{_includedir}/sefs/fclist.hh
%{_includedir}/sefs/filesystem.hh
%{_includedir}/sefs/query.hh
%{_includedir}/sefs/util.h

%files console
%defattr(-,root,root)
%{_bindir}/seinfo
%{_bindir}/sesearch
%{_bindir}/indexcon
%{_bindir}/findcon
%{_bindir}/replcon
%{_bindir}/sechecker
%{_bindir}/sediff
%{_bindir}/seaudit-report
%{setoolsdir}/sechecker-profiles/all-checks.sechecker
%{setoolsdir}/sechecker-profiles/analysis-checks.sechecker
%{setoolsdir}/sechecker-profiles/devel-checks.sechecker
%{setoolsdir}/sechecker-profiles/sechecker.dtd
%{setoolsdir}/sechecker_help.txt
%{setoolsdir}/seaudit-report-service
%{_mandir}/man1/findcon.1.gz
%{_mandir}/man1/indexcon.1.gz
%{_mandir}/man1/replcon.1.gz
%{_mandir}/man1/sechecker.1.gz
%{_mandir}/man1/sediff.1.gz
%{_mandir}/man1/seinfo.1.gz
%{_mandir}/man1/sesearch.1.gz
%{_mandir}/man8/seaudit-report.8.gz

%files gui
%defattr(-,root,root)
%{_bindir}/seaudit
%{_bindir}/sediffx
%{_bindir}/apol
%{tcllibdir}/apol_tcl/libapol_tcl.so.%{libapol_ver}
%{tcllibdir}/apol_tcl/pkgIndex.tcl
%{setoolsdir}/sediff_help.txt
%{setoolsdir}/sediffx.glade
%{setoolsdir}/sediffx.png
%{setoolsdir}/sediffx-small.png
%{setoolsdir}/apol_help.txt
%{setoolsdir}/domaintrans_help.txt
%{setoolsdir}/file_relabel_help.txt
%{setoolsdir}/infoflow_help.txt
%{setoolsdir}/types_relation_help.txt
%{setoolsdir}/apol_perm_mapping_ver12
%{setoolsdir}/apol_perm_mapping_ver15
%{setoolsdir}/apol_perm_mapping_ver16
%{setoolsdir}/apol_perm_mapping_ver17
%{setoolsdir}/apol_perm_mapping_ver18
%{setoolsdir}/apol_perm_mapping_ver19
%{setoolsdir}/apol_perm_mapping_ver20
%{setoolsdir}/apol_perm_mapping_ver21
%{setoolsdir}/apol.gif
%{setoolsdir}/seaudit.glade
%{setoolsdir}/seaudit_help.txt
%{setoolsdir}/seaudit.png
%{setoolsdir}/seaudit-small.png
%{setoolsdir}/dot_seaudit
%{_mandir}/man1/apol.1.gz
%{_mandir}/man1/sediffx.1.gz
%{_mandir}/man8/seaudit.8.gz
%{_sbindir}/seaudit

%config(noreplace) %{_sysconfdir}/pam.d/seaudit
%config(noreplace) %{_sysconfdir}/security/console.apps/seaudit
%attr(0644,root,root) /usr/share/applications/apol.desktop
%attr(0644,root,root) /usr/share/applications/seaudit.desktop
%attr(0644,root,root) /usr/share/applications/sediffx.desktop
%attr(0644,root,root) /usr/share/pixmaps/apol.png
%attr(0644,root,root) /usr/share/pixmaps/seaudit.png
%attr(0644,root,root) /usr/share/pixmaps/sediffx.png

%post libs
/sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Wed Apr 25 2007 Jason Tang <jtang@tresys.com> 3.2-0
- update to SETools 3.2 release

* Mon Feb 02 2007 Jason Tang <jtang@tresys.com> 3.1-1
- update to SETools 3.1 release

* Mon Oct 30 2006 Dan Walsh <dwalsh@redhat.com> 3.0-2.fc6
- bump for fc6
 
* Thu Oct 26 2006 Dan Walsh <dwalsh@redhat.com> 3.0-2
- Build on rawhide

* Sun Oct 15 2006 Dan Walsh <dwalsh@redhat.com> 3.0-1
- Update to upstream

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - sh: line 0: fg: no job control
- rebuild

* Tue May 23 2006 Dan Walsh <dwalsh@redhat.com> 2.4-2
- Remove sqlite include directory

* Wed May 3 2006 Dan Walsh <dwalsh@redhat.com> 2.4-1
- Update from upstream

* Mon Apr 10 2006 Dan Walsh <dwalsh@redhat.com> 2.3-3
- Fix help
- Add icons

* Tue Mar 21 2006 Dan Walsh <dwalsh@redhat.com> 2.3-2
- Remove console apps for sediff, sediffx and apol

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 2.3-1.2
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 2.3-1.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Tue Jan 31 2006 Dan Walsh <dwalsh@redhat.com> 2.3-1
- Update from upstream
  * apol:
	added new MLS components tab for sensitivities, 
	levels, and categories.
	Changed users tab to support ranges and default 
	levels.
	added range transition tab for searching range
	Transition rules.
	added new tab for network context components.
	added new tab for file system context components.
  * libapol:
	added binpol support for MLS, network contexts, 
	and file system contexts.
  * seinfo:
	added command line options for MLS components.
	added command line options for network contexts
	and file system contexts.
  * sesearch:
	added command line option for searching for rules
	by conditional boolean name.
  * seaudit:
	added new column in the log view for the 'comm' 
	field found in auditd log files.
	added filters for the 'comm' field and 'message'
	field.
  * manpages:
	added manpages for all tools.	



* Fri Dec 16 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt for new gcj

* Wed Dec 14 2005 Dan Walsh <dwalsh@redhat.com> 2.2-4
- Fix dessktop files
- Apply fixes from bkyoung

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Thu Nov 3 2005 Dan Walsh <dwalsh@redhat.com> 2.2-3
- Move more gui files out of base into gui 

* Thu Nov 3 2005 Dan Walsh <dwalsh@redhat.com> 2.2-2
- Move sediff from gui to main package

* Thu Nov 3 2005 Dan Walsh <dwalsh@redhat.com> 2.2-1
- Upgrade to upstream version

* Thu Oct 13 2005 Dan Walsh <dwalsh@redhat.com> 2.1.3-1
- Upgrade to upstream version

* Mon Oct 10 2005 Tomas Mraz <tmraz@redhat.com> 2.1.2-3
- use include instead of pam_stack in pam config

* Thu Sep 1 2005 Dan Walsh <dwalsh@redhat.com> 2.1.2-2
- Fix spec file
 
* Thu Sep 1 2005 Dan Walsh <dwalsh@redhat.com> 2.1.2-1
- Upgrade to upstream version
 
* Thu Aug 18 2005 Florian La Roche <laroche@redhat.com>
- do not package debug files into the -devel package

* Wed Aug 17 2005 Jeremy Katz <katzj@redhat.com> - 2.1.1-3
- rebuild against new cairo

* Wed May 25 2005 Dan Walsh <dwalsh@redhat.com> 2.1.1-0
- Upgrade to upstream version

* Mon May 23 2005 Bill Nottingham <notting@redhat.com> 2.1.0-5
- put libraries in the right place (also puts debuginfo in the right
  package)
- add %%defattr for -devel too

* Thu May 12 2005 Dan Walsh <dwalsh@redhat.com> 2.1.0-4
- Move sepcut to gui apps.

* Fri May 6 2005 Dan Walsh <dwalsh@redhat.com> 2.1.0-3
- Fix Missing return code.

* Wed Apr 20 2005 Dan Walsh <dwalsh@redhat.com> 2.1.0-2
- Fix requires line

* Tue Apr 19 2005 Dan Walsh <dwalsh@redhat.com> 2.1.0-1
- Update to latest from tresys

* Tue Apr 5 2005 Dan Walsh <dwalsh@redhat.com> 2.0.0-2
- Fix buildrequires lines in spec file

* Tue Mar 2 2005 Dan Walsh <dwalsh@redhat.com> 2.0.0-1
- Update to latest from tresys

* Mon Nov 29 2004 Dan Walsh <dwalsh@redhat.com> 1.5.1-6
- add FALLBACK=true to /etc/security/console.apps/apol

* Wed Nov 10 2004 Dan Walsh <dwalsh@redhat.com> 1.5.1-3
- Add badtcl patch from Tresys.

* Mon Nov 8 2004 Dan Walsh <dwalsh@redhat.com> 1.5.1-2
- Apply malloc problem patch provided by  Sami Farin 

* Mon Nov 1 2004 Dan Walsh <dwalsh@redhat.com> 1.5.1-1
- Update to latest from Upstream

* Wed Oct 6 2004 Dan Walsh <dwalsh@redhat.com> 1.4.1-5
- Update tresys patch

* Mon Oct 4 2004 Dan Walsh <dwalsh@redhat.com> 1.4.1-4
- Fix directory ownership

* Thu Jul 8 2004 Dan Walsh <dwalsh@redhat.com> 1.4.1-1
- Latest from Tresys

* Wed Jun 23 2004 Dan Walsh <dwalsh@redhat.com> 1.4-5
- Add build requires libselinux

* Tue Jun 22 2004 Dan Walsh <dwalsh@redhat.com> 1.4-4
- Add support for policy.18

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Thu Jun 10 2004 Dan Walsh <dwalsh@redhat.com> 1.4-2
- Fix install locations of policy_src_dir

* Wed Jun 2 2004 Dan Walsh <dwalsh@redhat.com> 1.4-1
- Update to latest from TRESYS.

* Tue Jun 1 2004 Dan Walsh <dwalsh@redhat.com> 1.3-3
- Make changes to work with targeted/strict policy
* Fri Apr 16 2004 Dan Walsh <dwalsh@redhat.com> 1.3-2
- Take out requirement for policy file

* Fri Apr 16 2004 Dan Walsh <dwalsh@redhat.com> 1.3-1
- Fix doc location

* Fri Apr 16 2004 Dan Walsh <dwalsh@redhat.com> 1.3-1
- Latest from TRESYS

* Tue Apr 13 2004 Dan Walsh <dwalsh@redhat.com> 1.2.1-8
- fix location of policy.conf file

* Tue Apr 6 2004 Dan Walsh <dwalsh@redhat.com> 1.2.1-7
- Obsolete setools-devel
* Tue Apr 6 2004 Dan Walsh <dwalsh@redhat.com> 1.2.1-6
- Fix location of 
* Tue Apr 6 2004 Dan Walsh <dwalsh@redhat.com> 1.2.1-5
- Remove devel libraries
- Fix installdir for lib64

* Sat Apr 3 2004 Dan Walsh <dwalsh@redhat.com> 1.2.1-4
- Add usr_t file read to policy

* Thu Mar 25 2004 Dan Walsh <dwalsh@redhat.com> 1.2.1-3
- Use tcl8.4

* Tue Mar 02 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Fri Feb 6 2004 Dan Walsh <dwalsh@redhat.com> 1.2.1-1
- New patch

* Fri Feb 6 2004 Dan Walsh <dwalsh@redhat.com> 1.2-1
- Latest upstream version

* Tue Dec 30 2003 Dan Walsh <dwalsh@redhat.com> 1.1.1-1
- New version from upstream
- Remove seuser.te.  Now in policy file.

* Tue Dec 30 2003 Dan Walsh <dwalsh@redhat.com> 1.1-2
- Add Defattr to devel
- move libs to base kit

* Fri Dec 19 2003 Dan Walsh <dwalsh@redhat.com> 1.1-1
- Update to latest code from tresys
- Break into three separate packages for cmdline, devel and gui
- Incorporate the tcl patch

* Mon Dec 15 2003 Jens Petersen <petersen@redhat.com> - 1.0.1-3
- apply setools-1.0.1-tcltk.patch to build against tcl/tk 8.4
- buildrequire tk-devel

* Thu Nov 20 2003 Dan Walsh <dwalsh@redhat.com> 1.0.1-2
- Add Bwidgets to this RPM

* Tue Nov 4 2003 Dan Walsh <dwalsh@redhat.com> 1.0.1-1
- Upgrade to 1.0.1

* Wed Oct 15 2003 Dan Walsh <dwalsh@redhat.com> 1.0-6
- Clean up build

* Tue Oct 14 2003 Dan Walsh <dwalsh@redhat.com> 1.0-5
- Update with correct seuser.te

* Wed Oct 1 2003 Dan Walsh <dwalsh@redhat.com> 1.0-4
- Update with final release from Tresys

* Mon Jun 2 2003 Dan Walsh <dwalsh@redhat.com> 1.0-1
- Initial version

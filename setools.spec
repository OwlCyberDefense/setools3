Summary: SELinux tools for managing policy
Name: setools
Version: 1.2
Release: 1
License: GPL
Group: System Environment/Base
Source: http://www.tresys.com/Downloads/selinux-tools/setools-1.2.tgz
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-buildroot
BuildRequires: perl, tcl, policycoreutils
Requires: tcl, tk, checkpolicy, policycoreutils, policy, policy-sources, bwidget
BuildArch: i386

%description
Security-enhanced Linux is a patch of the Linux kernel and a number of
utilities with enhanced security functionality designed to add mandatory access 
controls to Linux.  The Security-enhanced Linux kernel contains new 
architectural components originally developed to improve the security of the Flask 
operating system. These architectural components provide general support for the 
enforcement of many kinds of mandatory access control policies, including those 
based on the concepts of Type Enforcement, Role-based Access Control, and 
Multi-level Security.

The tools and libraries in this release include:

1. apol: The GUI-based policy analysis tool.

2. sepcut: A basic GUI-based policy configuration, browsing, 
editing, and testing tool. This tool is intended to provide a 
complete, single user interface for viewing the source files of a 
policy, configuring policy program modules, editing policy files, and 
making and testing the policy.

3. seuser: A GUI and command line user manager tool for SELinux.  This 
is a tool that actually manages a portion of a running policy (i.e., 
user accounts).  

4. seuser scripts: A set of shell scripts: seuseradd, seusermod, and 
seuserdel.  These scripts combine the functions of the associated s* 
commands with seuser to provide a single interface to manage users in 
SE Linux.

5. awish: A version of the TCL/TK wish interpreter that includes the 
setools libraries.  We use this to test our GUIs (apol and seuser have the 
interpreter compiled within them).  One could conceivably write one's own 
GUI tools using TCL/TK as extended via awish.

6. libapol: The main policy.conf analysis library, which is the core 
library for all our tools.

7. libseuser: The primary logic used for seuser.

8. libseaudit: The library for parsing and storing SE Linux audit messages.

9. seaudit: A GUI-based audit log analysis tool for Security Enhanced
Linux.  This tool allows you to sort and filter the audit log as
well as query the policy based on audit messages.

10. secmds: Includes two command line tools.  Seinfo is a command line
tool for looking at a SE Linux policy, and getting various component 
elements and statistics.  Sesearch is a command line tool to search the 
TE rules.

The apol, sepcut, seaudit, seinfo, sesearch, and seuser programs, and
the seuser* shell scripts, are the main tools intended for use. The
other tool (awish) and the two libraries can serve as building blocks
for the development of additional tools. All of these tools and
libraries are early generation, with little maturity, and should be
used with care.

See the help files for apol, sepcut, seaudit, and seuser for help on
using the tools.

%prep
%setup -q

%build
make all 

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p $RPM_BUILD_ROOT/%_bindir
make DESTDIR="${RPM_BUILD_ROOT}" install

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%_bindir/*
%_libdir/apol/*
/etc/security/selinux/src/policy/domains/program/seuser.te
/etc/security/selinux/src/policy/file_contexts/program/seuser.fc

%post
cd /etc/security/selinux/src/policy
make install
make reload
chcon system_u:object_r:policy_src_t /etc/security/selinux/src/policy/domains/program/seuser.te
chcon system_u:object_r:policy_src_t /etc/security/selinux/src/policy/file_contexts/program/seuser.fc
chcon system_u:object_r:seuser_exec_t /usr/bin/seuser
chcon system_u:object_r:seuser_conf_t /usr/lib/apol/seuser.conf

%postun
cd /etc/security/selinux/src/policy
make install
make reload

%changelog
* Mon Jun 2 2003 Dan Walsh <dwalsh@redhat.com> 1.0-1
- Initial version









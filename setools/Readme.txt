
SELinux Tools (setools). Version 0.6
by Tresys Technology, LLC
(selinux@tresys.com, www.tresys.com/selinux)

December 18, 2002


OVERVIEW

This readme file describes the SELinux tools (setools) developed by 
Tresys. See the change log for details on the changes in this version. 
This release includes the first version of a basic policy 
configuration/editing tool, sepct.

The tools and libraries in this release include:

1. apol: The GUI-based policy analysis tool, and the main tool in the 
package. 

2. sepcut (new): A basic GUI-based policy configuration, browsing, 
editing, and testing tool. This tool is intended to provide a 
complete, single user interface for viewing the source files of a 
policy, configuring policy program modules, editing policy files, and 
making and testing the policy.

3. seuser: A GUI or command line user manager tool for SELinux.  This 
is a tool that actually manages a portion of a running policy (i.e., 
user accounts).

4. awish: A version of the TCL/TK wish interpreter that includes the 
setools libraries.  We use this to test our GUIs (apol and seuser have the 
interpreter compiled within them).  One could conceivably write one's own 
GUI tools using TCL/TK as extended via awish.

5. libapol: The main policy.conf analysis library, which is the core 
library for all our tools.

6. libseuser: The primary logic used for seuser.

The apol, sepcut, and seuser programs are the main tools intended for 
use. The other tool (awish) and the two libraries can serve as 
building blocks for the development of additional tools. All of these 
tools and libraries are early generation, with little maturity, and 
should be used with care.  

See the help files for apol, sepcut, and seuser for help on using the 
tools.

These are *not* production tools and there will be bugs.  Report any 
bugs or comments to selinux@tresys.com.  Thank you.


THIS RELEASE

See the change log for a summary of the changes. The primary change in 
this release is the addition of the sepcut tool.


BUILDING AND INSTALLING

We have built and used this package on Linux (Redhat 7.x) using the 
several versions of SE Linux.  The tar file will create a ./setools 
directory with the following subdirectories:

apol		The policy analysis tool
awish		Our customize version of the TK wish interpreter
libapol 	The main policy (policy.conf) analysis library
libseuser	The seuser support library
sepcut		The policy configuration/editing tool
seuser		The user management tool
	
Before building you will need to ensure that you have TCL/TK 8.3 or 
higher installed with BWidgets.  Generally, Redhat 7.x has appropriate 
versions of TCL and TK.  If not, one place to find binaries is the 
ActiveState ActiveTcl package, 
(http://aspn.activestate.com/ASPN/Downloads/ActiveTcl). 

Usually the BWidgets package IS NOT installed.  The most current 
version can be found at http://sourceforge.net/projects/tcllib.

NOTE: Most reported problems have to do with not having BWidgets 
installed on the system.  Many distributions of TCL/TK do not include 
BWidgets by default.  To confirm you have BWidgets installed, look in 
your TCL lib directory.  For example, if you have TCL installed in the 
/usr/lib directory, then you should see a directory something like the 
following:

	/usr/lib/tcl8.3/BWidget-1.4.1
	
If you don't, then download BWidgets and install it there.  The 
current version of Bwidgets can be found at 
http://sourceforge.net/projects/tcllib.

Given that you have TCL/TK with BWidgets installed, below are the 
build instructions.  You have the option of installing either apol, 
sepcut, seuser, or all.  apol can run on any Linux box (doesn't require 
SELinux).  It is just an analysis tool and many might just want to use 
it on their regular Linux box (we do).  Likewise sepcut can run on any 
system with TCL/TK and BWidgets; it's a straight TCL/TK application 
without any special C library required.

seuser on the other hand, is an example operational policy management 
tool; it expects and requires an SELinux system.


NOTE: If you're using MLS aspects of a policy, apol and the other 
tools are specifically not currently designed to address those 
aspedcts. However, you may have success using apol with MLS-enabled 
policies if you compile with the -DCONFIG_SECURITY_SELINUX_MLS flag in 
the Makefile. We have conducted very little testing with MLS enabled. 
Even with this flag set during compile time, apol still ignores all 
the MLS aspects of a policy, but should be able to parse such policies

0. Review the ./setools/Makefile, and ensure that the TCL_INCLUDE and 
TCL_LIBINC variables are set appropriately for your installation of 
TCL/TK.
   
1. If you are installing seuser and have a version of SE Linux based
on an LSM kernel earlier than 2.4.19 (prior to August 2002 or so): 

	a. check that you have the policy management changes to your 
	installed policy. Starting with the 2.4.19 LSM kernel based SE 
	Linux, you do NOT need to install the policy patch; skip ahead 
	to step 2.

	The change to the policy necessary for pre-2.4.19 LSM kernels 
	are based on a patch we posted for the SELinux main 
	distribution.  See ./setools/policy/polpatch/readme.txt for 
	further instructions on determining whether you need the patch 
	and if so how to apply it.

	b. After you have applied the patch for the policy, make sure 
	the policy sources are installed. The patched 	policy make 
	file (./selinux/policy/Makefile) should have an 
	"install-src" target that will do this for you.

2. Build and install tools:  If you want to install all tools, just 
type "make install" to build and install everything.  Type "make" to 
see options to build individual pieces, for example to install just 
seuser, sepcut, or apol.

NOTE: If you installed seuser ("make install" or "make install-
seuser"), then the makefile also attempted to install the seuser 
policy.  If this failed, you either are not using an SELinux machine, 
the policy management patch isn't installed (see step 1), or there's a 
version problem with SELinux. Email us; we'll try to help 
(selinux@tresys.com)!

Most errors result from improperly installed TCL/TK, BWidgets, or the 
above lib/apol files.  
   
Send comments/questions to selinux@tresys.com.


WARNING: SEUSER TOOL AND POLICY UPDATE

seuser is one of the few (only?) operational policy management tools 
for SE Linux.  In this release, seuser now has a command line for use 
in scripting. The GUI remains available too (by running seuser -g).

Seuser is also the only tool in the package that will CHANGE things on 
your running system policy, so be careful in its use.  In particular, 
the seuser tool may change the following files:

	/etc/security/default_contexts
	/etc/security/cron_contexts
	the binary installed policy
	the users and other files and policy.conf source files in your 
		policy make directory

seuser now has a policy for itself (apol doesn't require one as it can 
run in the caller's domain).  As such, the make file will install 
policy updates and label certain files.  For this to work, you will 
need the policy management patch we developed separately (and included 
in this tar file).  Starting with the 2.4.19 LSM kernel based version
of SE Linux, these policy changes are already included and you need not
install this patch.  The install instructions below will tell you more.

The ./setools/seuser/seuser.conf file tells seuser where to find all the 
required policy files.  You should not need to change this file; the 
policy management patch will install the necessary files. seuser does NOT 
change /etc/passwd or otherwise help install a system user account.  It 
just allows you to correctly add system users to the SELinux policy.



BUGS AND ISSUES

There are undoubtedly many; see the change log for ones we know of. 
Please report any you may find.  We have many ideas for new features 
and tools, but we're currently building this package incrementally and 
slowly.  Adding new features and tools is (unfortunately) not a high 
work priority for us right now (we wish it were!).


COPYING

The intent is to allow free use of this source code under the GNU General 
Public License (see COPYING).  The following files are used directly from 
NSA's SELinux distribution (see http://www.nsa.gov/selinux/src-
disclaim.html): (all in the libapol/ directory queue.h, queue.c, and 
apolicy_scan.l (aka policy_scan.l).

Portions of libapol/apolicy_parse.y were also taken directly from NSA's 
distribution.  All other source code is copyright protected and freely 
distributed under the GNU GPL (see COPYING).  Absolutely no warranty is 
provided or implied (see COPYING).




# SE Tools Main makefile

TOPDIR		= $(shell pwd)

MAKEFILE =  Makefile
MAKE = make

# If debug is zero, an optimized version is created
DEBUG			= 1
# If GPROF is not zero, compile and link with gprof profiling data
USEGPROF		= 0
# Determine whether setools is linked dynamically with
# internal libraries - the dynamic versions of the setools
# libraries are always created and installed, this just determines
# how the setools applications link.
DYNAMIC 		= 0
# This determines: 
# 	1. whether libapol and libseuser use libselinux 
# 	   to find the default policies. NOTE: libselinux must
#	   be version 1.18 or greater.
# 	2. whether libsefs will be built into apol, awish 
#	   and seuserx. 
# Useful to create a version of apol that runs on non-selinux machines. 
# Set this to 0 for non-selinux machines.
USE_LIBSELINUX 		= 0

LIBS		= -lfl -lm
TCLVER		= $(shell env tclsh tcl_vars)
#TCLVER		= 8.3
#TCL_INCLUDE	= -I/usr/include
#TCL_LIBINC	= -L/usr/lib
TCL_LIBS	= -ltk$(TCLVER) -ltcl$(TCLVER) -ldl $(LIBS)
INCLUDE_DIR	= $(DESTDIR)/usr/include

LINKFLAGS	=
CC		?= gcc 
YACC		= bison -y
LEX		= flex -olex.yy.c

SHARED_LIB_INSTALL_DIR = $(DESTDIR)/usr/lib
STATIC_LIB_INSTALL_DIR = $(SHARED_LIB_INSTALL_DIR)
SETOOLS_INCLUDE = $(INCLUDE_DIR)/setools

# File location defaults; used in various places in code
# Change these if you want different defaults
SELINUX_DIR = $(DESTDIR)/selinux
SELINUX_POLICY_DIR = $(DESTDIR)/etc/security/selinux
POLICY_INSTALL_DIR = $(DESTDIR)$(SELINUX_POLICY_DIR)
POLICY_SRC_DIR	= $(DESTDIR)$(SELINUX_POLICY_DIR)/src/policy
POLICY_SRC_FILE = $(POLICY_SRC_DIR)/policy.conf
DEFAULT_LOG_FILE = /var/log/messages

# Compile options
# -DAPOL_PERFORM_TEST	
##		simple performance measure tests (shouldn't normally use)
# -DCONFIG_SECURITY_SELINUX_MLS 
#		compiles library to be compatible with MLS 
##		in the policy (experimental, see Readme)
CC_DEFINES	= -DCONFIG_SECURITY_SELINUX_MLS 

# Install directories
# Binaries go here
BINDIR		= $(DESTDIR)/usr/bin

# The code uses the specified path below. If you change this, DO NOT add 
# a trailing path seperator ("/"). For example, use "/usr/share/setools" 
# instead of "/usr/share/setools/". This probably needs to become more 
# robust in the future.
#
INSTALL_LIBDIR	= $(DESTDIR)/usr/share/setools
#
# END NOTE

# all apps that have a te/fc file need to be listed here
POLICYINSTALLDIRS = seuser

# You should not need to edit anything after this point.
ifeq ($(USE_LIBSELINUX), 1)
LIBSELINUX  = -lselinux
USE_LIBSEFS 		= 1
else
LIBSELINUX = 
USE_LIBSEFS 		= 0
endif

ifeq ($(USE_LIBSELINUX), 1)
CC_DEFINES += -DLIBSELINUX
endif

ifeq ($(USE_LIBSEFS), 1)
CC_DEFINES += -DLIBSEFS
endif

ifeq ($(DEBUG), 0)
CFLAGS		= -Wall -O2 -fPIC $(TCL_INCLUDE) $(CC_DEFINES)
else
CFLAGS		= -Wall -g $(TCL_INCLUDE) $(CC_DEFINES)
#CFLAGS		= -Wall -ansi -pedantic -g $(TCL_INCLUDE) $(CC_DEFINES)
endif

ifneq ($(USEGPROF), 0)
CFLAGS 		+= -pg
LINKFLAGS 	+= -pg
endif

INSTALL_HELPDIR = $(INSTALL_LIBDIR)

# This should be imported from tools/Makefile (deprecated)
SRC_POLICY_DIR = ../../

# exports
export CFLAGS CC YACC LEX LINKFLAGS BINDIR INSTALL_LIBDIR INSTALL_HELPDIR LIBS TCL_LIBINC TCL_LIBS MAKE 
export SELINUX_DIR POLICY_INSTALL_DIR POLICY_SRC_DIR SRC_POLICY_DIR POLICY_SRC_FILE DEFAULT_LOG_FILE
export TOPDIR SHARED_LIB_INSTALL_DIR STATIC_LIB_INSTALL_DIR SETOOLS_INCLUDE DYNAMIC LIBSELINUX USE_LIBSEFS

all:  all-libs apol awish seuser seuserx sepcut seaudit secmds sediff sediffx

all-nogui:  corelibs seuser secmds sediff

corelibs: libapol libseuser libseaudit libsefs

guilibs: libapol-tcl libseuser-tcl

all-libs: corelibs guilibs

help:
	@echo "Make targets for setools: "
	@echo "   install:           		build and install everything (selinux required)"
	@echo "   install-nogui:     		build and install all non-GUI tools (selinux required)"
	@echo ""
	@echo "   install-apol:      		build and install apol (selinux not required)"
	@echo "   install-sepcut:    		build and install sepct (selinux not required)"
	@echo "   install-seuser:    		build and install command line seuser (selinux required)"
	@echo "   install-seuserx:   		build and install seuser and seuserx (selinux required)"
	@echo "   install-secmds:    		build and install command line tools (selinux required for some tools)"
	@echo "   install-seaudit:   		build and install seaudit and seaudit-report (selinux not required)"
	@echo "   install-sediff:   		build and install sediff command-line tool (selinux not required)"
	@echo "   install-sediffx:   		build and install sediff GUI tool (selinux not required)"
	@echo ""
	@echo "   install-dev:       		build and install headers and libraries"
	@echo "   install-docs:      		install setools documentation"
	@echo "   install-policy:    		install SELinux policy and label files"
	@echo "   install-bwidget:   		install BWidgets-1.4.1 package (requires Tcl/Tk)"
	@echo ""
	@echo "   install-logwatch-files:   	install LogWatch config files for seaudit-report (LogWatch required)"
	@echo " "
	@echo "   all:               		build everything, but don't install"
	@echo "   all-nogui:         		only build non-GUI tools and libraries"
	@echo ""
	@echo "   apol:              		build policy analysis tool"
	@echo "   seuser:            		build SE Linux command line user tool"
	@echo "   seuserx:           		build SE Linux GUI user tool"
	@echo "   sepcut             		build policy customization/browsing tool"
	@echo "   secmds:            		build setools command line tools"
	@echo "   seaudit:           		build audit log analysis tools"
	@echo "   sediff:           		build semantic policy diff command line tool"
	@echo "   sediffx:           		build semantic policy diff GUI tool"
	@echo "   awish:             		build TCL/TK wish interpreter with SE Linux tools extensions."
	@echo " 				Useful for de-bugging problems with TCL/TK scripts."
	@echo " "
	@echo "   clean:             		clean up interim files"
	@echo "   bare:              		more extensive clean up"


apol: selinux_tool
	cd apol; $(MAKE) apol; 

awish: selinux_tool
	cd awish; $(MAKE) awish;

seuser: selinux_tool
	cd seuser; $(MAKE) seuser 	

seuserx: selinux_tool
	cd seuser; $(MAKE) seuserx;

sediff: selinux_tool
	cd sediff; $(MAKE) sediff;

sediffx: selinux_tool
	cd sediff; $(MAKE) sediffx

sepcut: selinux_tool
	cd sepct; $(MAKE) sepcut

seaudit: selinux_tool
	cd seaudit; $(MAKE) all	

secmds: selinux_tool
	cd secmds; $(MAKE) all

libapol: selinux_tool
	cd libapol; $(MAKE) libapol libapolso

libapol-tcl: selinux_tool
	cd libapol; $(MAKE) libapol-tcl libapol-tclso; 

libsefs: selinux_tool
ifeq ($(USE_LIBSEFS), 1)
	cd libsefs; $(MAKE) libsefs libsefsso
endif

libseuser: selinux_tool
	cd libseuser; $(MAKE) libseuser libseuserso

libseuser-tcl: selinux_tool
	cd libseuser; $(MAKE) libseuser-tcl libseuser-tclso;

libseaudit: selinux_tool
	cd libseaudit; $(MAKE) libseaudit libseauditso

$(INSTALL_LIBDIR):
	install -m 755 -d $(INSTALL_LIBDIR)

$(BINDIR):
	install -m 755 -d $(BINDIR)

install-apol: $(INSTALL_LIBDIR) $(BINDIR)
	cd apol; $(MAKE) install; 

install-awish: $(INSTALL_LIBDIR) $(BINDIR)
	cd awish; $(MAKE) install; 

# installs both GUI and non-GUI versions
install-seuserx: $(INSTALL_LIBDIR) $(BINDIR)
	cd seuser; $(MAKE) install; 

install-sediffx: $(INSTALL_LIBDIR) $(BINDIR)
	cd sediff; $(MAKE) install; 

# Non-GUI version only
install-seuser: $(INSTALL_LIBDIR) $(BINDIR)
	cd seuser; $(MAKE) install-nogui

install-sepcut: $(INSTALL_LIBDIR) $(BINDIR)
	cd sepct; $(MAKE) install

install-secmds: $(INSTALL_LIBDIR) $(BINDIR)
	cd secmds; $(MAKE) install

install-sediff: $(INSTALL_LIBDIR) $(BINDIR)
	cd sediff; $(MAKE) install

install-sediff-nogui: $(INSTALL_LIBDIR) $(BINDIR)
	cd sediff; $(MAKE) install-nogui

install-seaudit: $(INSTALL_LIBDIR) $(BINDIR)
	 cd seaudit; $(MAKE) install

install-nogui: $(INSTALL_LIBDIR) install-seuser install-secmds install-sediff-nogui

install: all $(BINDIR) $(SHARED_LIB_INSTALL_DIR) install-dev install-apol install-seuserx install-sepcut \
	 install-awish install-secmds install-seaudit install-sediff install-docs

$(SHARED_LIB_INSTALL_DIR):
	install -m 755 -d $(SHARED_LIB_INSTALL_DIR)
# Install the libraries
install-libseuser: $(SHARED_LIB_INSTALL_DIR)
	cd libseuser; $(MAKE) install

install-libapol: $(SHARED_LIB_INSTALL_DIR)
	cd libapol; $(MAKE) install

install-libseaudit: $(SHARED_LIB_INSTALL_DIR)
	cd libseaudit; $(MAKE) install

install-libsefs: $(SHARED_LIB_INSTALL_DIR)
ifeq ($(USE_LIBSEFS), 1)
	cd libsefs; $(MAKE) install
endif

install-dev: install-libseuser install-libapol install-libseaudit install-libsefs

# Install the policy - this is a separate step to better support systems with
# non-standard policies.
install-seuser-policy: $(INSTALL_LIBDIR)
	cd seuser; $(MAKE) install-policy

install-secmds-policy: $(INSTALL_LIBDIR)
	cd secmds; $(MAKE) install-policy

install-libapol-policy:
	cd libapol; $(MAKE) install-policy

install-libseuser-policy:
	cd libseuser; $(MAKE) install-policy

install-libseaudit-policy:
	cd libseaudit; $(MAKE) install-policy

install-libsefs-policy:
ifeq ($(USE_LIBSEFS), 1)
	cd libsefs; $(MAKE) install-policy
endif

install-policy: install-seuser-policy install-secmds-policy \
		install-libapol-policy install-libseuser-policy \
		install-libseaudit-policy install-libsefs-policy

# Install the BWidgets package
install-bwidget:
	cd packages; $(MAKE) install

# Install LogWatch config files to plug-in seaudit-report to LogWatch
install-logwatch-files:
	cd seaudit; $(MAKE) install-logwatch-service

# Re-generate all setools documentation in source tree
docs:
	cd docs-src; $(MAKE) docs

# Remove all generated setools documentation from source tree
remove-docs:
	cd docs-src; $(MAKE) remove-docs

install-docs:
	cd docs-src; $(MAKE) install

# test targets
tests: test-seuser test-apol test-seaudit test-regression

test-apol: selinux_tool
	cd libapol/test; $(MAKE) $@

test-seuser: selinux_tool
	cd libseuser/test; $(MAKE) $@

test-seaudit: selinux_tool
	cd libseaudit/test; $(MAKE) $@

test-clean: 
	cd libapol/test; $(MAKE) clean
	cd libseuser/test; $(MAKE) clean
	cd test; $(MAKE) clean

test-bare:
	cd libapol/test; $(MAKE) bare
	cd libseuser/test; $(MAKE) bare
	cd libseaudit/test; $(MAKE) bare
	cd test; $(MAKE) bare

test-regression: selinux_tool
	cd test; $(MAKE)

clean: test-clean
	cd apol; $(MAKE) clean
	cd awish; $(MAKE) clean
	cd libapol; $(MAKE) clean
	cd sepct; $(MAKE) clean
	cd seuser; $(MAKE) clean
	cd libseuser; $(MAKE) clean
	cd libsefs; $(MAKE) clean
	cd seaudit; $(MAKE) clean
	cd secmds; $(MAKE) clean
	cd libseaudit; $(MAKE) clean
	cd sediff; $(MAKE) clean
	rm -f *~
	rm -f lib/*.a lib/*.so lib/*.so.1

bare: test-bare
	cd apol; $(MAKE) bare
	cd awish; $(MAKE) bare
	cd libapol; $(MAKE) bare
	cd seuser; $(MAKE) bare
	cd sepct; $(MAKE) bare
	cd libseuser; $(MAKE) bare
	cd libsefs; $(MAKE) bare
	cd seaudit; $(MAKE) bare
	cd secmds; $(MAKE) bare
	cd libseaudit; $(MAKE) bare
	cd sediff; $(MAKE) bare
	rm -f *~
	rm -rf ./lib
	cd libseaudit; $(MAKE) bare
	cd packages; $(MAKE) bare


# Leave this empty target here!
selinux_tool:
# empty!

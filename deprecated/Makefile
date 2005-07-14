# SE Tools Main makefile

TOPDIR	 = $(shell pwd)
MAKEFILE = Makefile
MAKE 	 = make
SETOOLS_TREE = ../setools/

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
# 	1. whether libapol uses libselinux 
# 	   to find the default policies. NOTE: libselinux must
#	   be version 1.18 or greater.
# 	2. whether libsefs will be built into apol and awish 
# Useful to create a version of apol that runs on non-selinux machines. 
# Set this to 0 for non-selinux machines.
USE_LIBSELINUX 		= 1

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
##              set PERFORM_TEST above to 1 to use
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
POLICYINSTALLDIRS = 

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

ifeq ($(PERFORM_TEST), 1)
CC_DEFINES += -DAPOL_PERFORM_TEST
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
export SETOOLS_TREE

#all: libapol libapol-tcl libsefs seuser seuserx sepcut
all: seuser seuserx sepcut

all-nogui: seuser

help:
	@echo "   install-sepcut:    		build and install sepct (selinux not required)"
	@echo "   install-seuser:    		build and install command line seuser (selinux required)"
	@echo "   install-seuserx:   		build and install seuser and seuserx (selinux required)"
	@echo "   seuser:            		build SE Linux command line user tool"
	@echo "   seuserx:           		build SE Linux GUI user tool"
	@echo "   sepcut             		build policy customization/browsing tool"

libapol: selinux_tool
	cd $(SETOOLS_TREE)libapol; $(MAKE) libapol

libapol-tcl: selinux_tool
	cd $(SETOOLS_TREE)libapol; $(MAKE) libapol-tcl

libsefs: selinux_tool
	cd $(SETOOLS_TREE)libsefs; $(MAKE) libsefs

sepcut: selinux_tool
	cd sepct; $(MAKE) sepcut

seuser: selinux_tool
	cd seuser; $(MAKE) seuser

seuserx: selinux_tool
	cd seuser; $(MAKE) seuserx;

libseuser: selinux_tool
	cd libseuser; $(MAKE) libseuser libseuserso

libseuser-tcl: selinux_tool
	cd libseuser; $(MAKE) libseuser-tcl libseuser-tclso;

tests: test-seuser

test-seuser: selinux_tool
	cd libseuser/test; $(MAKE) $@

test-clean:
	cd libseuser/test; $(MAKE) clean

test-bare:
	cd libseuser/test; $(MAKE) bare

install-sepcut: $(INSTALL_LIBDIR) $(BINDIR)
	cd sepct; $(MAKE) install

install-libseuser: $(SHARED_LIB_INSTALL_DIR)
	cd libseuser; $(MAKE) install

# Non-GUI version only
install-seuser: $(INSTALL_LIBDIR) $(BINDIR)
	cd seuser; $(MAKE) install-nogui

# installs both GUI and non-GUI versions
install-seuserx: $(INSTALL_LIBDIR) $(BINDIR)
	cd seuser; $(MAKE) install; 

# Install the policy - this is a separate step to better support systems with
# non-standard policies.
install-seuser-policy: $(INSTALL_LIBDIR)
	cd seuser; $(MAKE) install-policy

install-libseuser-policy:
	cd libseuser; $(MAKE) install-policy

install: all install-seuserx install-sepcut 

install-nogui: install-seuser

install-dev: install-libseuser

clean:
	cd sepct; $(MAKE) clean
	cd seuser; $(MAKE) clean
	cd libseuser; $(MAKE) clean
	cd $(SETOOLS_TREE)libapol; $(MAKE) clean
	cd $(SETOOLS_TREE)libsefs; $(MAKE) clean
bare:
	cd seuser; $(MAKE) bare
	cd sepct; $(MAKE) bare
	cd libseuser; $(MAKE) bare
	cd $(SETOOLS_TREE)libapol; $(MAKE) bare
	cd $(SETOOLS_TREE)libsefs; $(MAKE) bare

selinux_tool:

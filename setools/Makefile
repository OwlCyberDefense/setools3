#SETools main Makefile

TOPDIR 			= $(shell pwd)
MAKEFILE 		= Makefile

MAKE 			?= make
CC 			?= gcc
YACC			= bison -y
LEX			= flex -olex.yy.c
LIBS			= -lfl -lm

INCLUDE_DIR		= $(DESTDIR)/usr/include
SHARED_LIB_INSTALL_DIR 	= $(DESTDIR)/usr/lib
STATIC_LIB_INSTALL_DIR 	= $(SHARED_LIB_INSTALL_DIR)
SETOOLS_INCLUDE 	= $(INCLUDE_DIR)/setools
TCLVER			= $(shell env tclsh tcl_vars)
TCL_LIBS		= -ltk$(TCLVER) -ltcl$(TCLVER) -ldl $(LIBS)

# File location defaults; used in various places in code
# Change these if you want different defaults
SELINUX_DIR 		= $(DESTDIR)/selinux
SELINUX_POLICY_DIR 	= $(DESTDIR)/etc/security/selinux
POLICY_INSTALL_DIR 	= $(DESTDIR)$(SELINUX_POLICY_DIR)
POLICY_SRC_DIR		= $(DESTDIR)$(SELINUX_POLICY_DIR)/src/policy
POLICY_SRC_FILE 	= $(POLICY_SRC_DIR)/policy.conf
DEFAULT_LOG_FILE 	= /var/log/messages

# Install directories
# Binaries go here
BINDIR			= $(DESTDIR)/usr/bin
# The code uses the specified path below. If you change this, DO NOT add 
# a trailing path seperator ("/"). For example, use "/usr/share/setools" 
# instead of "/usr/share/setools/". This probably needs to become more 
# robust in the future.
#
INSTALL_LIBDIR		= $(DESTDIR)/usr/share/setools
# all apps that have a te/fc file need to be listed here
POLICYINSTALLDIRS 	= 
# Help files here
INSTALL_HELPDIR = $(INSTALL_LIBDIR)

# Compile options
# If debug is zero, an optimized version is created
DEBUG			= 0
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
# -DAPOL_PERFORM_TEST	
#	simple performance measure tests (shouldn't normally use)
#	set PERFORM_TEST to 1 to use
PERFORM_TEST 		= 0
# -DCONFIG_SECURITY_SELINUX_MLS 
#	compiles library to be compatible with MLS 
#	in the policy (experimental, see Readme)
CC_DEFINES		= -DCONFIG_SECURITY_SELINUX_MLS 

# You should not need to edit anything after this point.
ifeq ($(USE_LIBSELINUX), 1)
LIBSELINUX  		= -lselinux
LDFLAGS			+= $(LIBSELINUX)
USE_LIBSEFS 		= 1
else
LIBSELINUX = 
USE_LIBSEFS 		= 0
endif

ifeq ($(USE_LIBSELINUX), 1)
CC_DEFINES 		+= -DLIBSELINUX
endif

ifeq ($(USE_LIBSEFS), 1)
CC_DEFINES 		+= -DLIBSEFS
endif

ifeq ($(PERFORM_TEST), 1)
CC_DEFINES 		+= -DAPOL_PERFORM_TEST
endif

ifeq ($(DEBUG), 0)
CFLAGS			= -Wall -O2 -fPIC $(CC_DEFINES)
else
CFLAGS			= -Wall -g -fPIC $(CC_DEFINES) -DDEBUG
#CFLAGS			= -Wall -ansi -pedantic -g $(CC_DEFINES)
endif

ifneq ($(USEGPROF), 0)
CFLAGS 			+= -pg
LINKFLAGS 		+= -pg
endif

ifneq ($(DYNAMIC), 0)
LINKFLAGS		+= -ldl
endif

# Exports
export CC YACC LEX LIBS MAKE CFLAGS TOPDIR LINKFLAGS LDFLAGS CC_DEFINES
export DYNAMIC LIBSELINUX USE_LIBSEFS
export INCLUDE_DIR SETOOLS_INCLUDE TCLVER TCL_LIBS
export SHARED_LIB_INSTALL_DIR STATIC_LIB_INSTALL_DIR
export SELINUX_DIR POLICY_INSTALL_DIR POLICY_SRC_DIR DEFAULT_LOG_FILE 
export POLICY_SRC_DIR POLICY_SRC_FILE
export BINDIR INSTALL_LIBDIR INSTALL_HELPDIR POLICYINSTALLDIR 

# Top Level Targets
all: all-libs all-nogui all-gui

all-nogui: corelibs sediff sechecker secmds

all-gui: all-libs apol awish seaudit sediffx

all-libs: corelibs guilibs

corelibs: libapol libseaudit
ifeq ($(USE_LIBSEFS), 1)
corelibs: libsefs
endif

guilibs: libapol-tcl

libapol-tcl apol: CFLAGS += $(TCL_INCLUDE)

#Libraries
libapol:
	$(MAKE) -C libapol libapol libapolso

libapol-tcl: 
	$(MAKE) -C libapol libapol-tcl libapol-tclso

libseaudit:
	$(MAKE) -C libseaudit libseaudit libseauditso

libsefs:
	$(MAKE) -C libsefs libsefs libsefsso

# Tools
apol: libapol libapol-tcl
	$(MAKE) -C apol apol

awish: libapol libapol-tcl
	$(MAKE) -C awish awish

seaudit: libapol libseaudit
	$(MAKE) -C seaudit all 

sediff: libapol
	$(MAKE) -C sediff sediff

sediffx: libapol
	$(MAKE) -C sediff sediffx

secmds: libapol
	$(MAKE) -C secmds all

sechecker: libapol
	$(MAKE) -C sechecker sechecker

# Some tools optionally use libsefs if available
ifeq ($(USE_LIBSEFS), 1)
apol awish sechecker secmds: libsefs
endif

docs:
	$(MAKE) -C docs-src $@

# Install Targets 
install: all install-dirs \
	install-dev install-apol install-awish \
	install-secmds install-seaudit install-sediff \
	install-docs install-sechecker

install-nogui: all-nogui install-dirs install-dev install-secmds \
	install-sediff-nogui install-sechecker

# Install directories
install-dirs: $(BINDIR) $(SHARED_LIB_INSTALL_DIR) $(INSTALL_LIBDIR)

$(BINDIR) $(SHARED_LIB_INSTALL_DIR) $(INSTALL_LIBDIR):
	test -d $@ || install -m 755 -d $@

# Install Libraries
install-dev: install-libapol install-libseaudit
ifeq ($(USE_LIBSEFS), 1)
install-dev: install-libsefs
endif

# Individual Install Targets
install-apol: $(BINDIR) $(INSTALL_LIBDIR) 
	$(MAKE) -C apol install

install-awish: $(BINDIR) 
	$(MAKE) -C awish install

install-secmds: $(BINDIR) $(INSTALL_LIBDIR) 
	$(MAKE) -C secmds install

install-seaudit: $(BINDIR) $(INSTALL_LIBDIR) 
	$(MAKE) -C seaudit install

install-sediff: $(BINDIR) $(INSTALL_LIBDIR) 
	$(MAKE) -C sediff install

install-sediff-nogui: $(BINDIR) $(INSTALL_LIBDIR) 
	$(MAKE) -C sediff install-nogui

install-sediffx: $(BINDIR) $(INSTALL_LIBDIR) 
	$(MAKE) -C sediff install

install-sechecker: $(BINDIR) $(INSTALL_LIBDIR) 
	$(MAKE) -C sechecker install

install-sechecker-profiles: $(BINDIR) $(INSTALL_LIBDIR) 
	$(MAKE) -C sechecker install-profiles

# Install the BWidgets package
install-bwidget:
	$(MAKE) -C packages install

# Install LogWatch config files to plug-in seaudit-report to LogWatch
install-logwatch-files:
	$(MAKE) -C seaudit install-logwatch-service

# Install Documentation
install-docs: docs
	$(MAKE) -C docs-src install

# Install Libraries
install-libapol: $(INSTALL_LIBDIR) $(SHARED_LIB_INSTALL_DIR) 
	$(MAKE) -C libapol install

install-libseaudit: $(INSTALL_LIBDIR) $(SHARED_LIB_INSTALL_DIR) 
	$(MAKE) -C libseaudit install

install-libsefs: $(INSTALL_LIBDIR) $(SHARED_LIB_INSTALL_DIR) 
	$(MAKE) -C libsefs install

# Install Policy 
install-policy: $(POLICYINSTALLDIR) install-secmds-policy \
		install-libapol-policy install-libseaudit-policy
ifeq ($(USE_LIBSEFS), 1)
install-policy: install-libsefs-policy
endif

install-secmds-policy: $(BINDIR)
	$(MAKE) -C secmds install-policy

install-libapol-policy: $(SHARED_LIB_INSTALL_DIR)
	$(MAKE) -C libapol install-policy

install-libseaudit-policy: $(SHARED_LIB_INSTALL_DIR)
	$(MAKE) -C libseaudit install-policy

install-libsefs-policy: $(SHARED_LIB_INSTALL_DIR)
	$(MAKE) -C libsefs install-policy

# Help 
help:
	@echo "Make targets for setools: "
	@echo "   install:           		build and install everything (selinux required)"
	@echo "   install-nogui:     		build and install all non-GUI tools (selinux required)"
	@echo ""
	@echo "   install-apol:      		build and install apol (selinux not required)"
	@echo "   install-secmds:    		build and install command line tools (selinux required for some tools)"
	@echo "   install-seaudit:   		build and install seaudit and seaudit-report (selinux not required)"
	@echo "   install-sediff:   		build and install sediff command-line tool (selinux not required)"
	@echo "   install-sediffx:   		build and install sediff GUI tool (selinux not required)"
	@echo "   install-sechecker:   		build and install sechecker (selinux not required)"
	@echo ""
	@echo "   install-dev:       		build and install headers and libraries"
	@echo "   install-docs:      		install setools documentation"
	@echo "   install-policy:    		install SELinux policy and label files"
	@echo "   install-bwidget:   		install BWidgets-1.4.1 package (requires Tcl/Tk)"
	@echo ""
	@echo "   install-logwatch-files:   install LogWatch config files for seaudit-report (LogWatch required)"
	@echo " "
	@echo "   all:               		build everything, but don't install"
	@echo "   all-nogui:         		only build non-GUI tools and libraries"
	@echo ""
	@echo "   apol:              		build policy analysis tool"
	@echo "   secmds:            		build setools command line tools"
	@echo "   seaudit:           		build audit log analysis tools"
	@echo "   sediff:           		build semantic policy diff command line tool"
	@echo "   sediffx:           		build semantic policy diff GUI tool"
	@echo "   sechecker:                    build policy checking tool"
	@echo "   awish:             		build TCL/TK wish interpreter with SE Linux tools extensions."
	@echo " 				Useful for de-bugging problems with TCL/TK scripts."
	@echo " "
	@echo "   clean:             		clean up interim files"
	@echo "   bare:              		more extensive clean up"


# Other Targets
clean:
	$(MAKE) -C apol $@
	$(MAKE) -C awish $@
	$(MAKE) -C libapol $@
	$(MAKE) -C libseaudit $@
	$(MAKE) -C libsefs $@
	$(MAKE) -C seaudit $@
	$(MAKE) -C secmds $@
	$(MAKE) -C sechecker $@
	$(MAKE) -C sediff $@
	rm -f *~
	rm -f lib/*.a lib/*.so lib/*.so.1

bare:
	$(MAKE) -C apol $@
	$(MAKE) -C awish $@
	$(MAKE) -C libapol $@
	$(MAKE) -C libseaudit $@
	$(MAKE) -C libsefs $@
	$(MAKE) -C seaudit $@
	$(MAKE) -C secmds $@
	$(MAKE) -C sechecker $@
	$(MAKE) -C sediff $@
	$(MAKE) -C packages $@
	rm -f *~
	rm -rf ./lib

remove-docs:
	$(MAKE) -C docs-src $@

.PHONY: clean bare help\
        libapol libapol-tcl libseaudit libsefs


# SE Tools Main makefile

TOPDIR		= $(shell pwd)

MAKEFILE =  Makefile
MAKE = make

LIBS		= -lfl -lm
TCLVER		= $(shell env tclsh tcl_vars version)
TCL_LIBINC	= -L$(shell env tclsh tcl_vars pkgPath)
TCL_INCLUDE	= -I$(shell echo $(shell env tclsh tcl_vars pkgPath) | sed -e "s/lib/include/g")
#TCLVER		= 8.3
#TCL_INCLUDE	= -I/usr/include
#TCL_LIBINC	= -L/usr/lib
TCL_LIBS	= -ltk$(TCLVER) -ltcl$(TCLVER) -ldl $(LIBS)
INCLUDE_DIR	= $(DESTDIR)/usr/include

LINKFLAGS	= 
CC		= gcc 
YACC		= bison -y
LEX		= flex -olex.yy.c

DEBUG		= 1
DYNAMIC		= 0

SHARED_LIB_INSTALL_DIR = /usr/lib
STATIC_LIB_INSTALL_DIR = $(SHARED_LIB_INSTALL_DIR)
SETOOLS_INCLUDE = $(DESTDIR)$(INCLUDE_DIR)/setools

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
# -DLIBSELINUX 
#		compiles libapol and libseuser libraries to use the
#		libselinux helper functions for locating system default 
#		policy resources, instead of the logic from libapol or 
#		the locations defined in the seuser.conf file.
#
#		NOTE: When using this compile option, you will need to   
#		link in the libselinux library for the following 
#		programs: 
#		  seaudit, seinfo, sesearch, seuser, seuserx
##
CC_DEFINES	= -fPIC

ifeq ($(DEBUG), 0)
CFLAGS		= -Wall -O2 $(TCL_INCLUDE) $(CC_DEFINES)
else
CFLAGS		= -Wall -g $(TCL_INCLUDE) $(CC_DEFINES)
#CFLAGS		= -Wall -ansi -pedantic -g $(TCL_INCLUDE) $(CC_DEFINES)
endif


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

INSTALL_HELPDIR = $(INSTALL_LIBDIR)

# This should be imported from tools/Makefile (deprecated)
SRC_POLICY_DIR = ../../

# all apps that have a te/fc file need to be listed here
POLICYINSTALLDIRS = seuser

# exports
export CFLAGS CC YACC LEX LINKFLAGS BINDIR INSTALL_LIBDIR INSTALL_HELPDIR LIBS TCL_LIBINC TCL_LIBS MAKE 
export SELINUX_DIR POLICY_INSTALL_DIR POLICY_SRC_DIR SRC_POLICY_DIR POLICY_SRC_FILE DEFAULT_LOG_FILE
export TOPDIR SHARED_LIB_INSTALL_DIR STATIC_LIB_INSTALL_DIR SETOOLS_INCLUDE DEBUG

all:  all-libs apol awish seuser seuserx sepcut seaudit secmds

all-nogui:  corelibs seuser secmds

corelibs: libapol libseuser libseaudit libsefs

guilibs: libapol-tcl libseuser-tcl

all-libs: corelibs guilibs

help:
	@echo "Make targets for setools: "
	@echo "   install:           build and install everything (selinux required)"
	@echo "   install-nogui:     build and install all non-GUI tools (selinux required)"
	@echo ""
	@echo "   install-apol:      build and install apol (selinux not required)"
	@echo "   install-sepcut:    build and install sepct (selinux not required)"
	@echo "   install-seuser:    build and install command line seuser (selinux required)"
	@echo "   install-seuserx:   build and install seuser and seuserx (selinux required)"
	@echo "   install-secmds:    build and install command line tools (selinux not required)"
	@echo "   install-seaudit:   build and install seaudit and seaudit-report (selinux not required)"
	@echo ""
	@echo "   install-dev:       build and install headers and libraries"
	@echo "   install-docs:      install setools documentation"
	@echo "   install-policy:    install SELinux policy and label files"
	@echo "   install-bwidget:   install BWidgets-1.4.1 package (requires Tcl/Tk)"
	@echo " "
	@echo "   all:               build everything, but don't install"
	@echo "   all-nogui:         only build non-GUI tools and libraries"
	@echo ""
	@echo "   apol:              build policy analysis tool"
	@echo "   seuser:            build SE Linux command line user tool"
	@echo "   seuserx:           build SE Linux GUI user tool"
	@echo "   sepcut             build policy customization/browsing tool"
	@echo "   secmds:            build setools command line tools"
	@echo "   seaudit:           built audit log analysis tools"
	@echo "   awish:             build TCL/TK wish interpreter with SE Linux tools extensions"
	@echo " "
	@echo "   clean:             clean up interim files"
	@echo "   bare:              more extensive clean up"


apol: selinux_tool
	cd apol;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd apol; $(MAKE) apol; \
	else \
		echo "Could not build apol."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi

awish: selinux_tool
	cd awish;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd awish; $(MAKE) awish; \
	else \
		echo "Could not build awish."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi

seuser: selinux_tool
	cd seuser; $(MAKE) seuser 	

seuserx: selinux_tool
	cd seuser;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd seuser; $(MAKE) seuserx; \
	else \
		echo "Could not build seuserx."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi

sepcut: selinux_tool
	cd sepct; $(MAKE) sepcut

seaudit: selinux_tool
	cd seaudit; $(MAKE) all	

secmds: selinux_tool
	cd secmds; $(MAKE) all

libapol: selinux_tool
	cd libapol; $(MAKE) libapol libapolso

libapol-tcl: selinux_tool
	cd libapol;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd libapol; $(MAKE) libapol-tcl libapol-tclso; \
	else \
		echo "Could not build libapol-tcl."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi

libsefs: selinux_tool
	cd libsefs; $(MAKE) libsefs libsefsso

libseuser: selinux_tool
	cd libseuser; $(MAKE) libseuser libseuserso

libseuser-tcl: selinux_tool
	cd libseuser;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd libseuser; $(MAKE) libseuser-tcl libseuser-tclso; \
	else \
		echo "Could not build libseuser-tcl."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi

libseaudit: selinux_tool
	cd libseaudit; $(MAKE) libseaudit libseauditso

$(INSTALL_LIBDIR):
	install -m 755 -d $(INSTALL_LIBDIR)

install-apol: $(INSTALL_LIBDIR)
	cd apol;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd apol; $(MAKE) install; \
	else \
		echo "Could not install apol."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi

install-awish: $(INSTALL_LIBDIR)
	cd awish;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd awish; $(MAKE) install; \
	else \
		echo "Could not install awish."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi	

# installs both GUI and non-GUI versions
install-seuserx: $(INSTALL_LIBDIR)
	cd seuser;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd seuser; $(MAKE) install; \
	else \
		echo "Could not install seuserx."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi	

# Non-GUI version only
install-seuser: $(INSTALL_LIBDIR)
	cd seuser; $(MAKE) install-nogui

install-sepcut: $(INSTALL_LIBDIR)
	cd sepct; $(MAKE) install

install-secmds: $(INSTALL_LIBDIR)
	cd secmds; $(MAKE) install

install-seaudit: $(INSTALL_LIBDIR)
	 cd seaudit; $(MAKE) install

install-nogui: $(INSTALL_LIBDIR) install-seuser install-secmds

install: install-dev install-apol install-seuserx install-sepcut \
	 install-awish install-secmds install-seaudit install-docs \
	 install-policy install-bwidget

# Install the libraries
install-libseuser:
	cd libseuser; $(MAKE) install

install-libapol:
	cd libapol; $(MAKE) install

install-libseaudit:
	cd libseaudit; $(MAKE) install

install-libsefs:
	cd libsefs; $(MAKE) install

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
	cd libsefs; $(MAKE) install-policy

install-policy: install-seuser-policy install-secmds-policy \
		install-libapol-policy install-libseuser-policy \
		install-libseaudit-policy install-libsefs-policy

# Install the BWidgets package
install-bwidget:
	cd packages; $(MAKE) install

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
	cd libseaudit; $(MAKE) bare
	cd packages; $(MAKE) bare


# Leave this empty target here!
selinux_tool:
# empty!

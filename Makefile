# SE Tools Main makefile

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

SHARED_LIB_INSTALL_DIR = $(DESTDIR)/usr/lib
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
CC_DEFINES	= -fPIC

CFLAGS		= -Wall -O2 $(TCL_INCLUDE) $(CC_DEFINES)
#CFLAGS		= -Wall -g $(TCL_INCLUDE) $(CC_DEFINES)
#CFLAGS		= -Wall -ansi -pedantic -g $(TCL_INCLUDE) $(CC_DEFINES)

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
export SHARED_LIB_INSTALL_DIR STATIC_LIB_INSTALL_DIR SETOOLS_INCLUDE

all:  all-libs apol awish seuser seuserx sepcut seaudit secmds

all-nogui:  corelibs seuser secmds

corelibs: libapol libseuser libseaudit

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
	@echo "   install-seaudit:   build and install seaudit (selinux not required)"
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
	@echo "   seaudit:           built audit log analysis tool"
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
	cd seaudit; $(MAKE)	

secmds: selinux_tool
	cd secmds; $(MAKE) all
	
libapol: selinux_tool
	cd libapol; $(MAKE) libapol

libapol-tcl: selinux_tool
	cd libapol;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd libapol; $(MAKE) libapol-tcl; \
	else \
		echo "Could not build libapol-tcl."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi

libseuser: selinux_tool
	cd libseuser; $(MAKE) libseuser

libseuser-tcl: selinux_tool
	cd libseuser;
	@if [ "${shell env tclsh tcl_vars search_tcl_libs}" != "none" ]; then \
		cd libseuser; $(MAKE) libseuser-tcl; \
	else \
		echo "Could not build libseuser-tcl."; \
		echo "Tcl library is not built or not in expected location(s)."; \
	fi

libseaudit: selinux_tool
	cd libseaudit; $(MAKE)

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

install: install-apol install-seuserx install-sepcut install-awish install-secmds install-seaudit

# Install the libraries
install-libseuser:
	cd libseuser; $(MAKE) install

install-libapol:
	cd libapol; $(MAKE) install
	
install-libseaudit:
	cd libseaudit; $(MAKE) install
	
install-dev: install-libseuser install-libapol install-libseaudit
	
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
	
install-policy: install-seuser-policy install-secmds-policy install-libapol-policy install-libseuser-policy install-libseaudit-policy

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
tests: test-seuser test-apol test-regression

test-apol: selinux_tool
	cd libapol/test; $(MAKE) $@

test-seuser: selinux_tool
	cd libseuser/test; $(MAKE) $@

test-clean: 
	cd libapol/test; $(MAKE) clean
	cd libseuser/test; $(MAKE) clean
	cd test; $(MAKE) clean

test-bare:
	cd libapol/test; $(MAKE) bare
	cd libseuser/test; $(MAKE) bare
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
	cd seaudit; $(MAKE) clean
	cd secmds; $(MAKE) clean
	cd libseaudit; $(MAKE) clean
	rm -f *~
	rm -f lib/*.a

bare: test-bare
	cd apol; $(MAKE) bare
	cd awish; $(MAKE) bare
	cd libapol; $(MAKE) bare
	cd seuser; $(MAKE) bare
	cd sepct; $(MAKE) bare
	cd libseuser; $(MAKE) bare
	cd seaudit; $(MAKE) bare
	cd secmds; $(MAKE) bare
	cd libseaudit; $(MAKE) bare
	rm -f *~
	rm -rf ./lib


# Leave this empty target here!
selinux_tool:
# empty!

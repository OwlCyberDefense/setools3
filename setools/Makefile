# SE Tools Main makefile

MAKEFILE =  Makefile
MAKE = make

LIBS		= -lfl -lm 
TCLVER		= 8.3
TCL_INCLUDE	= -I/usr/include
TCL_LIBINC	= -L/usr/lib
TCL_LIBS	= -ltk$(TCLVER) -ltcl$(TCLVER) -ldl $(LIBS)

LINKFLAGS	= 
CC		= gcc 
YACC		= bison -y
LEX		= flex -olex.yy.c


# File location defaults; used in various places in code
# Change these if you want different defaults
POLICY_SRC_DIR	= $(DESTDIR)/etc/security/selinux/src
POLICY_SRC_FILE = $(POLICY_SRC_DIR)/policy.conf
DEFAULT_LOG_FILE = /var/log/messages

# Compile options
# -DCONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY 
##		support the new conditional policy extensions, soon to be released
##		in the new checkpolicy.
# -DAPOL_PERFORM_TEST	
##		simple performance measure tests (shouldn't normally use)
# -DCONFIG_SECURITY_SELINUX_MLS 
##		compiles library to be compatible with MLS 
#		in the policy (experimental, see Readme)
#
CC_DEFINES	= -DCONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY

#CFLAGS		= -Wall -O2 $(TCL_INCLUDE) $(CC_DEFINES)
CFLAGS		= -Wall -g $(TCL_INCLUDE) $(CC_DEFINES)
#CFLAGS		= -Wall -ansi -pedantic -g $(TCL_INCLUDE) $(CC_DEFINES)

# Install directories
# Binaries go here
BINDIR		= $(DESTDIR)/usr/bin


# NOTE: DON'T CHANGE INSTALL_LIBDIR.  The code expects below INSTALL_LIBDIR 
# to point here.  We will eventually fix this so that the code
# uses the path below, rather than having a hard-coded path.  If you really want
# to change this, then change it here, and change the #define for APOL_INSTALL_DIR
# in ./setools/libapol/apol_tcl/util/sepct/top.tcl .  Also make sure to change 
# ./setools/policy/seuser.fc to reflect the change.
#
INSTALL_LIBDIR	= $(DESTDIR)/usr/lib/apol
#
# END NOTE


# This should be imported from tools/Makefile (deprecated)
SRC_POLICY_DIR = ../../

# all apps that have a te/fc file need to be listed here
POLICYINSTALLDIRS = seuser

# exports
export CFLAGS CC YACC LEX LINKFLAGS BINDIR INSTALL_LIBDIR LIBS TCL_LIBINC TCL_LIBS MAKE 
export POLICY_SRC_DIR SRC_POLICY_DIR POLICY_SRC_FILE DEFAULT_LOG_FILE

all:  all-libs apol awish seuserx sepcut seaudit secmds

all-nogui:  corelibs seuser secmds

corelibs: libapol libseuser libseaudit

guilibs: libapol-tcl libseuser-tcl

all-libs: corelibs guilibs

help:
	@echo "Make targets for setools: "
	@echo "   install:         build and install everything (selinux required)"
	@echo "   install-nogui:   build and install all non-GUI tools (selinux required)"
	@echo ""
	@echo "   install-apol:    build and install apol (selinux not required)"
	@echo "   install-sepcut:  build and install sepct (selinux not required)"
	@echo "   install-seuser:  build and install command line seuser (selinux required)"
	@echo "   install-seuserx: build and install seuser and seuserx (selinux required)"
	@echo "   install-secmds:  build and install command line tools (selinux not required)"
	@echo "   install-seaudit: build and install seaudit (selinux not required)"
	@echo " "
	@echo "   all:             build everything, but don't install"
	@echo "   all-nogui:       only build non-GUI tools and libraries"
	@echo ""
	@echo "   rpm:             create a source and binary rpm - must be root"
	@echo "   docs:            generate setools documentation"
	@echo "   remove-docs:     remove setools documentation"
	@echo "   apol:            build policy analysis tool"
	@echo "   seuser:          build SE Linux command line user tool"
	@echo "   seuserx:         build SE Linux GUI user tool"
	@echo "   sepcut           build policy customization/browsing tool"
	@echo "   secmds:          build setools command line tools"
	@echo "   seaudit:         built audit log analysis tool"
	@echo "   awish:           build TCL/TK wish interpreter with SE Linux tools extensions"
	@echo " "
	@echo "   clean:          clean up interim files"
	@echo "   bare:           more extensive clean up"


apol: selinux_tool
	cd apol; $(MAKE) apol 

awish: selinux_tool
	cd awish; $(MAKE) awish

seuser: selinux_tool
	cd seuser; $(MAKE) seuser

seuserx: selinux_tool
	cd seuser; $(MAKE) seuserx

sepcut: selinux_tool
	cd sepct; $(MAKE) sepcut

seaudit: selinux_tool
	cd seaudit; $(MAKE)	

secmds: selinux_tool
	cd secmds; $(MAKE) all

libapol: selinux_tool
	cd libapol; $(MAKE) libapol

libapol-tcl: selinux_tool
	cd libapol; $(MAKE) libapol-tcl

libseuser: selinux_tool
	cd libseuser; $(MAKE) libseuser

libseuser-tcl: selinux_tool
	cd libseuser; $(MAKE) libseuser-tcl

libseaudit: selinux_tool
	cd libseaudit; $(MAKE)

$(INSTALL_LIBDIR):
	install -m 755 -d $(INSTALL_LIBDIR)

install-apol: $(INSTALL_LIBDIR)
	cd apol; $(MAKE) install

install-awish: $(INSTALL_LIBDIR)
	cd awish; $(MAKE) install	

# installs both GUI and non-GUI versions
install-seuserx: $(INSTALL_LIBDIR)
	cd seuser; $(MAKE) install

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

# Next four targets are to support installation as part of a system
# install. These targets are deprecated.
#
# copy all policy files to the uninstalled selinux policy build directory
insert-policy: 
	cd seuser ; $(MAKE) $@ 

sysinstall-seuser: $(INSTALL_LIBDIR)
	cd seuser; $(MAKE) sys-install "CFLAGS+=$(SYS_OPTIONS)"

sysall-seuser: 
	cd seuser; $(MAKE) sys-all "CFLAGS+=$(SYS_OPTIONS)"

sys-install: install-apol sysinstall-seuser install-sepcut

sys-all: apol sysall-seuser sepcut

VER=$(shell cat VERSION)

rpm: bare
	cd packages; make rpm
	@if [ ! -e ../setools-$(VER) ]; then \
		cd ..; mv setools setools-$(VER); \
	fi
	cd ..; tar cfz setools-$(VER).tgz setools-$(VER); rpmbuild -tb setools-$(VER).tgz; 

# Make all setools documentation
docs:
	cd docs-src; make docs

# Remove all generated setools documentation 
remove-docs:
	cd docs-src; make remove-docs

# test targets
tests: test-seuser test-apol

test-apol: selinux_tool
	cd libapol/test; $(MAKE) $@

test-seuser: selinux_tool
	cd libseuser/test; $(MAKE) $@

test-clean: 
	cd libapol/test; $(MAKE) clean
	cd libseuser/test; $(MAKE) clean

test-bare:
	cd libapol/test; $(MAKE) bare
	cd libseuser/test; $(MAKE) clean

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

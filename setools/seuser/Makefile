# seuser tool

SEUSER_STARTUP_SCRIPT = se_user.tcl
TCL-FILES	= seuser_head.tcl tmp.tcl
TCL-STRIP-FILES = seuser_db.tcl seuser_top.tcl seuser_advanced.tcl seuser_user_info.tcl seuser_generic_users.tcl seuser_selinux_users.tcl seuser_tail.tcl
SEUSER_HELP_FILE = seuser_help.txt
SEUSER_CONF_FILE = seuser.conf
LIBAPOL		= ../lib/libapol.a
LIBAPOL-TCL	= ../lib/libapol-tcl.a
LIBSEUSER	= ../lib/libseuser.a
LIBSEUSER-TCL	= ../lib/libseuser-tcl.a
CMD-OBJ		= seuser_cmd.o $(LIBSEUSER) $(LIBAPOL)
GUI-OBJ		= seuser_gui.o $(LIBAPOL-TCL) $(LIBSEUSER-TCL) $(LIBSEUSER) $(LIBAPOL)
SE_SHELL_SCRIPTS = seuseradd seuserdel seusermod

TE_PROGS_DIR	= $(POLICY_SRC_DIR)/policy/domains/program
FC_PROGS_DIR	= $(POLICY_SRC_DIR)/policy/file_contexts/program
#POLICY_FULL_SRC = $(POLICY_SRC_DIR)/policy  
GUI_CFLAGS  	+= -DSTARTUP_SCRIPT='"$(SEUSER_STARTUP_SCRIPT)"'
CFLAGS  	+= -DSEUSERCMD_VERSION_STRING='"$(shell cat CMD_VERSION)"'

SHELL = /bin/sh

seuser: $(CMD-OBJ) 
	$(CC) -o $@ $(CMD-OBJ) $(LINKFLAGS) $(LIBS)

seuserx: $(GUI-OBJ) se_user.tcl
	$(CC) $(GUI_CFLAGS) $(TCL_LIBINC) -o $@ $(GUI-OBJ) $(LINKFLAGS) $(TCL_LIBS)

se_user.tcl: $(TCL-FILES)
	cat $(TCL-FILES) | \
	sed -e 's/SEUSER_GUI_VERSION/$(shell cat GUI_VERSION)/g' > $@ 

tmp.tcl: $(TCL-STRIP-FILES)
	cat $(TCL-STRIP-FILES) > $@
        # compact it by removing comments and empty lines
	@perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' $@ 

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

$(LIBAPOL): 
	cd ../ ; $(MAKE) libapol

$(LIBAPOL-TCL): 
	cd ../ ; $(MAKE) libapol-tcl

$(LIBSEUSER):
	cd ../ ; $(MAKE) libseuser

$(LIBSEUSER-TCL):
	cd ../ ; $(MAKE) libseuser-tcl


# The following two targets are for when seuser is installed during the 
# selinux installation procedure. (THESE TARGETS ARE DEPRECATED)

# TE_FILE_INSTALL_DIR and FC_FILE_INSTALL_DIR are assumed to be passed down
# from a higher level Makefile.

insert-policy:
	-install -m 644 ../policy/seuser.te $(TE_FILE_INSTALL_DIR)
	-install -m 644 ../policy/seuser.fc $(FC_FILE_INSTALL_DIR)

sys-all: seuser seuserx

sys-install: seuser seuserx se_user.tcl
	-install -m 755 seuser $(SE_SHELL_SCRIPTS) $(BINDIR)
	-install -m 644 $(SEUSER_CONF_FILE) $(INSTALL_LIBDIR)
	-install -m 644 se_user.tcl $(SEUSER_HELP_FILE) $(INSTALL_LIBDIR)

# Installation
# This process is complicated by the fact that we have 3 scenarios for
# installation: installation on a standard linux box, installation
# on an selinux box, and installation during rpm building.
#
# NOTE:	The following targets assume selinux and the chcon utility.
#      	To ignore install errors in a command line, we use `-' at  
#      	the beginning of a shell command (after the initial tab). 
#      	The `-' is discarded before the command is passed to the 
#	shell for execution. When a line starts with `@', the 
#	echoing of that line is suppressed.


seuser-policy:
	cat ../policy/seuser_template.fc | \
	sed -e 's|SEUSER_BINDIR|$(BINDIR)|g' | \
	sed -e 's|SEUSER_INSTALL_LIBDIR|$(INSTALL_LIBDIR)|g' > ../policy/seuser.fc 
	
	-@if [ -e $(POLICY_SRC_DIR)/policy/Makefile -a -e ../policy/seuser.fc ]; then \
		install -d $(TE_PROGS_DIR); \
		install -d $(FC_PROGS_DIR); \
		install -m 644 -Z system_u:object_r:policy_src_t ../policy/seuser.te $(TE_PROGS_DIR); \
		install -m 644 -Z system_u:object_r:policy_src_t ../policy/seuser.fc $(FC_PROGS_DIR); \
	else \
		install -d $(TE_PROGS_DIR); \
		install -d $(FC_PROGS_DIR); \
		install -m 644 ../policy/seuser.te $(TE_PROGS_DIR); \
		install -m 644 ../policy/seuser.fc $(FC_PROGS_DIR); \
		echo "ERROR: YOU MUST HAVE THE POLICY SOURCE INSTALLED TO $(POLICY_SRC_DIR)."; \
		echo "	seuser did not install with context because the policy source was"; \
		echo "	not found. type 'make install-src' from your policy directory, or"; \
		echo "	consult your SELinux documentation."; \
	fi
	
	-@if [ -e ../policy/seuser.fc ]; then \
		rm -f ../policy/seuser.fc; \
	fi
	

policy-install: seuser-policy
	-@if [ -e $(POLICY_SRC_DIR)/policy/Makefile ]; then \
		make -C $(POLICY_SRC_DIR)/policy/ clean; \
		make -C $(POLICY_SRC_DIR)/policy/ load; \
	fi 

install-nogui: seuser policy-install
	-install -d $(BINDIR); 
	-@if [ -e $(POLICY_SRC_DIR)/policy/Makefile ]; then \
		install -m 755 -Z system_u:object_r:seuser_exec_t seuser $(BINDIR); \
		install -m 644 -Z system_u:object_r:seuser_conf_t $(SEUSER_CONF_FILE) $(INSTALL_LIBDIR); \
	else \
		install -m 755 seuser $(BINDIR); \
		install -m 644 $(SEUSER_CONF_FILE) $(INSTALL_LIBDIR); \
	fi
	-install -m 755 $(SE_SHELL_SCRIPTS) $(BINDIR)

install: install-nogui seuserx se_user.tcl
	-install -d $(BINDIR); 
	-@if [ -e /etc/security/selinux/src/policy/policy.conf ]; then \
		install -m 755 -Z system_u:object_r:seuser_exec_t seuserx $(BINDIR); \
	else \
		install -m 755 seuserx $(BINDIR); \
	fi
	-install -m 644 se_user.tcl $(SEUSER_HELP_FILE) $(INSTALL_LIBDIR)

clean:
	rm -f *.o  core* seuser seuserx *~ se_user.tcl tmp.tcl
bare:
	rm -f *.o  core* seuser seuserx *~ se_user.tcl tmp.tcl 







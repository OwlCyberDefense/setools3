#apol tool

APOL_STARTUP_SCRIPT = apol.tcl
APOL_HELP_FILES	= apol_help.txt dta_help.txt iflow_help.txt obj_perms_help.txt 
APOL_PERM_MAPS  = perm_maps/apol_perm_mapping_ver*
APOL_DFLT_PMAP  = apol_perm_mapping_ver18

# The modules must each be listed here.
ANALYSIS-MODULES = dta_module.tcl dirflow_module.tcl fulflow_module.tcl \
                   relabel_module.tcl types_relation_module.tcl

TCL-FILES	= head.tcl tmp.tcl
TCL-STRIP-FILES = types_tab.tcl terules_tab.tcl roles_tab.tcl rbac_tab.tcl \
		  users_tab.tcl initial_sids_tab.tcl file_contexts_tab.tcl \
		  cond_bools_tab.tcl cond_rules_tab.tcl classes_perms_tab.tcl \
		  policyconf.tcl perms_map.tcl analysis_tab.tcl \
		  range_dialog.tcl level_dialog.tcl \
		  range_trans.tcl mls_tab.tcl \
		  netcontexts_tab.tcl context_dialog.tcl context_selector.tcl \
		  fscontexts_tab.tcl \
		  common_widgets.tcl range_selector.tcl \
		  $(ANALYSIS-MODULES) top.tcl

ifeq ($(DYNAMIC), 0)
	LIBAPOL		= ../libapol/libapol-tcl.a ../libapol/libapol.a
	
	ifeq ($(USE_LIBSEFS), 1)
	LIBSEFS		= ../libsefs/libsefs.a
	else
	LIBSEFS = 
	endif
else
	LIBAPOL		= ../libapol/libapol.so.$(shell cat ../libapol/VERSION) ../libapol/libapol-tcl.a
	
	ifeq ($(USE_LIBSEFS), 1)
	LIBSEFS		= ../libsefs/libsefs.so.$(shell cat ../libsefs/VERSION)
	else
	LIBSEFS = 
	endif
endif

GUI-OBJ		= apol_gui.o $(LIBAPOL) $(LIBSEFS)
CFLAGS          += -DSTARTUP_SCRIPT='"$(APOL_STARTUP_SCRIPT)"'

# apol is optionally linked to libselinux. The LIBSELINUX variable 
# is set in the top-level Makefile.
all: libapol libapol-tcl apol

apol: $(GUI-OBJ) apol.tcl
	$(CC) $(TCL_LIBINC) -o $@ $(LINKFLAGS) $(GUI-OBJ) $(TCL_LIBS) $(LIBSELINUX)


apol.tcl: $(TCL-FILES)
	cat $(TCL-FILES) | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat VERSION)/g' | \
	sed -e 's|APOL_INSTALL_DIR|$(INSTALL_LIBDIR)|g' > $@ 

tmp.tcl: $(TCL-STRIP-FILES)
	cat $(TCL-STRIP-FILES) > $@
	# compact it by removing comments and empty lines
	@perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' $@

libpol:
	$(MAKE) -C .. libapol

libapol-tcl:
	$(MAKE) -C .. libapol-tcl

libsefs:
	$(MAKE) -C .. libsefs

../libapol/libapol.a: 
	$(MAKE) -C .. libapol

../libapol/libapol-tcl.a:
	$(MAKE) -C .. libapol-tcl

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

%.tcl: 
# do nothing

$(LIBSEFS):
	$(MAKE) -C .. libsefs

install: apol apol.tcl
	install -m 755 apol $(BINDIR)
	@if [ -n $(INSTALL_LIBDIR) ]; then \
		for file in $(TCL-FILES); do \
			if [ -f $(INSTALL_LIBDIR)/$$file ]; then \
				mv $(INSTALL_LIBDIR)/$$file $(INSTALL_LIBDIR)/$$file.old; \
			fi \
		done \
	fi
	install -m 644 apol.tcl $(APOL_HELP_FILES) $(APOL_PERM_MAPS) $(INSTALL_LIBDIR)
	cd $(INSTALL_LIBDIR); ln -sf $(APOL_DFLT_PMAP) apol_perm_mapping

clean:
	rm -f *.o  core apol *~ apol.tcl tmp.tcl

bare:
	rm -f *.o  core* apol *~ apol.tcl tmp.tcl

.PHONY: clean bare libapol libapol-tcl libsefs


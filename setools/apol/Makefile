# apol tool

APOL_STARTUP_SCRIPT = apol.tcl
TCL-FILES	= head.tcl tmp.tcl
TCL-STRIP-FILES = types_tab.tcl terules_tab.tcl roles_tab.tcl rbac_tab.tcl users_tab.tcl initial_sids_tab.tcl classes_perms_tab.tcl policyconf.tcl perms_map.tcl analysis_tab.tcl $(ANALYSIS-MODULES) top.tcl
# The modules must each be listed here.
ANALYSIS-MODULES = dta_module.tcl dirflow_module.tcl fulflow_module.tcl 

APOL_HELP_FILES	= apol_help.txt dta_help.txt iflow_help.txt
APOL_PERM_MAPS	= apol_perm_mapping_ver12 apol_perm_mapping_ver15
APOL_DFLT_PMAP  = apol_perm_mapping_ver15
LIBAPOL		= ../lib/libapol-tcl.a ../lib/libapol.a
GUI-OBJ		= apol_gui.o $(LIBAPOL)
CFLAGS            += -DSTARTUP_SCRIPT='"$(APOL_STARTUP_SCRIPT)"'

apol: $(GUI-OBJ) apol.tcl
	$(CC) $(TCL_LIBINC) -o $@ $(GUI-OBJ) $(LINKFLAGS) $(TCL_LIBS)


apol.tcl: $(TCL-FILES)
	cat $(TCL-FILES) | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat VERSION)/g' > $@

tmp.tcl: $(TCL-STRIP-FILES)
	cat $(TCL-STRIP-FILES) > $@
        # compact it by removing comments and empty lines
	@perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' $@


../lib/libapol.a: 
	cd ../; $(MAKE) libapol

../lib/libapol-tcl.a:
	cd ../; $(MAKE) libapol-tcl

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

%.tcl: 
# do nothing


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







bin_SCRIPTS = apol

dist_setools_DATA = apol_help.txt domaintrans_help.txt file_relabel_help.txt \
	infoflow_help.txt types_relation_help.txt \
	perm_maps/apol_perm_mapping_ver12 \
	perm_maps/apol_perm_mapping_ver15 \
	perm_maps/apol_perm_mapping_ver16 \
	perm_maps/apol_perm_mapping_ver17 \
	perm_maps/apol_perm_mapping_ver18 \
	perm_maps/apol_perm_mapping_ver19 \
	perm_maps/apol_perm_mapping_ver20 \
	perm_maps/apol_perm_mapping_ver21 \
	apol.gif

dist_noinst_DATA = apol.png foo_module.tcl

EXTRA_DIST = head.tcl \
	types_tab.tcl terules_tab.tcl roles_tab.tcl rbac_tab.tcl \
	users_tab.tcl initial_sids_tab.tcl file_contexts_tab.tcl \
	cond_bools_tab.tcl cond_rules_tab.tcl classes_perms_tab.tcl \
	policyconf.tcl perms_map.tcl analysis_tab.tcl \
	range_dialog.tcl level_dialog.tcl \
	range_trans.tcl mls_tab.tcl \
	netcontexts_tab.tcl context_dialog.tcl context_selector.tcl \
	fscontexts_tab.tcl \
	common_widgets.tcl range_selector.tcl \
	domaintrans_module.tcl directflow_module.tcl transflow_module.tcl \
	relabel_module.tcl types_relation_module.tcl \
	open_policy_dialog.tcl util.tcl top.tcl

DEPENDENCIES = $(top_builddir)/libqpol/swig/tcl/libtqpol.so $(top_builddir)/libapol/swig/tcl/libtapol.so $(top_builddir)/config.tcl

#if WANT_LIBSEFS
#apol_DEPENDENCIES += $(top_builddir)/libsefs/swig/tcl/libtsefs.so
#endif

TCL_STRIP_FILES = $(filter-out head.tcl,$(EXTRA_DIST))
TCL_AUTOPATH = @TCL_AUTOPATH@

init.tcl: Makefile
	@echo "proc tcl_config_init_libraries {} {" > $@
	@echo "    global auto_path" >> $@
	@echo "    lappend auto_path $(TCL_AUTOPATH)" >> $@
	@echo "    package require qpol" >> $@
	@echo "    package require apol" >> $@
	@echo "    package require apol_tcl" >> $@
	@echo "}" >> $@
	@echo "proc tcl_config_get_install_dir {} {" >> $@
	@echo "    return \"${setoolsdir}\"" >> $@
	@echo "}" >> $@

$(bin_SCRIPTS): head.tcl init.tcl $(top_builddir)/config.tcl $(TCL_STRIP_FILES)
	cat head.tcl init.tcl $(top_builddir)/config.tcl > $@
	cat $(TCL_STRIP_FILES) | perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' >> $@
	chmod u+x $@

%.tcl:
# do nothing

CLEANFILES = $(bin_SCRIPTS) init.tcl

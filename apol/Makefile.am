apol_install_dir = @apol_install_dir@
apol_gui_version = @VERSION@

bin_PROGRAMS = apol
dist_bin_SCRIPTS = apol.tcl

dist_pkgdata_DATA = apol_help.txt dta_help.txt iflow_help.txt obj_perms_help.txt \
	perm_maps/apol_perm_mapping_ver12 \
	perm_maps/apol_perm_mapping_ver15 \
	perm_maps/apol_perm_mapping_ver16 \
	perm_maps/apol_perm_mapping_ver17 \
	perm_maps/apol_perm_mapping_ver18 \
	perm_maps/apol_perm_mapping_ver19 \
	perm_maps/apol_perm_mapping_ver20

BUILT_SOURCES = tmp.tcl

AM_CFLAGS = -I$(top_srcdir)/libqpol/include @TCL_INCLUDES@ -DSTARTUP_SCRIPT='"apol.tcl"'
AM_LDFLAGS = @TCL_LIB_SPEC@ @TK_LIB_SPEC@

apol_SOURCES = apol_gui.c \
	head.tcl \
	types_tab.tcl terules_tab.tcl roles_tab.tcl rbac_tab.tcl \
	users_tab.tcl initial_sids_tab.tcl file_contexts_tab.tcl \
	cond_bools_tab.tcl cond_rules_tab.tcl classes_perms_tab.tcl \
	policyconf.tcl perms_map.tcl analysis_tab.tcl \
	range_dialog.tcl level_dialog.tcl \
	range_trans.tcl mls_tab.tcl \
	netcontexts_tab.tcl context_dialog.tcl context_selector.tcl \
	fscontexts_tab.tcl \
	common_widgets.tcl range_selector.tcl \
	dta_module.tcl dirflow_module.tcl fulflow_module.tcl \
	relabel_module.tcl \
	top.tcl

noinst_DATA = foo_module.tcl

LDADD = $(top_srcdir)/libapol/libapol.a $(top_srcdir)/libqpol/src/libqpol.so @QPOL_LIB_FLAG@ @TCL_LIB_FLAG@ @TK_LIB_FLAG@
apol_DEPENDENCIES = apol.tcl $(top_srcdir)/libapol/libapol-tcl.a $(top_srcdir)/libapol/libapol.a $(top_srcdir)/libqpol/src/libqpol.so $(top_srcdir)/config.tcl

if WANT_LIBSEFS
apol_LDADD = $(top_srcdir)/libapol/libapol-tcl.a $(top_srcdir)/libsefs/libsefs.a $(LDADD)
apol_DEPENDENCIES += $(top_srcdir)/libsefs/libsefs.a
else
apol_LDADD = $(top_srcdir)/libapol/libapol-tcl.a $(LDADD)
endif

TCL_STRIP_FILES = $(top_srcdir)/config.tcl $(filter-out head.tcl,$(filter %.tcl,$(apol_SOURCES)))

apol.tcl: head.tcl tmp.tcl
	cat $^ | \
	sed -e 's/APOL_GUI_VERSION/$(apol_gui_version)/g' | \
	sed -e 's|APOL_INSTALL_DIR|$(apol_install_dir)|g' > $@

# build a compacted version of apol Tcl files
tmp.tcl: $(TCL_STRIP_FILES)
	cat $^ > $@
	@perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' $@

%.tcl:
# do nothing

# FIX ME: install help files, perm maps, and link to default perm map

$(top_srcdir)/libapol/libapol-tcl.a $(top_srcdir)/libapol/libapol.a:
	$(MAKE) -C $(top_srcdir)/libapol $(notdir $@)

$(top_srcdir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_srcdir)/libqpol/src $(notdir $@)

$(top_srcdir)/libsefs/libsefs.a:
	$(MAKE) -C $(top_srcdir)/libsefs $(notdir $@)

CLEANFILES = $(dist_bin_SCRIPTS)

mostlyclean-local:
	-rm -rf $(dist_bin_SCRI)

clean-local:
	-rm -rf tmp.tcl

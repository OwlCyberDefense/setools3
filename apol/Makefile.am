bin_PROGRAMS = apol
dist_setools_SCRIPTS = apol.tcl

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

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @TCL_INCLUDES@ -DSTARTUP_SCRIPT='"apol.tcl"'
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ @TCL_LIB_SPEC@ @TK_LIB_SPEC@

apol_SOURCES = apol.c \
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
	domaintrans_module.tcl directflow_module.tcl transflow_module.tcl \
	relabel_module.tcl types_relation_module.tcl \
	open_policy_dialog.tcl top.tcl

LDADD = @SELINUX_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @TCL_LIB_FLAG@ @TK_LIB_FLAG@
apol_DEPENDENCIES = apol.tcl $(top_builddir)/libapol-tcl/libapol-tcl.a $(top_builddir)/libapol/src/libapol.so $(top_builddir)/libqpol/src/libqpol.so $(top_builddir)/config.tcl

if WANT_LIBSEFS
apol_LDADD = $(top_builddir)/libapol-tcl/libapol-tcl.a @SEFS_LIB_FLAG@ $(LDADD)
apol_DEPENDENCIES += $(top_builddir)/libsefs/src/libsefs.so
else
apol_LDADD = $(top_builddir)/libapol-tcl/libapol-tcl.a $(LDADD)
endif

TCL_STRIP_FILES = $(patsubst %,$(srcdir)/%,$(filter-out head.tcl,$(filter %.tcl,$(apol_SOURCES))))

apol.tcl: $(srcdir)/head.tcl $(top_builddir)/config.tcl $(TCL_STRIP_FILES)
	cat $(srcdir)/head.tcl $(top_builddir)/config.tcl > $@
	cat $(TCL_STRIP_FILES) | perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' >> $@

%.tcl:
# do nothing

$(top_builddir)/libapol/libapol-tcl.a:
	$(MAKE) -C $(top_builddir)/libapol-tcl $(notdir $@)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

$(top_builddir)/libsefs/src/libsefs.so:
	$(MAKE) -C $(top_builddir)/libsefs/src $(notdir $@)

CLEANFILES = $(dist_setools_SCRIPTS)

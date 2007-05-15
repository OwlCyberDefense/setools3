noinst_LIBRARIES = libapol_tcl.a
setoolsdir = @setoolsdir@

libapol_tcl_so_DATA = libapol_tcl.so.@libapol_version@
libapol_tcl_sodir = $(libdir)/setools/apol_tcl

package_SCRIPTS = pkgIndex.tcl
packagedir = $(libapol_tcl_sodir)

bin_SCRIPTS = apol

libapol_tcl_a_SOURCES = apol_tcl.c

libapol_tcl_a_DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libsefs/src/libsefs.so \
	$(top_builddir)/libqpol/swig/tcl/libtqpol.so \
	$(top_builddir)/libapol/swig/tcl/libtapol.so

libapol_tcl_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libapol_tcl_a_SOURCES)))

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

EXTRA_DIST = \
	analysis_tab.tcl \
	classes_perms_tab.tcl \
	common_widgets.tcl \
	cond_bools_tab.tcl \
	cond_rules_tab.tcl \
	context_dialog.tcl \
	context_selector.tcl \
	directflow_module.tcl \
	domaintrans_module.tcl \
	file_contexts_tab.tcl \
	find.tcl \
	fscontexts_tab.tcl \
	goto.tcl \
	head.tcl \
	initial_sids_tab.tcl \
	level_dialog.tcl \
	mls_tab.tcl \
	netcontexts_tab.tcl \
	open_policy_dialog.tcl \
	perms_map.tcl \
	policyconf.tcl \
	progress_dialog.tcl \
	range_dialog.tcl \
	range_selector.tcl \
	range_trans.tcl \
	rbac_tab.tcl \
	relabel_module.tcl \
	roles_tab.tcl \
	terules_tab.tcl \
	transflow_module.tcl \
	types_relation_module.tcl \
	types_tab.tcl \
	users_tab.tcl \
	util.tcl \
	top.tcl
# top.tcl must be last one written because it spawns the rest of the script

TCL_STRIP_FILES = $(patsubst %,$(srcdir)/%,$(filter-out head.tcl,$(EXTRA_DIST)))

DEPENDENCIES = $(top_builddir)/libqpol/swig/tcl/libtqpol.so $(top_builddir)/libapol/swig/tcl/libtapol.so $(top_builddir)/config.tcl

#if WANT_LIBSEFS
#apol_DEPENDENCIES += $(top_builddir)/libsefs/swig/tcl/libtsefs.so
#endif

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@SEFS_CFLAGS@@ @APOL_CFLAGS@ @QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include @TCL_INCLUDES@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @TCL_LIB_FLAG@

$(libapol_tcl_so_DATA): $(libapol_tcl_so_OBJS)
	$(CC) -shared -o $@ $^ $(AM_LDFLAGS) $(LDFLAGS)

$(libapol_tcl_so_DATA): libapol_tcl.a

$(package_SCRIPTS): $(libapol_tcl_so_DATA)
	echo "lappend auto_path $(top_builddir)/libapol/swig/tcl ; package require apol ; pkg_mkIndex . $^" | LD_LIBRARY_PATH=$(top_builddir)/libqpol/src:$(top_builddir)/libapol/src:$(top_builddir)/libsefs/src $(TCLSH_PROG)
	$(mkdir_p) apol_tcl
	cp $< $@ apol_tcl

TCL_AUTOPATH = @TCL_AUTOPATH@

init.tcl: Makefile
	@echo "proc tcl_config_init_libraries {} {" > $@
	@echo "    global auto_path" >> $@
	@echo "    lappend auto_path $(TCL_AUTOPATH)" >> $@
	@echo "    puts \"Initializing libqpol.\"" >> $@
	@echo "    package require qpol" >> $@
	@echo "    puts \"Initializing libapol.\"" >> $@
	@echo "    package require apol" >> $@
	@echo "    puts \"Initializing libapol_tcl.\"" >> $@
	@echo "    package require apol_tcl" >> $@
	@echo "}" >> $@
	@echo "proc tcl_config_get_install_dir {} {" >> $@
	@echo "    return \"${setoolsdir}\"" >> $@
	@echo "}" >> $@

$(bin_SCRIPTS): head.tcl init.tcl $(top_builddir)/config.tcl $(TCL_STRIP_FILES)
	cat $(srcdir)/head.tcl init.tcl $(top_builddir)/config.tcl > $@
	cat $(TCL_STRIP_FILES) | perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' >> $@
	chmod u+x $@

%.tcl:
# do nothing

CLEANFILES = $(packages_SCRIPTS) $(bin_SCRIPTS) init.tcl

MOSTLYCLEANFILES = $(libapol_tcl_so_DATA) $(package_SCRIPTS) apol_tcl/$(package_SCRIPTS) apol_tcl/$(libapol_tcl_so_DATA)

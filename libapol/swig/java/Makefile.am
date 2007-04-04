wrappedso_DATA = libjapol.so.@libapol_version@
wrappedso_SONAME = @libapol_jswig_soname@
short_name = libjapol.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.apol

wrappedclass_DATA = \
        apol_attr_query_t.class \
        apol_avrule_query_t.class \
        apol_bool_query_t.class \
        apol_cat_query_t.class \
        apol_class_query_t.class \
        apol_common_query_t.class \
        apol_cond_query_t.class \
        apolConstants.class \
        apol_constraint_query_t.class \
        apol_context_t.class \
        apol_domain_trans_analysis_t.class \
        apol_domain_trans_result_t.class \
        apol_fs_use_query_t.class \
        apol_genfscon_query_t.class \
        apol_infoflow_analysis_t.class \
        apol_infoflow_graph_t.class \
        apol_infoflow_result_t.class \
        apol_infoflow_step_t.class \
        apol_infoflow_t.class \
        apol_isid_query_t.class \
        apol.class \
        apolJNI.class \
        apol_level_query_t.class \
        apol_mls_level_t.class \
        apol_mls_range_t.class \
        apol_netifcon_query_t.class \
        apol_nodecon_query_t.class \
        apol_perm_query_t.class \
        apol_policy_path_t.class \
        apol_policy_path_type_e.class \
        apol_policy_t.class \
        apol_portcon_query_t.class \
        apol_range_trans_query_t.class \
        apol_relabel_analysis_t.class \
        apol_relabel_result_pair_t.class \
        apol_relabel_result_t.class \
        apol_role_allow_query_t.class \
        apol_role_query_t.class \
        apol_role_trans_query_t.class \
        apol_string_vector_t.class \
        apol_terule_query_t.class \
        apol_type_query_t.class \
        apol_types_relation_access_t.class \
        apol_types_relation_analysis_t.class \
        apol_types_relation_result_t.class \
        apol_user_query_t.class \
        apol_validatetrans_query_t.class \
        apol_vector_t.class \
        SWIGTYPE_p_qpol_avrule_t.class \
        SWIGTYPE_p_qpol_cond_t.class \
        SWIGTYPE_p_qpol_context_t.class \
        SWIGTYPE_p_qpol_fs_use_t.class \
        SWIGTYPE_p_qpol_genfscon_t.class \
        SWIGTYPE_p_qpol_iterator_t.class \
        SWIGTYPE_p_qpol_level_t.class \
        SWIGTYPE_p_qpol_mls_level_t.class \
        SWIGTYPE_p_qpol_mls_range_t.class \
        SWIGTYPE_p_qpol_netifcon_t.class \
        SWIGTYPE_p_qpol_nodecon_t.class \
        SWIGTYPE_p_qpol_policy_t.class \
        SWIGTYPE_p_qpol_portcon_t.class \
        SWIGTYPE_p_qpol_range_trans_t.class \
        SWIGTYPE_p_qpol_role_allow_t.class \
        SWIGTYPE_p_qpol_role_t.class \
        SWIGTYPE_p_qpol_role_trans_t.class \
        SWIGTYPE_p_qpol_syn_avrule_t.class \
        SWIGTYPE_p_qpol_syn_terule_t.class \
        SWIGTYPE_p_qpol_terule_t.class \
        SWIGTYPE_p_qpol_type_t.class \
        SWIGTYPE_p_unsigned_int.class \
        SWIGTYPE_p_void.class
wrappedclassdir = $(setoolsdir)/$(subst .,/,$(package_name))

dist_noinst_DATA = $(srcdir)/../apol.i
BUILT_SOURCES = apol_wrap.c $(subst .class,.java,$(wrappedclass_DATA))

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include -D__attribute__\(x\)=''
AM_JFLAGS = @DEBUGJFLAGS@ @WARNJFLAGS@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_JAVA_OPT) -package $(package_name) -o $@ -I$(top_srcdir)/libapol/include $<

$(wrappedso_DATA): $(filter %.c, $(BUILT_SOURCES))
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_JAVA_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(wrappedclass_DATA): $(filter %.java, $(BUILT_SOURCES))
	$(JAVAC) $(AM_JFLAGS) $(JAVAFLAGS) $^

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(short_name)

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/$(short_name)

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedclass_DATA) $(wrappedso_SONAME) $(short_name)

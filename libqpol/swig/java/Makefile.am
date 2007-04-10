wrappedso_DATA = libjqpol.so.@libqpol_version@
wrappedso_SONAME = @libqpol_jswig_soname@
short_name = libjqpol.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.qpol

wrappedclass_DATA = \
	qpol_avrule_t.class \
	qpol_bool_t.class \
	qpol_capability_e.class \
	qpol_cat_t.class \
	qpol_class_t.class \
	qpol_common_t.class \
	qpol_cond_expr_node_t.class \
	qpol_cond_t.class \
	qpolConstants.class \
	qpol_constraint_expr_node_t.class \
	qpol_constraint_t.class \
	qpol_context_t.class \
	qpol_fs_use_t.class \
	qpol_genfscon_t.class \
	qpol_isid_t.class \
	qpol_iterator_t.class \
	qpol.class \
	qpolJNI.class \
	qpol_level_t.class \
	qpol_mls_level_t.class \
	qpol_mls_range_t.class \
	qpol_module_t.class \
	qpol_netifcon_t.class \
	qpol_nodecon_t.class \
	qpol_policy_t.class \
	qpol_range_trans_t.class \
	qpol_role_allow_t.class \
	qpol_role_t.class \
	qpol_role_trans_t.class \
	qpol_syn_avrule_t.class \
	qpol_syn_terule_t.class \
	qpol_terule_t.class \
	qpol_type_set_t.class \
	qpol_type_t.class \
	qpol_user_t.class \
	qpol_validatetrans_t.class \
	SWIGTYPE_p_f_p_void_p_struct_qpol_policy_int_p_q_const__char_va_list__void.class \
	SWIGTYPE_p_int.class \
	SWIGTYPE_p_void.class
wrappedclassdir = $(setoolsdir)/$(subst .,/,$(package_name))

dist_noinst_DATA = $(srcdir)/../qpol.i
BUILT_SOURCES = qpol_wrap.c $(subst .class,.java,$(wrappedclass_DATA))

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	-I$(top_builddir) -fpic \
	-I$(top_srcdir)/libqpol/include
AM_JFLAGS = @DEBUGJFLAGS@ @WARNJFLAGS@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so 

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_JAVA_OPT) -package $(package_name) -o $@ -I$(top_srcdir)/libqpol/include $<

$(wrappedso_DATA): $(filter %.c, $(BUILT_SOURCES))
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_JAVA_CFLAGS) -DSWIGJAVA=1 $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
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

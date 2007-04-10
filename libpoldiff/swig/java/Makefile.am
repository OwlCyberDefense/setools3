wrappedso_DATA = libjpoldiff.so.@libpoldiff_version@
wrappedso_SONAME = @libpoldiff_jswig_soname@
short_name = libjpoldiff.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.poldiff

wrappedclass_DATA = \
        poldiff_attrib_t.class \
        poldiff_avrule_t.class \
        poldiff_bool_t.class \
        poldiff_cat_t.class \
        poldiff_class_t.class \
        poldiff_common_t.class \
        poldiffConstants.class \
        poldiff_form_e.class \
        poldiff.class \
        poldiffJNI.class \
        poldiff_level_t.class \
        poldiff_range_t.class \
        poldiff_range_trans_t.class \
        poldiff_role_allow_t.class \
        poldiff_role_t.class \
        poldiff_role_trans_t.class \
        poldiff_stats_t.class \
        poldiff_terule_t.class \
        poldiff_t.class \
        poldiff_type_remap_entry_t.class \
        poldiff_type_t.class \
        poldiff_user_t.class \
        SWIGTYPE_p_apol_mls_range_t.class \
        SWIGTYPE_p_apol_policy.class \
        SWIGTYPE_p_apol_string_vector_t.class \
        SWIGTYPE_p_apol_vector_t.class \
        SWIGTYPE_p_qpol_cond_t.class \
        SWIGTYPE_p_void.class
wrappedclassdir = $(setoolsdir)/$(subst .,/,$(package_name))

dist_noinst_DATA = $(srcdir)/../poldiff.i
BUILT_SOURCES = poldiff_wrap.c $(subst .class,.java,$(wrappedclass_DATA))

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include -I$(top_srcdir)/libpoldiff/include
AM_JFLAGS = @DEBUGJFLAGS@ @WARNJFLAGS@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @POLDIFF_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libpoldiff/src/poldiff.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_JAVA_OPT) -package $(package_name) -o $@ -I$(top_srcdir)/libpoldiff/include $<

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

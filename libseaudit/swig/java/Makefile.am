wrappedso_DATA = libjseaudit.so.@libseaudit_version@
wrappedso_SONAME = @libseaudit_jswig_soname@
short_name = libjseaudit.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.seaudit

wrappedclass_DATA = \
        seaudit_avc_message_t.class \
        seaudit_avc_message_type_e.class \
        seaudit_bool_message_t.class \
        seaudit_filter_date_match_e.class \
        seaudit_filter_match_e.class \
        seaudit_filter_t.class \
        seaudit_filter_visible_e.class \
        seaudit.class \
        seauditJNI.class \
        seaudit_load_message_t.class \
        seaudit_log_t.class \
        seaudit_log_type_e.class \
        seaudit_message_t.class \
        seaudit_message_type_e.class \
        seaudit_model_t.class \
        seaudit_report_format_e.class \
        seaudit_report_t.class \
        seaudit_sort_t.class \
        SWIGTYPE_p_apol_string_vector_t.class \
        SWIGTYPE_p_apol_vector_t.class \
        SWIGTYPE_p_FILE.class \
        SWIGTYPE_p_void.class \
        tm_t.class
wrappedclassdir = $(setoolsdir)/$(subst .,/,$(package_name))

dist_noinst_DATA = $(srcdir)/../seaudit.i
BUILT_SOURCES = seaudit_wrap.c $(subst .class,.java,$(wrappedclass_DATA))

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include -I$(top_srcdir)/libseaudit/include -D__attribute__\(x\)=''
AM_JFLAGS = @DEBUGJFLAGS@ @WARNJFLAGS@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @POLDIFF_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libseaudit/src/seaudit.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_JAVA_OPT) -package $(package_name) -o $@ -I$(top_srcdir)/libseaudit/include $<

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

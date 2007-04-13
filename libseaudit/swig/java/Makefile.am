wrappedso_DATA = libjseaudit.so.@libseaudit_version@
wrappedso_SONAME = @libseaudit_jswig_soname@
short_name = libjseaudit.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.seaudit
package_dir = $(dir $(subst .,/,$(package_name)))seaudit

wrappedjar_DATA = seaudit.jar
wrappedjardir = $(libdir)/setools

dist_noinst_DATA = $(srcdir)/../seaudit.i
BUILT_SOURCES = seaudit_wrap.c \
        seaudit_avc_message_t.java \
        seaudit_avc_message_type_e.java \
        seaudit_bool_message_t.java \
        seaudit_filter_date_match_e.java \
        seaudit_filter_match_e.java \
        seaudit_filter_t.java \
        seaudit_filter_visible_e.java \
        seaudit.java \
        seauditJNI.java \
        seaudit_load_message_t.java \
        seaudit_log_t.java \
        seaudit_log_type_e.java \
        seaudit_message_t.java \
        seaudit_message_type_e.java \
        seaudit_model_t.java \
        seaudit_report_format_e.java \
        seaudit_report_t.java \
        seaudit_sort_t.java \
        SWIGTYPE_p_FILE.java \
        SWIGTYPE_p_void.java \
        tm_t.java

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include -I$(top_srcdir)/libseaudit/include
AM_JFLAGS = @DEBUGJFLAGS@ @WARNJFLAGS@ \
	-classpath $(top_builddir)/libqpol/swig/java/qpol.jar:$(top_builddir)/libqpol/swig/java/apol.jar
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @POLDIFF_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libseaudit/src/seaudit.so

$(firstword $(BUILT_SOURCES)): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_JAVA_OPT) -package $(package_name) -o $@ \
	-I$(top_srcdir)/libseaudit/include -I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/include \
	-I$(top_srcdir)/libqpol/swig -I$(top_srcdir)/libapol/swig $<

$(wrappedso_DATA): $(filter %.c, $(BUILT_SOURCES))
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_JAVA_CFLAGS) -DSWIGJAVA=1 $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

classes = $(patsubst %.java,$(package_dir)/%.class,$(filter %.java, $(BUILT_SOURCES)))

# Because the Java compiler can generate multiple class files from the
# same source .java file, putting all of the classes below will result
# in repeated invocations of javac.  Therefore, an alternative is to
# just depend upon the first class file, and let the Java compiler
# create the rest of them.
$(firstword $(classes)): $(filter %.java, $(BUILT_SOURCES))
	$(JAVAC) $(AM_JFLAGS) $(JAVAFLAGS) -d . $^

$(wordlist 2,$(words $(classes)),$(classes)): $(firstword $(classes))

$(wrappedjar_DATA): MANIFEST.MF

$(wrappedjar_DATA): $(classes)
	$(JAR) cf $@ -m MANIFEST.MF $^

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(short_name)

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/$(short_name)

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(classes) $(wrappedso_DATA) $(wrappedjar_DATA) $(wrappedso_SONAME) $(short_name)

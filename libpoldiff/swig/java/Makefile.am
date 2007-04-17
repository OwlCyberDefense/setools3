wrappedso_DATA = libjpoldiff.so.@libpoldiff_version@
wrappedso_SONAME = @libpoldiff_jswig_soname@
short_name = libjpoldiff.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.poldiff
package_dir = $(dir $(subst .,/,$(package_name)))poldiff

wrappedjar_DATA = poldiff.jar
wrappedjardir = $(libdir)/setools

dist_noinst_DATA = $(srcdir)/../poldiff.i
BUILT_SOURCES = poldiff_wrap.c \
        poldiff_attrib_t.java \
        poldiff_avrule_t.java \
        poldiff_bool_t.java \
        poldiff_cat_t.java \
        poldiff_class_t.java \
        poldiff_common_t.java \
        poldiffConstants.java \
        poldiff_form_e.java \
        poldiff.java \
        poldiffJNI.java \
        poldiff_level_t.java \
        poldiff_range_t.java \
        poldiff_range_trans_t.java \
        poldiff_role_allow_t.java \
        poldiff_role_t.java \
        poldiff_role_trans_t.java \
        poldiff_stats_t.java \
        poldiff_terule_t.java \
        poldiff_t.java \
        poldiff_type_remap_entry_t.java \
        poldiff_type_t.java \
        poldiff_user_t.java

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include -I$(top_srcdir)/libpoldiff/include
AM_JFLAGS = @DEBUGJFLAGS@ @WARNJFLAGS@ \
	-classpath $(top_builddir)/libqpol/swig/java/qpol.jar:$(top_builddir)/libapol/swig/java/apol.jar
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @POLDIFF_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libpoldiff/src/poldiff.so

$(firstword $(BUILT_SOURCES)): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_JAVA_OPT) -package $(package_name) -o $@ \
	-I$(top_srcdir)/libpoldiff/include -I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/include \
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

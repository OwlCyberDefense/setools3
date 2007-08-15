wrappedso_DATA = libjpolsearch.so.@libpolsearch_version@
wrappedso_SONAME = @libpolsearch_jswig_soname@
short_name = libjpolsearch.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.polsearch
package_dir = $(dir $(subst .,/,$(package_name)))polsearch

wrappedjar_DATA = polsearch.jar
wrappedjardir = $(libdir)/setools

dist_noinst_DATA = $(srcdir)/../polsearch.i
BUILT_SOURCES = polsearch_wrap.cc \
	criterionVector.java \
	opVector.java \
	paramTypeVector.java \
	polsearch_bool_parameter.java \
	polsearch_bool_query.java \
	polsearch_criterion.java \
	polsearch_element_e.java \
	polsearch_level_parameter.java \
	polsearch_match_e.java \
	polsearch_number_parameter.java \
	polsearch_op_e.java \
	polsearch_parameter.java \
	polsearch_param_type_e.java \
	polsearch_proof.java \
	polsearch_query.java \
	polsearch_range_parameter.java \
	polsearch_regex_parameter.java \
	polsearch_string_expression_parameter.java \
	polsearch_result.java \
	polsearch_test_cond_e.java \
	polsearch_test.java \
	proofVector.java \
	resultVector.java \
	stringVector.java \
	testCondVector.java \
	testVector.java \
	SWIGTYPE_p_f_p_void__void.java \
	SWIGTYPE_p_std__type_info.java \
	polsearch.java \
	polsearchJNI.java \
	SWIGTYPE_p_void.java

AM_CXXFLAGS = @DEBUGCXXFLAGS@ @WARNCXXFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libpolsearch/include
AM_JFLAGS = @DEBUGJFLAGS@ @WARNJFLAGS@ \
	-classpath $(top_builddir)/libqpol/swig/java/qpol.jar:$(top_builddir)/libapol/swig/java/apol.jar:$(top_builddir)/libsefs/swig/java/sefs.jar
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @SEFS_LIB_FLAG@ @POLSEARCH_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libsefs/src/libsefs.so \
	$(top_builddir)/libpolsearch/src/polsearch.so

$(firstword $(BUILT_SOURCES)): $(dist_noinst_DATA)
	$(SWIG) -c++ $(SWIG_JAVA_OPT) -package $(package_name) -o $@ \
	-I$(top_srcdir)/libpolsearch/include -I$(top_srcdir)/libsefs/include \
	-I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/include \
	-I$(top_srcdir)/libqpol/swig -I$(top_srcdir)/libapol/swig \
	-I$(top_srcdir)/libsefs/swig $<

$(wordlist 2,$(words $(BUILT_SOURCES)), $(BUILT_SOURCES)): $(firstword $(BUILT_SOURCES))

$(wrappedso_DATA): $(filter %.cc, $(BUILT_SOURCES))
	$(CXX) -shared -o $@ $^ $(AM_CXXFLAGS) $(CXXFLAGS) $(SWIG_JAVA_CFLAGS) -DSWIGJAVA=1 $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

# Intentionally do not include SWIGTYPE_p_void.java below so that the
# Java compiler uses the one created in package
# com.tresys.setools.qpol instead of the one from package
# com.tresys.setools.polsearch.
java_files = $(filter-out SWIGTYPE_p_void.java, $(filter %.java, $(BUILT_SOURCES)))

classes = $(patsubst %.java, $(package_dir)/%.class, $(java_files))

# Because the Java compiler can generate multiple class files from the
# same source .java file, putting all of the classes below will result
# in repeated invocations of javac.  Therefore, an alternative is to
# just depend upon the first class file, and let the Java compiler
# create the rest of them.
$(firstword $(classes)): $(java_files)
	$(JAVAC) $(AM_JFLAGS) $(JAVAFLAGS) -d . $^

$(wordlist 2,$(words $(classes)),$(classes)): $(firstword $(classes))

$(wrappedjar_DATA): MANIFEST.MF

$(wrappedjar_DATA): $(classes)
	$(JAR) cfm $@ MANIFEST.MF $^

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(short_name)

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/$(short_name)

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(classes) $(wrappedso_DATA) $(wrappedjar_DATA) $(wrappedso_SONAME) $(short_name)

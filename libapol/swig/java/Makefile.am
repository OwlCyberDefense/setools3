wrappedso_DATA = libjapol.so.@libapol_version@
wrappedso_SONAME = @libapol_jswig_soname@
short_name = libjapol.so
wrappedsodir = $(libdir)

package_name = com.tresys.setools.apol
package_dir = $(dir $(subst .,/,$(package_name)))apol

wrappedjar_DATA = apol.jar
wrappedjardir = $(setoolsdir)

dist_noinst_DATA = $(srcdir)/../apol.i
BUILT_SOURCES = apol_wrap.c \
	apol_attr_query_t.java \
	apol_avrule_query_t.java \
	apol_bool_query_t.java \
	apol_cat_query_t.java \
	apol_class_query_t.java \
	apol_common_query_t.java \
	apol_cond_query_t.java \
	apolConstants.java \
	apol_constraint_query_t.java \
	apol_context_t.java \
	apol_domain_trans_analysis_t.java \
	apol_domain_trans_result_t.java \
	apol_fs_use_query_t.java \
	apol_genfscon_query_t.java \
	apol_infoflow_analysis_t.java \
	apol_infoflow_graph_t.java \
	apol_infoflow_result_t.java \
	apol_infoflow_step_t.java \
	apol_infoflow_t.java \
	apol_ip_t.java \
	apol_isid_query_t.java \
	apol.java \
	apolJNI.java \
	apol_level_query_t.java \
	apol_mls_level_t.java \
	apol_mls_range_t.java \
	apol_netifcon_query_t.java \
	apol_nodecon_query_t.java \
	apol_perm_query_t.java \
	apol_policy_path_t.java \
	apol_policy_path_type_e.java \
	apol_policy_t.java \
	apol_portcon_query_t.java \
	apol_range_trans_query_t.java \
	apol_relabel_analysis_t.java \
	apol_relabel_result_pair_t.java \
	apol_relabel_result_t.java \
	apol_role_allow_query_t.java \
	apol_role_query_t.java \
	apol_role_trans_query_t.java \
	apol_string_vector_t.java \
	apol_terule_query_t.java \
	apol_type_query_t.java \
	apol_types_relation_access_t.java \
	apol_types_relation_analysis_t.java \
	apol_types_relation_result_t.java \
	apol_user_query_t.java \
	apol_validatetrans_query_t.java \
	apol_vector_t.java \
	SWIGTYPE_p_unsigned_int.java \
	SWIGTYPE_p_void.java

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include
AM_JFLAGS = @DEBUGJFLAGS@ @WARNJFLAGS@ \
	-classpath $(top_builddir)/libqpol/swig/java/qpol.jar
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so

$(firstword $(BUILT_SOURCES)): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) $(SWIG_JAVA_OPT) -package $(package_name) -o $@ -I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/swig $<

$(wordlist 2,$(words $(BUILT_SOURCES)), $(BUILT_SOURCES)): $(firstword $(BUILT_SOURCES))

$(wrappedso_DATA): $(filter %.c, $(BUILT_SOURCES))
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_JAVA_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

# Intentionally do not include SWIGTYPE_p_void.java below so that the
# Java compiler uses the one created in package
# com.tresys.setools.qpol instead of the one from package
# com.tresys.setools.apol.
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
	$(mkdir_p) $(javadir) && cd $(javadir) && $(LN_S) -f $(wrappedjardir)/$(wrappedjar_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/$(short_name)

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(classes) $(wrappedso_DATA) $(wrappedjar_DATA) $(wrappedso_SONAME) $(short_name)

wrappedso_DATA = libtpolsearch.so.@libpolsearch_version@
wrappedso_SONAME = @libpolsearch_tswig_soname@
short_name = libtpolsearch.so
wrappedsodir = $(libdir)/setools/polsearch

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../polsearch.i
BUILT_SOURCES = polsearch_wrap.cc

AM_CXXFLAGS = @DEBUGCXXFLAGS@ @WARNCXXFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libpolsearch/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libsefs/src/libsefs.so \
	$(top_builddir)/libpolsearch/src/libpolsearch.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) -c++ $(SWIG_TCL_OPT) -pkgversion @libpolsearch_version@ -o $@ \
	-I$(top_srcdir)/libpolsearch/include -I$(top_srcdir)/libsefs/include \
	-I$(top_srcdir)/libapol/include -I$(top_srcdir)/libapol/swig \
	-I$(top_srcdir)/libqpol/swig -I$(top_srcdir)/libsefs/swig $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CXX) -shared -o $@ $^ $(AM_CXXFLAGS) $(CXXFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(package_SCRIPTS): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | LD_LIBRARY_PATH=$(top_builddir)/libqpol/src:$(top_builddir)/libapol/src:$(top_builddir)/libsefs/src:$(top_builddir)/libpolsearch/src $(TCLSH_PROG)
	$(mkdir_p) polsearch
	cp $(wrappedso_DATA) $@ polsearch

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA) polsearch/$(wrappedso_DATA) polsearch/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)

wrappedso_DATA = _polsearch.so.@libpolsearch_version@
wrappedso_SONAME = @libpolsearch_pyswig_soname@
wrappedsodir = $(pkgpyexecdir)

wrappedpy_DATA = polsearch.py
wrappedpydir = $(pkgpythondir)

dist_noinst_DATA = $(srcdir)/../polsearch.i
BUILT_SOURCES = polsearch_wrap.cc

AM_CXXFLAGS = @DEBUGCXXFLAGS@ @WARNCXXFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libpolsearch/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @POLSEARCH_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libsefs/src/libsefs.so \
	$(top_builddir)/libpolsearch/src/libpolsearch.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) -c++ $(SWIG_PYTHON_OPT) -o $@ \
	-I$(top_srcdir)/libpolsearch/include -I$(top_srcdir)/libsefs/include \
	-I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/include \
	-I$(top_srcdir)/libqpol/swig -I$(top_srcdir)/libapol/swig -I$(top_srcdir)/libsefs/swig $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CXX) -shared -o $@ $^ $(AM_CXXFLAGS) $(CXXFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ _polsearch.so

$(wrappedpy_DATA): $(BUILT_SOURCES)

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) _polsearch.so

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/_polsearch.so

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedpy_DATA) $(wrappedso_SONAME) _polsearch.so polsearch.pyc

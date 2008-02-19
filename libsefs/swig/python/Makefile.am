wrappedso_DATA = _sefs.so.@libsefs_version@
wrappedso_SONAME = @libsefs_pyswig_soname@
wrappedsodir = $(pkgpyexecdir)

wrappedpy_DATA = sefs.py
wrappedpydir = $(pkgpythondir)

dist_noinst_DATA = $(srcdir)/../sefs.i
BUILT_SOURCES = sefs_wrap.cc

AM_CXXFLAGS = @DEBUGCXXFLAGS@ @WARNCXXFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libsefs/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ @PYTHON_LDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @SEFS_LIB_FLAG@ @XML_LIBS@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libsefs/src/libsefs.so

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) -c++ $(SWIG_PYTHON_OPT) -o $@ \
	-I$(top_srcdir)/libsefs/include -I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/include \
	-I$(top_srcdir)/libqpol/swig -I$(top_srcdir)/libapol/swig $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CXX) -shared -o $@ $^ $(AM_CXXFLAGS) $(CXXFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ _sefs.so

$(wrappedpy_DATA): $(BUILT_SOURCES)

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) _sefs.so

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/_sefs.so

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedpy_DATA) $(wrappedso_SONAME) _sefs.so sefs.pyc

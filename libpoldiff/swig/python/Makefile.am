wrappedso_DATA = _poldiff.so.@libpoldiff_version@
wrappedso_SONAME = @libpoldiff_pyswig_soname@
wrappedsodir = $(pkgpyexecdir)

wrappedpy_DATA = poldiff.py
wrappedpydir = $(pkgpythondir)

dist_noinst_DATA = $(srcdir)/../poldiff.i
BUILT_SOURCES = poldiff_wrap.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libpoldiff/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @POLDIFF_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libpoldiff/src/libpoldiff.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ \
	-I$(top_srcdir)/libpoldiff/include -I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/include \
	-I$(top_srcdir)/libqpol/swig -I$(top_srcdir)/libapol/swig $<
$<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ _poldiff.so

$(wrappedpy_DATA): $(BUILT_SOURCES)

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) _poldiff.so

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/_poldiff.so

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedpy_DATA) $(wrappedso_SONAME) _poldiff.so poldiff.pyc

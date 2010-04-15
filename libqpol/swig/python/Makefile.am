wrappedso_DATA = _qpol.so.@libqpol_version@
wrappedso_SONAME = @libqpol_pyswig_soname@
wrappedsodir = $(pkgpyexecdir)

pkgpython_PYTHON = __init__.py
wrappedpy_DATA = qpol.py $(pkgpython_PYTHON)
wrappedpydir = $(pkgpyexecdir)

dist_noinst_DATA = $(srcdir)/../qpol.i
BUILT_SOURCES = qpol_wrap.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	-I$(top_builddir) -fpic \
	-I$(top_srcdir)/libqpol/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ @QPOL_LIB_FLAG@ @PYTHON_LDFLAGS@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ _qpol.so

$(wrappedpy_DATA): $(BUILT_SOURCES)

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) _qpol.so

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/_qpol.so

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) qpol.py $(wrappedso_SONAME) _qpol.so qpol.pyc

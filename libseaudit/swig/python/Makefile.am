wrappedso_DATA = _seaudit.so.@libseaudit_version@
wrappedso_SONAME = @libseaudit_pyswig_soname@
wrappedsodir = $(pkgpyexecdir)

wrappedpy_DATA = seaudit.py
wrappedpydir = $(pkgpythondir)

dist_noinst_DATA = $(srcdir)/../seaudit.i
BUILT_SOURCES = seaudit_wrap.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libseaudit/include -D__attribute__\(x\)=''
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @SEAUDIT_LIB_FLAG@ @XML_LIBS@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libseaudit/src/libseaudit.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ \
	-I$(top_srcdir)/libseaudit/include -I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/include \
	-I$(top_srcdir)/libqpol/swig -I$(top_srcdir)/libapol/swig $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_PYTHON_CPPFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ _seaudit.so

$(wrappedpy_DATA): $(BUILT_SOURCES)

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) _seaudit.so

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/_seaudit.so

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedpy_DATA) $(wrappedso_SONAME) _seaudit.so seaudit.pyc

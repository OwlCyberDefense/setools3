wrappedso_DATA = libtqpol.so.@libqpol_version@
wrappedso_SONAME = @libqpol_tswig_soname@
short_name = libtqpol.so
wrappedsodir = $(libdir)/setools/qpol

package_DATA = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../qpol.i
BUILT_SOURCES = qpol_wrap.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	-I$(top_builddir) -fpic \
	-I$(top_srcdir)/libqpol/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_TCL_OPT) -pkgversion @libqpol_version@ -o $@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(package_DATA): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | $(TCLSH_PROG) > $@

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(short_name)

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/$(short_name)

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA)

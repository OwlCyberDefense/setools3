wrappedso_DATA = libtapol.so.@libapol_version@
wrappedso_SONAME = @libapol_tswig_soname@
short_name = libtapol.so
wrappedsodir = $(libdir)/setools/apol

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../apol.i
BUILT_SOURCES = apol_wrap.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_TCL_OPT) -pkgversion @libapol_version@ -o $@ -I$(top_srcdir)/libapol/include -I$(top_srcdir)/libqpol/swig $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(package_SCRIPTS): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | $(TCLSH_PROG) > $@
	$(mkdir_p) apol
	cp $(wrappedso_DATA) $@ apol

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(wrappedso_SONAME)
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) $(short_name)

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_SONAME) $(DESTDIR)$(wrappedsodir)/$(short_name)

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA) apol/$(wrappedso_DATA) apol/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)
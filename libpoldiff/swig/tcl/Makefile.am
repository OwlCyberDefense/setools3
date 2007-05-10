wrappedso_DATA = libtpoldiff.so.@libpoldiff_version@
wrappedso_SONAME = @libpoldiff_tswig_soname@
short_name = libtpoldiff.so
wrappedsodir = $(libdir)/setools/poldiff

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../poldiff.i
BUILT_SOURCES = poldiff_wrap.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libpoldiff/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libpoldiff/src/libpoldiff.so

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_TCL_OPT) -pkgversion @libpoldiff_version@ -o $@ -I$(top_srcdir)/libpoldiff/include -I$(top_srcdir)/libapol/include -I$(top_srcdir)/libapol/swig -I$(top_srcdir)/libqpol/swig $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

$(package_SCRIPTS): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | LD_LIBRARY_PATH=$(top_builddir)/libqpol/src:$(top_builddir)/libapol/src:$(top_builddir)/libpoldiff/src $(TCLSH_PROG)
	$(mkdir_p) poldiff
	cp $(wrappedso_DATA) $@ poldiff

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA) poldiff/$(wrappedso_DATA) poldiff/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)

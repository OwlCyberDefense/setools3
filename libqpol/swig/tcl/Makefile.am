wrappedso_DATA = libtqpol.so.@libqpol_version@
wrappedso_SONAME = @libqpol_tswig_soname@
short_name = libtqpol.so
wrappedsodir = $(libdir)/setools/qpol

package_SCRIPTS = pkgIndex.tcl
packagedir = $(wrappedsodir)

dist_noinst_DATA = $(srcdir)/../qpol.i
BUILT_SOURCES = qpol_wrap.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	-I$(top_builddir) -fpic \
	-I$(top_srcdir)/libqpol/include
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ @QPOL_LIB_FLAG@ @TCL_LIB_SPEC@

$(BUILT_SOURCES): $(dist_noinst_DATA) $(DEPENDENCIES)
	$(SWIG) $(SWIG_TCL_OPT) -pkgversion @libqpol_version@ -o $@ $<

$(wrappedso_DATA): $(BUILT_SOURCES)
	$(CC) -shared -o $@ $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_TCL_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ $(wrappedso_SONAME)
	$(LN_S) -f $@ $(short_name)

libdirs = $(top_builddir)/libqpol/src

$(package_SCRIPTS): $(wrappedso_DATA)
	echo "pkg_mkIndex . $^" | LD_LIBRARY_PATH=$(top_builddir)/libqpol/src $(TCLSH_PROG)
	chmod 644 $@
	$(mkdir_p) qpol
	cp $(wrappedso_DATA) $@ qpol

MOSTLYCLEANFILES = $(BUILT_SOURCES) $(wrappedso_DATA) $(wrappedso_SONAME) $(short_name) $(package_DATA) qpol/$(wrappedso_DATA) qpol/$(package_SCRIPTS)

CLEANFILES = $(package_SCRIPTS)

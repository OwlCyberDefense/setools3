lib_LIBRARIES = libapol_tcl.a
setoolsdir = @setoolsdir@

libapol_tcl_so_DATA = libapol_tcl.so.@libapol_version@
libapol_tcl_sodir = $(libdir)/setools/apol_tcl

package_SCRIPTS = pkgIndex.tcl
packagedir = $(libapol_tcl_sodir)

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@SEFS_CFLAGS@ @APOL_CFLAGS@ @QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(top_srcdir)/libapol/include @TCL_INCLUDES@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @TCL_LIB_FLAG@

libapol_tcl_a_SOURCES = apol_tcl.c

libapol_tcl_a_DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so

libapol_tcl_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libapol_tcl_a_SOURCES)))

$(libapol_tcl_so_DATA): $(libapol_tcl_so_OBJS)
	$(CC) -shared -o $@ $^ $(AM_LDFLAGS) $(LDFLAGS)

$(package_SCRIPTS): $(libapol_tcl_so_DATA)
	echo "pkg_mkIndex . $^" | $(TCLSH_PROG) > $@
	$(mkdir_p) apol_tcl
	cp $< $@ apol_tcl

MOSTLYCLEANFILES = $(libapol_tcl_so_DATA)

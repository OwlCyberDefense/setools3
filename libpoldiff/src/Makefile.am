lib_LIBRARIES = libpoldiff.a

poldiffso_DATA = @libpoldiff_soname@
poldiffsodir = $(libdir)

AM_CFLAGS = -fpic -I$(srcdir)/../include @APOL_CFLAGS@ @QPOL_CFLAGS@

libpoldiff_a_SOURCES = \
	poldiff.c \
	class_diff.c \
	poldiff_internal.h

libpoldiff_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libpoldiff_a_SOURCES)))
LIBPOLDIFF_SONAME = @libpoldiff_soname@

dist_noinst_DATA = libpoldiff.map

$(poldiffso_DATA): $(libpoldiff_so_OBJS) libpoldiff.map
	$(CC) -shared -o $@ $(libpoldiff_so_OBJS) $(LDFLAGS) -Wl,-soname,$(LIBPOLDIFF_SONAME),--version-script=$(srcdir)/libpoldiff.map,-z,defs -lqpol -lapol -L$(top_builddir)/libqpol/src -L$(top_builddir)/libapol/src
	$(LN_S) -f $@ libpoldiff.so

install-data-hook:
	cd $(DESTDIR)$(poldiffsodir) && $(LN_S) -f $(poldiffso_DATA) libpoldiff.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libpoldiff.so $(poldiffso_DATA)

uninstall-local:
	-rm -rf $(poldiffsodir)/libpoldiff.so

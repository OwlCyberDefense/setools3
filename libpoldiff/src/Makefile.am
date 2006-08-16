lib_LIBRARIES = libpoldiff.a
poldiffso_DATA = libpoldiff.so
poldiffsodir = $(libdir)

AM_CFLAGS = -fpic -I$(srcdir)/../include @APOL_CFLAGS@ @QPOL_CFLAGS@

libpoldiff_a_SOURCES = \
	poldiff.c \
	class_diff.c \
	poldiff_internal.h

libpoldiff_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libpoldiff_a_SOURCES)))
LIBPOLDIFF_SONAME = @libpoldiff_soname@

noinst_DATA = libpoldiff.map

libpoldiff.so: $(libpoldiff_so_OBJS) libpoldiff.map
	$(CC) -shared -o $@ $(libpoldiff_so_OBJS) $(LDFLAGS) -Wl,-soname,$(LIBPOLDIFF_SONAME),--version-script=$(srcdir)/libpoldiff.map,-z,defs -lqpol -lapol -L$(top_srcdir)/libqpol/src -L$(top_srcdir)/libapol/src
	$(LN_S) -f $@ $(LIBPOLDIFF_SONAME)

install-data-hook:
	cd $(poldiffsodir) && $(LN_S) -f $(poldiffso_DATA) libpoldiff.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libpoldiff.so

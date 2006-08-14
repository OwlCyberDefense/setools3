lib_LIBRARIES = libpoldiff.a
poldiffso_DATA = libpoldiff.so
poldiffsodir = $(libdir)

AM_CFLAGS = -fpic -I$(srcdir)/../include -I$(top_srcdir)/libapol/include \
	-I$(top_srcdir)/libqpol/include

libpoldiff_a_SOURCES = \
	poldiff.c

libpoldiff_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libpoldiff_a_SOURCES)))
LIBPOLDIFF_SONAME = @libpoldiff_soname@

noinst_DATA = libpoldiff.map

libpoldiff.so: $(libpoldiff_so_OBJS) libpoldiff.map
	$(CC) -shared -o $@ $(libpoldiff_so_OBJS) $(LDFLAGS) -Wl,-soname,$(LIBPOLDIFF_SONAME),--version-script=$(srcdir)/libpoldiff.map,-z,defs -lqpol -lapol -L$(top_srcdir)/libqpol/src -L$(top_srcdir)/libapol/src
	ln -sf $@ $(LIBPOLDIFF_SONAME)

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libpoldiff.so

lib_LIBRARIES = libsefs.a

sefsso_DATA = libsefs.so.@libsefs_version@
sefssodir = $(libdir)

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ -I$(srcdir)/../include -fpic
AM_CXXFLAGS = $(AM_CFLAGS)
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

noinst_LIBRARIES = libsqlite.a
libsqlite_a_CFLAGS = -fPIC -w -O2
libsqlite_a_SOURCES = \
	sqlite/attach.c sqlite/auth.c sqlite/btree.c sqlite/build.c sqlite/date.c \
	sqlite/delete.c sqlite/expr.c sqlite/func.c sqlite/hash.c sqlite/insert.c sqlite/legacy.c \
	sqlite/main.c sqlite/opcodes.c sqlite/os_mac.c sqlite/os_unix.c sqlite/os_win.c sqlite/pager.c \
	sqlite/parse.c sqlite/pragma.c sqlite/printf.c sqlite/random.c sqlite/select.c sqlite/table.c \
	sqlite/tokenize.c sqlite/trigger.c sqlite/update.c sqlite/utf.c sqlite/util.c sqlite/vacuum.c \
	sqlite/vdbeapi.c sqlite/vdbeaux.c sqlite/vdbe.c sqlite/vdbemem.c sqlite/where.c \
	sqlite/btree.h sqlite/os.h sqlite/pager.h sqlite/vdbe.h \
	sqlite/hash.h sqlite/os_mac.h sqlite/parse.h sqlite/vdbeInt.h \
	sqlite/opcodes.h sqlite/os_unix.h sqlite/sqlite3.h \
	sqlite/os_common.h sqlite/os_win.h sqlite/sqliteInt.h

libsefs_a_LIBADD = libsqlite_a-*.o
libsefs_a_SOURCES = \
	entry.cc \
	fcfile.cc \
	fclist.cc \
	filesystem.cc \
	new_ftw.c new_ftw.h \
	query.cc \
	sefs_internal.hh \
	util.c

libsefs_a_DEPENDENCIES = \
	libsqlite.a \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libqpol/src/libqpol.so

libsefs_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libsefs_a_SOURCES))) $(patsubst %.cc,%.o,$(filter %.cc,$(libsefs_a_SOURCES)))
libsefs_so_OBJS += $(patsubst %.c,libsqlite_a-%.o,$(filter %.c,$(notdir $(libsqlite_a_SOURCES))))

LIBSEFS_SONAME = @libsefs_soname@

dist_noinst_DATA = libsefs.map

$(sefsso_DATA): $(libsefs_so_OBJS) libsefs.map
	$(CXX) -shared -o $@ $(libsefs_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBSEFS_SONAME),--version-script=$(srcdir)/libsefs.map,-z,defs $(top_builddir)/libqpol/src/libqpol.so $(top_builddir)/libapol/src/libapol.so @SELINUX_LIB_FLAG@ -lselinux -lsepol
	$(LN_S) -f $@ @libsefs_soname@
	$(LN_S) -f $@ libsefs.so

libsefs.so: $(sefso_DATA)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

install-data-hook:
	cd $(DESTDIR)$(sefssodir) && $(LN_S) -f $(sefsso_DATA) @libsefs_soname@
	cd $(DESTDIR)$(sefssodir) && $(LN_S) -f $(sefsso_DATA) libsefs.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libsefs.so @libsefs_soname@ $(sefsso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(sefssodir)/$(sefsso_DATA) $(DESTDIR)$(sefssodir)/@libsefs_soname@ $(DESTDIR)$(sefssodir)/libsefs.so

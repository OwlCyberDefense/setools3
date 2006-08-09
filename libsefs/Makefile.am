# libsefs

lib_LIBRARIES = libsefs.a

sefsso_DATA = @libsefs_soname@
sefssodir = $(libdir)

AM_CFLAGS = -fPIC @QPOL_CFLAGS@ @APOL_CFLAGS@

libsefs_a_SOURCES = \
	fsdata.c fsdata.h \
	file_contexts.c file_contexts.h \
	fshash.c fshash.h

noinst_LIBRARIES = libsqlite.a
libsqlite_a_SOURCES =
libsqlite_a_CFLAGS = -fPIC -w -O2
if WANT_LIBSEFS
libsqlite_a_SOURCES += \
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
libsefs_a_LIBADD=libsqlite_a-*.o
endif

libsefs_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libsefs_a_SOURCES)))
if WANT_LIBSEFS
libsefs_so_OBJS += $(patsubst %.c,libsqlite_a-%.o,$(filter %.c,$(notdir $(libsqlite_a_SOURCES))))
endif

LIBSEFS_SONAME = @libsefs_soname@

$(sefsso_DATA): $(libsefs_so_OBJS)
	$(CC) -shared -o $@ $(libsefs_so_OBJS) $(LDFLAGS) -Wl,-soname,$(LIBSEFS_SONAME) -L$(top_srcdir)/libapol/src -L$(top_srcdir)/libqpol/src -lapol -lqpol
	$(LN_S) -f $@ libsefs.so

install-data-hook:
	cd $(sefssodir) && $(LN_S) -f $(sefsso_DATA) libsefs.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libsefs.so $(sefsso_DATA)

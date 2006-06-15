# libsefs 

lib_LIBRARIES = libsefs.a

AM_CFLAGS = -fPIC -I$(top_srcdir)/libqpol/include -I$(top_srcdir)/libapol

libsefs_a_SOURCES = \
	fsdata.c fsdata.h
	file_contexts.c file_contexts.h \
	fshash.c fshash.h

if WANT_LIBSEFS
libsefs_a_SOURCES += \
	sqlite/attach.c sqlite/auth.c sqlite/btree.c sqlite/build.c sqlite/date.c \
	sqlite/delete.c sqlite/expr.c sqlite/func.c sqlite/hash.c sqlite/insert.c sqlite/legacy.c \
	sqlite/main.c sqlite/opcodes.c sqlite/os_mac.c sqlite/os_unix.c sqlite/os_win.c sqlite/pager.c \
	sqlite/parse.c sqlite/pragma.c sqlite/printf.c sqlite/random.c sqlite/select.c sqlite/table.c \
	sqlite/tokenize.c sqlite/trigger.c sqlite/update.c sqlite/utf.c sqlite/util.c sqlite/vacuum.c \
	sqlite/vdbeapi.c sqlite/vdbeaux.c sqlite/vdbe.c sqlite/vdbemem.c sqlite/where.c
endif


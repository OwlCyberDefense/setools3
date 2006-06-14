sepol_srcdir = @sepol_srcdir@

lib_LIBRARIES = libqpol.a
qpolso_DATA = libqpol.so
qpolsodir = $(libdir)

AM_YFLAGS = -d
BUILT_SOURCES = policy_parse.h

AM_CFLAGS = -I$(srcdir)/../include -I$(sepol_srcdir)/include -fpic
libqpol_a_SOURCES = \
	avrule_query.c \
	bool_query.c \
	class_perm_query.c \
	cond_query.c \
	context_query.c \
	debug.h \
	expand.c \
	fs_use_query.c \
	genfscon_query.c \
	isid_query.c \
	iterator.c \
	iterator_internal.h \
	mls_query.c \
	mlsrule_query.c \
	module_compiler.c \
	netifcon_query.c \
	nodecon_query.c \
	policy.c \
	policy_extend.c \
	policy_parse.h \
	policy_query.c \
	portcon_query.c \
	queue.c \
	rbacrule_query.c \
	role_query.c \
	terule_query.c \
	type_query.c \
	user_query.c \
	policy_parse.y policy_scan.l
libqpol_a_DEPENDENCIES = $(srcdir)/tmp_sepol
libqpol_a_LIBADD = $(srcdir)/tmp_sepol/*.o

libqpol_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libqpol_a_SOURCES))) policy_parse.o policy_scan.o

$(srcdir)/tmp_sepol: $(sepol_srcdir)/src/libsepol.a
	mkdir -p $@
	rm -f $@/*
	cp $< $@
	(cd $@; ar x libsepol.a)

libqpol.so: $(srcdir)/tmp_sepol $(libqpol_so_OBJS)
	$(CC) -shared -o $@ $(libqpol_so_OBJS) $(LDFLAGS) -Wl,-soname,$(SONAME),--version-script=$(srcdir)/libqpol.map,-z,defs -Wl,--whole-archive $(sepol_srcdir)/src/libsepol.a -Wl,--no-whole-archive -lselinux  

CLEANFILES = $(BUILD_SOURCES) policy_scan.c policy_parse.c

clean-local:
	-rm -rf $(srcdir)/tmp_sepol

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libqpol.so

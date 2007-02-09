sepol_srcdir = @sepol_srcdir@

lib_LIBRARIES = libqpol.a
qpolso_DATA = @libqpol_soname@
qpolsodir = $(libdir)

tmp_sepol = ./tmp_sepol

AM_YFLAGS = -d
BUILT_SOURCES = policy_parse.h

# search in sepol_srcdir/include before system's sepol directory
AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ \
	-I$(srcdir)/../include -I$(sepol_srcdir)/../include @SELINUX_CFLAGS@ -fpic
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

libqpol_a_SOURCES = \
	avrule_query.c \
	bool_query.c \
	class_perm_query.c \
	cond_query.c \
	constraint_query.c \
	context_query.c \
	expand.c \
	fs_use_query.c \
	genfscon_query.c \
	isid_query.c \
	iterator.c \
	iterator_internal.h \
	mls_query.c \
	mlsrule_query.c \
	module.c \
	module_compiler.c \
	module_compiler.h \
	netifcon_query.c \
	nodecon_query.c \
	policy.c \
	policy_extend.c \
	policy_parse.h \
	portcon_query.c \
	qpol_internal.h \
	queue.c \
	queue.h \
	rbacrule_query.c \
	role_query.c \
	syn_rule_internal.h \
	syn_rule_query.c \
	terule_query.c \
	type_query.c \
	user_query.c \
	util.c \
	policy_parse.y policy_scan.l
libqpol_a_DEPENDENCIES = $(tmp_sepol)
libqpol_a_LIBADD = $(tmp_sepol)/*.o

libqpol_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libqpol_a_SOURCES))) policy_parse.o policy_scan.o
LIBQPOL_SONAME = @libqpol_soname@

dist_noinst_DATA = libqpol.map

$(tmp_sepol): $(sepol_srcdir)/libsepol.a
	mkdir -p $@
	rm -f $@/*
	cp $< $@
	(cd $@; ar x libsepol.a)

$(qpolso_DATA): $(tmp_sepol) $(libqpol_so_OBJS) libqpol.map
	$(CC) -shared -o $@ $(libqpol_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBQPOL_SONAME),--version-script=$(srcdir)/libqpol.map,-z,defs -Wl,--whole-archive $(sepol_srcdir)/libsepol.a -Wl,--no-whole-archive @SELINUX_LIB_FLAG@ -lselinux -lsepol
	$(LN_S) -f $@ libqpol.so

libqpol.so: $(qpolso_DATA)

install-data-hook:
	cd $(DESTDIR)$(qpolsodir) && $(LN_S) -f $(qpolso_DATA) libqpol.so

CLEANFILES = policy_parse.h policy_scan.c policy_parse.c

clean-local:
	-rm -rf $(tmp_sepol)

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libqpol.so $(qpolso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(qpolsodir)/$(qpolso_DATA)

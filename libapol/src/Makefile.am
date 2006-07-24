lib_LIBRARIES = libapol.a

apolso_DATA = libapol.so
apolsodir = $(libdir)

AM_CFLAGS = -fpic -I$(top_srcdir)/libqpol/include -I$(srcdir)/../include \
	-DAPOL_INSTALL_DIR='"${apol_install_dir}"' \
	-DAPOL_HELP_DIR='"${apol_help_dir}"' \
	-DLIBAPOL_POLICY_INSTALL_DIR='"@selinux_policy_dir@/policy"' \
	-DLIBAPOL_DEFAULT_POLICY='"@selinux_default_policy@"'

libapol_a_SOURCES = \
	avl-util.c \
	avrule-query.c \
	bool-query.c \
	class-perm-query.c \
	condrule-query.c \
	constraint-query.c \
	context-query.c \
	domain-trans-analysis.c \
	fscon-query.c \
	infoflow-analysis.c \
	isid-query.c \
	mls-query.c \
	netcon-query.c \
	perm-map.c \
	poldiff.c \
	policy.c \
	policy-query.c \
	queue.c \
	rangetrans-query.c \
	rbacrule-query.c \
	relabel-analysis.c \
	render.c \
	role-query.c \
	terule-query.c \
	type-query.c \
	user-query.c \
	util.c \
	vector.c \
	policy-query-internal.h queue.h

libapol_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libapol_a_SOURCES)))
LIBAPOL_SONAME = @libapol_soname@

noinst_DATA = libapol.map

libapol.so: $(libqpol_so_OBJS) libapol.map
	$(CC) -shared -o $@ $(libapol_so_OBJS) $(LDFLAGS) -Wl,-soname,$(LIBAPOL_SONAME),--version-script=$(srcdir)/libapol.map,-z,defs -lqpol -L$(top_srcdir)/libqpol/src
	ln -sf $@ $(LIBAPOL_SONAME)

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libapol.so

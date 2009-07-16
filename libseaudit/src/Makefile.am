lib_LIBRARIES = libseaudit.a

seauditso_DATA = libseaudit.so.@libseaudit_version@
seauditsodir = $(libdir)

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@APOL_CFLAGS@ @QPOL_CFLAGS@ @XML_CFLAGS@ -I$(srcdir)/../include -fpic
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

libseaudit_a_SOURCES = \
	avc_message.c \
	bool_message.c \
	filter.c filter-internal.c filter-internal.h \
	load_message.c \
	log.c \
	message.c \
	model.c \
	parse.c \
	report.c \
	sort.c \
	util.c \
	seaudit_internal.h

libseaudit_a_DEPENDENCIES = $(top_builddir)/libapol/src/libapol.so

libseaudit_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libseaudit_a_SOURCES)))
LIBSEAUDIT_SONAME = @libseaudit_soname@

dist_noinst_DATA = libseaudit.map

$(seauditso_DATA): $(libseaudit_so_OBJS) libseaudit.map
	$(CC) -shared -o $@ $(libseaudit_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBSEAUDIT_SONAME),--version-script=$(srcdir)/libseaudit.map,-z,defs $(top_builddir)/libqpol/src/libqpol.so $(top_builddir)/libapol/src/libapol.so $(XML_LIBS) -lselinux
	$(LN_S) -f $@ @libseaudit_soname@
	$(LN_S) -f $@ libseaudit.so

libseaudit.so: $(seauditso_DATA)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

install-data-hook:
	cd $(DESTDIR)$(seauditsodir) && $(LN_S) -f $(seauditso_DATA) @libseaudit_soname@
	cd $(DESTDIR)$(seauditsodir) && $(LN_S) -f $(seauditso_DATA) libseaudit.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libseaudit.so @libseaudit_soname@ $(seauditso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(seauditsodir)/$(seauditso_DATA) $(DESTDIR)$(seauditsodir)/@libseaudit_soname@ $(DESTDIR)$(seauditsodir)/libseaudit.so

lib_LIBRARIES = libsefs.a

sefsso_DATA = libsefs.so.@libsefs_version@
sefssodir = $(libdir)

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SQLITE3_CFLAGS@ -I$(srcdir)/../include -fpic
AM_CXXFLAGS = @DEBUGCXXFLAGS@ @WARNCXXFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SQLITE3_CFLAGS@ -I$(srcdir)/../include -fpic
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

libsefs_a_SOURCES = \
	db.cc \
	entry.cc \
	fcfile.cc \
	fclist.cc \
	filesystem.cc \
	new_ftw.c new_ftw.h \
	query.cc \
	sefs_internal.hh \
	util.c

libsefs_a_DEPENDENCIES = \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libqpol/src/libqpol.so

libsefs_so_OBJS = $(patsubst %.c,%.o,$(filter %.c,$(libsefs_a_SOURCES))) $(patsubst %.cc,%.o,$(filter %.cc,$(libsefs_a_SOURCES)))
libsefs_so_OBJS += $(patsubst %.c,libsqlite_a-%.o,$(filter %.c,$(notdir $(libsqlite_a_SOURCES))))

LIBSEFS_SONAME = @libsefs_soname@

dist_noinst_DATA = libsefs.map

$(sefsso_DATA): $(libsefs_so_OBJS) libsefs.map
	$(CXX) -shared -o $@ $(libsefs_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBSEFS_SONAME),--version-script=$(srcdir)/libsefs.map,-z,defs $(top_builddir)/libqpol/src/libqpol.so $(top_builddir)/libapol/src/libapol.so $(SQLITE3_LIBS) -lselinux -lsepol
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

lib_LIBRARIES = libpolsearch.a

polsearchso_DATA = libpolsearch.so.@libpolsearch_version@
polsearchsodir = $(libdir)

AM_CXXFLAGS = @DEBUGCXXFLAGS@ @WARNCXXFLAGS@ @PROFILECFLAGS@ \
	@SEFS_CFLAGS@ @APOL_CFLAGS@ @QPOL_CFLAGS@ -I$(srcdir)/../include -fpic
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

libpolsearch_a_SOURCES = \
	bool_parameter.cc \
	bool_query.cc \
	criterion.cc \
	level_parameter.cc \
	number_parameter.cc \
	parameter.cc \
	polsearch.cc \
	polsearch_internal.hh \
	proof.cc \
	query.cc \
	range_parameter.cc \
	regex_parameter.cc \
	result.cc \
	string_expression_parameter.cc \
	test.cc \
	util.cc

libpolsearch_a_DEPENDENCIES = \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libsefs/src/libsefs.so

libpolsearch_so_OBJS = $(patsubst %.cc,%.o,$(filter %.cc,$(libpolsearch_a_SOURCES)))
LIBPOLSEARCH_SONAME = @libpolsearch_soname@

dist_noinst_DATA = libpolsearch.map

$(polsearchso_DATA): $(libpolsearch_so_OBJS) libpolsearch.map
	$(CXX) -shared -o $@ $(libpolsearch_so_OBJS) $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(LIBPOLSEARCH_SONAME),--version-script=$(srcdir)/libpolsearch.map,-z,defs $(top_builddir)/libqpol/src/libqpol.so $(top_builddir)/libapol/src/libapol.so $(top_builddir)/libsefs/src/libsefs.so
	$(LN_S) -f $@ @libpolsearch_soname@
	$(LN_S) -f $@ libpolsearch.so

libpolsearch.so: $(polsearchso_DATA)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

install-data-hook:
	cd $(DESTDIR)$(polsearchsodir) && $(LN_S) -f $(polsearchso_DATA) @libpolsearch_soname@
	cd $(DESTDIR)$(polsearchsodir) && $(LN_S) -f $(polsearchso_DATA) libpolsearch.so

mostlyclean-local:
	-rm -rf *.gcno *.gcda *.gprof *.gcov libpolsearch.so @libpolsearch_soname@ $(polsearchso_DATA)

uninstall-local:
	-rm -rf $(DESTDIR)$(polsearchsodir)/$(polsearchso_DATA) $(DESTDIR)$(polsearchsodir)/@libpolsearch_soname@ $(DESTDIR)$(polsearchsodir)/libpolsearch.so

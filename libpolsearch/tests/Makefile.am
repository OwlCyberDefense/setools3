TESTS = libpolsearch-tests
check_PROGRAMS = libpolsearch-tests

libpolsearch_tests_SOURCES = \
	bool_query-tests.hh \
	bool_query-tests.cc \
	libpolsearch-tests.cc

AM_CXXFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@ @POLSEARCH_CFLAGS@

AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLSEARCH_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libpolsearch_tests_DEPENDENCIES = ../src/libpolsearch.so
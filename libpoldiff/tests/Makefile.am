TESTS = libpoldiff-tests
check_PROGRAMS = libpoldiff-tests

libpoldiff_tests_SOURCES = \
	components-tests.c components-tests.h \
	libpoldiff-tests.c libpoldiff-tests.h \
	mls-tests.c mls-tests.h \
	nomls-tests.c nomls-tests.h \
	policy-defs.h \
	rules-tests.c rules-tests.h

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @POLDIFF_CFLAGS@

AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libpoldiff_tests_DEPENDENCIES = ../src/libpoldiff.so

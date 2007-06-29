TESTS = libpoldiff-tests
check_PROGRAMS = libpoldiff-tests

libpoldiff_tests_SOURCES = \
	components-tests.c components-tests.h \
	libpoldiff-tests.c libpoldiff-tests.h \
	mls-tests.c mls-tests.h \
	nomls-tests.c nomls-tests.h \
	policy-defs.h \
	rules-tests.c rules-tests.h

POLICY_ROOT = /home/paul/testing-policies/setools-3.2/sediff

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @POLDIFF_CFLAGS@ -I/usr/local/include \
	-DPOLICY_ROOT='"$(POLICY_ROOT)"'

AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ -L/usr/local/lib

LDADD = @SELINUX_LIB_FLAG@ @POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ -lcunit

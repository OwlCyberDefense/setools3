TESTS = libapol-tests
check_PROGRAMS = libapol-tests

libapol_tests_SOURCES = \
	avrule-tests.c avrule-tests.h \
	dta-tests.c dta-tests.h \
	policy-21-tests.c policy-21-tests.h \
	terule-tests.c terule-tests.h \
	libapol-tests.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@

AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libapol_tests_DEPENDENCIES = ../src/libapol.so


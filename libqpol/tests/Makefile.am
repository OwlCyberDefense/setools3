TESTS = libqpol-tests
check_PROGRAMS = libqpol-tests

libqpol_tests_SOURCES = \
	capabilities-tests.c capabilities-tests.h \
	libqpol-tests.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@

AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libqpol_tests_DEPENDENCIES = ../src/libqpol.so

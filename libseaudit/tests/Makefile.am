TESTS = libseaudit-tests
check_PROGRAMS = libseaudit-tests

libseaudit_tests_SOURCES = \
	filters.c filters.h \
	parse_file.c parse_file.h \
	libseaudit-tests.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEAUDIT_CFLAGS@

AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @SEAUDIT_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libseaudit_tests_DEPENDENCIES = ../src/libseaudit.so

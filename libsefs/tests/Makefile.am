if DO_FUSE
  MAYBE_TESTS = libsefs-tests
endif

TESTS = $(MAYBE_TESTS)
check_PROGRAMS = libsefs-tests # fuse_non_mls

libsefs_tests_SOURCES = \
	libsefs-tests.cc

#fuse_non_mls_SOURCES = \
#	fuse_non_mls.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@

AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @SEFS_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @CUNIT_LIB_FLAG@

libsefs_tests_DEPENDENCIES = ../src/libsefs.so # fuse_non_mls

#fuse_non_mls_CFLAGS = $(AM_CFLAGS) @FUSE_CFLAGS@
#fuse_non_mls_LDADD = $(LDADD) @FUSE_LIBS@

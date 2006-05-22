bin_PROGRAMS = awish
awish_SOURCES = awish.c

AM_CFLAGS = -I$(top_srcdir)/libqpol/include @TCL_INCLUDE_SPEC@
AM_LDFLAGS = @TCL_LIB_SPEC@ @TK_LIB_SPEC@

LDADD = $(top_srcdir)/libapol/libapol-tcl.a $(top_srcdir)/libapol/libapol.a $(top_srcdir)/libqpol/src/libqpol.so @QPOL_LIB_FLAG@ @TCL_LIB_FLAG@ @TK_LIB_FLAG@

if WANT_LIBSEFS
awish_LDADD = $(LDADD) $(top_srcdir)/libsefs/libsefs.a
else
awish_LDADD = $(LDADD)
endif

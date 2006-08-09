bin_PROGRAMS = awish
awish_SOURCES = awish.c

AM_CFLAGS = @QPOL_CFLAGS@ @APOL_CFLAGS@ @TCL_INCLUDES@
AM_LDFLAGS = @TCL_LIB_SPEC@ @TK_LIB_SPEC@

LDADD = @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @TCL_LIB_FLAG@ @TK_LIB_FLAG@
awish_DEPENDENCIES = $(top_srcdir)/libapol-tcl/libapol-tcl.a $(top_srcdir)/libapol/src/libapol.so $(top_srcdir)/libqpol/src/libqpol.so

if WANT_LIBSEFS
awish_LDADD = $(top_srcdir)/libapol-tcl/libapol-tcl.a @SEFS_LIB_FLAG@ $(LDADD)
awish_DEPENDENCIES += $(top_srcdir)/libsefs/libsefs.so
else
awish_LDADD = $(top_srcdir)/libapol-tcl/libapol-tcl.a $(LDADD)
endif

$(top_srcdir)/libapol/libapol-tcl.a:
	$(MAKE) -C $(top_srcdir)/libapol-tcl $(notdir $@)

$(top_srcdir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_srcdir)/libapol $(notdir $@)

$(top_srcdir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_srcdir)/libqpol $(notdir $@)

$(top_srcdir)/libsefs/libsefs.so:
	$(MAKE) -C $(top_srcdir)/libsefs $(notdir $@)

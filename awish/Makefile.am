bin_PROGRAMS = awish
awish_SOURCES = awish.c

AM_CFLAGS = -I$(top_srcdir)/libqpol/include -I$(top_srcdir)/libapol/include @TCL_INCLUDES@
AM_LDFLAGS = @TCL_LIB_SPEC@ @TK_LIB_SPEC@

LDADD = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so @QPOL_LIB_FLAG@ @TCL_LIB_FLAG@ @TK_LIB_FLAG@
awish_DEPENDENCIES = $(top_srcdir)/libapol-tcl/libapol-tcl.a $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so

if WANT_LIBSEFS
awish_LDADD = $(top_srcdir)/libapol-tcl/libapol-tcl.a $(top_srcdir)/libsefs/libsefs.a $(LDADD)
awish_DEPENDENCIES += $(top_srcdir)/libsefs/libsefs.a
else
awish_LDADD = $(top_srcdir)/libapol-tcl/libapol-tcl.a $(LDADD)
endif

$(top_srcdir)/libapol/libapol-tcl.a:
	$(MAKE) -C $(top_srcdir)/libapol-tcl $(notdir $@)

$(top_srcdir)/libapol/libapol.a:
	$(MAKE) -C $(top_srcdir)/libapol $(notdir $@)

$(top_srcdir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_srcdir)/libqpol $(notdir $@)

$(top_srcdir)/libsefs/libsefs.a:
	$(MAKE) -C $(top_srcdir)/libsefs $(notdir $@)

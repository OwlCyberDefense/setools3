bin_PROGRAMS = awish
awish_SOURCES = awish.c

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @TCL_INCLUDES@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ @TCL_LIB_SPEC@ @TK_LIB_SPEC@

LDADD = @SELINUX_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @TCL_LIB_FLAG@ @TK_LIB_FLAG@
awish_DEPENDENCIES = $(top_builddir)/libapol-tcl/libapol-tcl.a $(top_builddir)/libapol/src/libapol.so $(top_builddir)/libqpol/src/libqpol.so

if WANT_LIBSEFS
awish_LDADD = $(top_builddir)/libapol-tcl/libapol-tcl.a @SEFS_LIB_FLAG@ $(LDADD)
awish_DEPENDENCIES += $(top_builddir)/libsefs/src/libsefs.so
else
awish_LDADD = $(top_builddir)/libapol-tcl/libapol-tcl.a $(LDADD)
endif


$(top_builddir)/libapol/libapol-tcl.a:
	$(MAKE) -C $(top_builddir)/libapol-tcl $(notdir $@)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

$(top_builddir)/libsefs/src/libsefs.so:
	$(MAKE) -C $(top_builddir)/libsefs/src $(notdir $@)

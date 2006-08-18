bin_PROGRAMS = sediff

AM_CFLAGS = @QPOL_CFLAGS@ @APOL_CFLAGS@ @POLDIFF_CFLAGS@

sediff_LDADD = @POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
sediff_CFLAGS = $(AM_CFLAGS)
sediff_DEPENDENCIES = $(top_builddir)/libpoldiff/src/libpoldiff.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libqpol/src/libqpol.so

sediff_SOURCES = sediff_cli.c

$(top_builddir)/libpoldiff/src/libpoldiff.so:
	$(MAKE) -C $(top_builddir)/libpoldiff/src $(notdir $@)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)


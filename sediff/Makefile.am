bin_PROGRAMS = sediff sediffx

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @POLDIFF_CFLAGS@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

sediff_LDADD = @SELINUX_LIB_FLAG@ @POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
sediffx_LDADD = -L/usr/lib -lgthread-2.0 -lglib-2.0 @SELINUX_LIB_FLAG@ @POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ \
        	@GTK_LIBS@ @GLADE_LIBS@ @XML_LIBS@

sediff_CFLAGS = $(AM_CFLAGS)
sediffx_CFLAGS = $(AM_CFLAGS) -pthread @GTK_CFLAGS@ @GLADE_CFLAGS@ 

sediffx_LDFLAGS = -pthread -rdynamic

sediff_DEPENDENCIES = $(top_builddir)/libpoldiff/src/libpoldiff.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libqpol/src/libqpol.so

sediff_SOURCES = sediff_cli.c

sediffx_SOURCES = sediff_find_window.c  sediff_rename_types.c  sediff_treemodel.c  utilgui.c sediff_gui.c

$(top_builddir)/libpoldiff/src/libpoldiff.so:
	$(MAKE) -C $(top_builddir)/libpoldiff/src $(notdir $@)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

setoolsdir = @setoolsdir@

dist_setools_DATA = sediff_help.txt sediffx.glade \
	sediffx.png sediffx-small.png

if BUILD_GUI
  MAYBE_SEDIFFX = sediffx
endif

bin_PROGRAMS = sediff $(MAYBE_SEDIFFX)

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @POLDIFF_CFLAGS@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @POLDIFF_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@

sediff_CFLAGS = $(AM_CFLAGS)
sediffx_CFLAGS = $(AM_CFLAGS) \
	@GTK_CFLAGS@ @PIXBUF_CFLAGS@ @GLADE_CFLAGS@ @GTHREAD_CFLAGS@

# need the -rdynamic flag below - glade uses dlopen() upon sediffx callbacks
sediffx_LDFLAGS = $(AM_LDFLAGS) \
	@GTK_LIBS@ @PIXBUF_LIBS@ @GLADE_LIBS@ @GTHREAD_LIBS@ @XML_LIBS@ \
	-rdynamic

DEPENDENCIES = $(top_builddir)/libpoldiff/src/libpoldiff.so \
	$(top_builddir)/libapol/src/libapol.so \
	$(top_builddir)/libqpol/src/libqpol.so

sediff_SOURCES = sediff_cli.c

#sediffx_SOURCES = \
#	sediff_find_window.c sediff_find_window.h \
#	sediff_remap_types.c sediff_remap_types.h \
#	sediff_treemodel.c sediff_treemodel.h \
#	utilgui.c utilgui.h \
#	sediff_policy_open.c sediff_policy_open.h \
#	sediff_progress.c sediff_progress.h \
#	sediff_results.c sediff_results.h \
#

sediffx_SOURCES = \
	toplevel.c toplevel.h \
	sediffx.c sediffx.h

$(top_builddir)/libpoldiff/src/libpoldiff.so:
	$(MAKE) -C $(top_builddir)/libpoldiff/src $(notdir $@)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

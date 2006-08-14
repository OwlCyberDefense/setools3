bin_PROGRAMS = seaudit seaudit_report

AM_CFLAGS = -I$(top_srcdir)/libseaudit @QPOL_CFLAGS@ @APOL_CFLAGS@ @GTK_CFLAGS@ @GLADE_CFLAGS@ @XML_CFLAGS@ -DAPOL_INSTALL_DIR='"${apol_install_dir}"'
# need the -rdynamic flag below glade uses dlopen() upon seaudit callbacks
AM_LDFLAGS = @GTK_LIBS@ @GLADE_LIBS@ @XML_LIBS@ -rdynamic
LDADD = $(top_srcdir)/libseaudit/libseaudit.a @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@

dist_pkgdata_DATA = \
	customize_filter_window.glade \
	filter_window.glade \
	multifilter_window.glade \
	prefer_window.glade \
	query_window.glade \
	report_window.glade \
	seaudit.glade \
	seaudit_help.txt

seaudit_SOURCES = \
	auditlogmodel.c auditlogmodel.h \
	filtered_view.c filtered_view.h \
	filter_window.c filter_window.h \
	multifilter_window.c multifilter_window.h \
	preferences.c preferences.h \
	query_window.c query_window.h \
	report.c report.h \
	report_window.c report_window.h \
	seaudit.c seaudit_callback.c \
	seaudit_callback.h seaudit.h \
	seaudit_window.c seaudit_window.h \
	utilgui.c utilgui.h
seaudit_DEPENDENCIES = $(top_srcdir)/libseaudit/libseaudit.a \
                       $(top_srcdir)/libapol/src/libapol.so \
                       $(top_srcdir)/libqpol/src/libqpol.so

seaudit_report_SOURCES = seaudit-report.c report.c report.h
seaudit_report_DEPENDENCIES = $(top_srcdir)/libseaudit/libseaudit.a \
                              $(top_srcdir)/libapol/src/libapol.so \
                              $(top_srcdir)/libqpol/src/libqpol.so

$(top_srcdir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_srcdir)/libapol/src $(notdir $@)

$(top_srcdir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_srcdir)/libqpol/src $(notdir $@)

$(top_srcdir)/libseaudit/libseaudit.a:
	$(MAKE) -C $(top_srcdir)/libseaudit $(notdir $@)

# FIX ME:
# install glade files, saudit_help.txt, dot_seaudit, conf file, report
# stylesheet, man pages, logwatch install, DEFAULT_LOG, INSTALL_LIBDIR

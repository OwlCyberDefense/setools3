setoolsdir = @setoolsdir@
bin_PROGRAMS = seaudit-report
sbin_PROGRAMS = seaudit

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEAUDIT_CFLAGS@ \
	@GTK_CFLAGS@ @PIXBUF_CFLAGS@ @GLADE_CFLAGS@ @GTHREAD_CFLAGS@ \
	@XML_CFLAGS@ \
	-DAPOL_INSTALL_DIR='"${setoolsdir}"' -I$(top_srcdir)/libseaudit
# need the -rdynamic flag below - glade uses dlopen() upon seaudit callbacks
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@GTK_LIBS@ @PIXBUF_LIBS@ @GLADE_LIBS@ @GTHREAD_LIBS@ \
	@XML_LIBS@ -rdynamic
LDADD = @SELINUX_LIB_FLAG@ @SEAUDIT_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@

dist_setools_DATA = \
	seaudit.glade \
	seaudit_help.txt \
	seaudit-report.conf \
	seaudit-report.css \
	seaudit.png seaudit-small.png

nodist_setools_DATA = \
	dot_seaudit \
	seaudit-report-service

seaudit_SOURCES = \
	filter_view.c filter_view.h \
	message_view.c message_view.h \
	modify_view.c modify_view.h \
	policy_components_view.c policy_components_view.h \
	policy_view.c policy_view.h \
	preferences.c preferences.h \
	preferences_view.c preferences_view.h \
	progress.c progress.h \
	report_window.c report_window.h \
	seaudit.c seaudit.h \
	toplevel.c toplevel.h \
	utilgui.c utilgui.h

seaudit_DEPENDENCIES = $(top_builddir)/libseaudit/src/libseaudit.so \
                       $(top_builddir)/libapol/src/libapol.so \
                       $(top_builddir)/libqpol/src/libqpol.so

dot_seaudit: dot_seaudit.in Makefile
	sed -e 's|\@setoolsdir\@|$(setoolsdir)|g' $< > $@

seaudit_report_SOURCES = seaudit-report.c
seaudit_report_DEPENDENCIES = $(top_builddir)/libseaudit/src/libseaudit.so \
                              $(top_builddir)/libapol/src/libapol.so \
                              $(top_builddir)/libqpol/src/libqpol.so

logwatch = /etc/logwatch
LOGWATCH_GROUP = $(logwatch)/conf/logfiles
LOGWATCH_SERVICE = $(logwatch)/conf/services
LOGWATCH_FILTER = $(logwatch)/scripts/services

dist_noinst_DATA = dot_seaudit.in \
	seaudit-report-group.conf \
        seaudit-report-service.conf \
        seaudit-report-service.in

seaudit-report-service: seaudit-report-service.in Makefile
	sed -e 's|\@bindir\@|$(bindir)|g' $< > $@

install-logwatch: $(dist_noinst_DATA) seaudit-report-service
	install -m 644 seaudit-report-group.conf $(LOGWATCH_GROUP)
	install -m 644 seaudit-report-service.conf $(LOGWATCH_SERVICE)
	install -m 755 seaudit-report-service $(LOGWATCH_FILTER)

$(top_builddir)/libapol/libapol-tcl.a:
	$(MAKE) -C $(top_builddir)/libapol-tcl $(notdir $@)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

$(top_builddir)/libsefs/src/libsefs.so:
	$(MAKE) -C $(top_builddir)/libsefs/src $(notdir $@)

.PHONY: install-logwatch

CLEANFILES = dot_seaudit seaudit-report-service

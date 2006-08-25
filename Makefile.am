if COPY_BWIDGET
  MAYBE_BWIDGET = packages
endif

if BUILD_GUI
  MAYBE_GUI = libapol-tcl apol awish seaudit
endif

SUBDIRS = libqpol libapol libpoldiff libsefs libseaudit secmds sechecker sediff man $(MAYBE_GUI) $(MAYBE_BWIDGET)

DIST_SUBDIRS = $(SUBDIRS) packages libapol-tcl apol awish seaudit

EXTRA_DIST = VERSION KNOWN-BUGS

libqpol:
	$(MAKE) -C $(top_srcdir)/libqpol

libapol:
	$(MAKE) -C $(top_srcdir)/libapol
	$(MAKE) -C $(top_srcdir)/libapol-tcl

libpoldiff:
	$(MAKE) -C $(top_srcdir)/libpoldiff

libsefs:
	$(MAKE) -C $(top_srcdir)/libsefs

libseaudit:
	$(MAKE) -C $(top_srcdir)/libseaudit

apol:
	$(MAKE) -C $(top_srcdir)/apol

secmds:
	$(MAKE) -C $(top_srcdir)/secmds

seaudit:
	$(MAKE) -C $(top_srcdir)/seaudit

sediff:
	$(MAKE) -C $(top_srcdir)/sediff sediff

sediffx:
	$(MAKE) -C $(top_srcdir)/sediff sediffx

sechecker:
	$(MAKE) -C $(top_srcdir)/sechecker

awish:
	$(MAKE) -C $(top_srcdir)/awish

help:
	@echo "Make targets for setools:"
	@echo "   all:          build everything, but don't install"
	@echo "   install:      install everything"
	@echo "   uninstall:    remove setools from your system"
	@echo ""
	@echo "   apol:         build policy analysis tool"
	@echo "   secmds:       build setools command line tools"
	@echo "   seaudit:      build audit log analysis tools"
	@echo "   sediff:       build semantic policy diff command line tool"
	@echo "   sediffx:      build semantic policy diff GUI tool"
	@echo "   sechecker:    build policy checking tool"
	@echo "   awish:        build Tcl/Tk wish interpreter with SE Linux tools extensions"
	@echo "                 (useful for debugging problems with Tcl/Tk scripts)"
	@echo ""
	@echo "   install-logwatch:   install LogWatch config files for seaudit-report"
	@echo "                       (requires LogWatch and root privileges)"
	@echo ""
	@echo "   clean:        clean up interim files"
	@echo "   distclean:    clean everything not in original distribution"

install-logwatch:
	$(MAKE) -C $(top_srcdir)/seaudit install-logwatch

.PHONY: libqpol libapol libapol-tcl libpoldiff libsefs libseaudit \
	apol secmds seaudit sediff sediffx sechecker awish \
	install-logwatch help \
	seinfo sesearch indexcon findcon replcon searchcon

seinfo:
	$(MAKE) -C $(top_srcdir)/secmds seinfo

sesearch:
	$(MAKE) -C $(top_srcdir)/secmds sesearch

indexcon:
	$(MAKE) -C $(top_srcdir)/secmds indexcon

findcon:
	$(MAKE) -C $(top_srcdir)/secmds findcon

replcon:
	$(MAKE) -C $(top_srcdir)/secmds replcon

searchcon:
	$(MAKE) -C $(top_srcdir)/secmds searchcon

distclean-local:
	-rm -r config.tcl

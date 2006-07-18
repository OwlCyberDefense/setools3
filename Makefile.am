if COPY_BWIDGET
	MAYBE_BWIDGET = packages
endif

SUBDIRS = libqpol libapol libsefs libseaudit apol secmds sechecker awish $(MAYBE_BWIDGET)

EXTRA_DIST = VERSION KNOWN-BUGS

libqpol:
	$(MAKE) -C $(top_srcdir)/libqpol

libapol:
	$(MAKE) -C $(top_srcdir)/libapol

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
	@echo "FIX ME: sediff not done yet"

sediffx:
	@echo "FIX ME: sediffx not done yet"

sechecker:
	$(MAKE) -C $(top_srcdir)/sechecker

awish:
	$(MAKE) -C $(top_srcdir)/awish

all-nogui: secmds sediff sechecker

help:
	@echo "Make targets for setools:"
	@echo "   all:          build everything, but don't install"
	@echo "   all-nogui:    only build non-GUI tools and libraries"
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
	@echo "                 (useful for de-bugging problems with Tcl/Tk scripts)"
	@echo ""
	@echo "   clean:        clean up interim files"
	@echo "   distclean:    clean everything not in original distribution"

.PHONY: libqpol libapol libsefs \
	apol secmds seaudit sediff sediffx sechecker awish \
	all-nogui help \
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

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = dist-bzip2

if COPY_BWIDGET
  MAYBE_BWIDGET = packages
endif

if BUILD_GUI
  MAYBE_GUI = libapol-tcl apol awish seaudit
endif

SUBDIRS = libqpol libapol libpoldiff libsefs libseaudit secmds sechecker sediff man $(MAYBE_GUI) $(MAYBE_BWIDGET)

INDENT_OPTS = -npro -nbad -bap -sob -ss -l132 -di1 -nbc -br -nbbb -c40 -cd40 -ncdb -ce -cli0 -cp40 -ncs -d0 -nfc1 -nfca -i8 -ts8 -ci8 -lp -ip0 -npcs -npsl -sc

EXTRA_DIST = VERSION KNOWN-BUGS COPYING.LGPL COPYING.GPL

libqpol:
	$(MAKE) -C $(top_srcdir)/libqpol

libapol:
	$(MAKE) -C $(top_srcdir)/libapol

libapol-tcl:
	$(MAKE) -C $(top_srcdir)/libapol-tcl

libpoldiff:
	$(MAKE) -C $(top_srcdir)/libpoldiff

libsefs:
	$(MAKE) -C $(top_srcdir)/libsefs

libseaudit:
	$(MAKE) -C $(top_srcdir)/libseaudit

apol: libqpol libapol libsefs libapol-tcl
	$(MAKE) -C $(top_srcdir)/apol

secmds: libqpol libapol libsefs
	$(MAKE) -C $(top_srcdir)/secmds

seaudit: libqpol libapol libseaudit
	$(MAKE) -C $(top_srcdir)/seaudit

sediff: libqpol libapol libpoldiff
	$(MAKE) -C $(top_srcdir)/sediff sediff

sediffx: libqpol libapol libpoldiff
	$(MAKE) -C $(top_srcdir)/sediff sediffx

sechecker: libqpol libapol libsefs
	$(MAKE) -C $(top_srcdir)/sechecker

awish: libqpol libapol libsefs libapol-tcl
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

seinfo: libqpol libapol
	$(MAKE) -C $(top_srcdir)/secmds seinfo

sesearch: libqpol libapol
	$(MAKE) -C $(top_srcdir)/secmds sesearch

indexcon: libqpol libapol libsefs
	$(MAKE) -C $(top_srcdir)/secmds indexcon

findcon: libqpol libapol libsefs
	$(MAKE) -C $(top_srcdir)/secmds findcon

replcon: libqpol libapol libsefs
	$(MAKE) -C $(top_srcdir)/secmds replcon

searchcon: libqpol libapol libsefs
	$(MAKE) -C $(top_srcdir)/secmds searchcon

distclean-local:
	-rm -r config.tcl

indent:
	find $(top_src_dir) -name '*.[ch]' ! -wholename '*sqlite*' -type f -exec indent $(INDENT_OPTS) '{}' \;

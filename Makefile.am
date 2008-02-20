ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = dist-bzip2

if BUILD_APOL
  MAYBE_APOL = apol
endif

if BUILD_GUI
  MAYBE_GUI = seaudit
endif
# sediffx is also built conditionally, from sediffx/Makefile.am

SUBDIRS = libqpol libapol libsefs libpoldiff libseaudit secmds sechecker sediff man packages debian $(MAYBE_APOL) $(MAYBE_GUI)

#old indent opts
#INDENT_OPTS = -npro -nbad -bap -sob -ss -l132 -di1 -nbc -br -nbbb -c40 -cd40 -ncdb -ce -cli0 -cp40 -ncs -d0 -nfc1 -nfca -i8 -ts8 -ci8 -lp -ip0 -npcs -npsl -sc
C_INDENT_OPTS   = -npro -nbad -bap -nbbb -nbbo -nbc -br -bli0 -bls -c40 -cbi0 -cd40 -cdw  -ce -ci8 -cli0 -cp40 -ncs -d0 -nbfda -di1 -nfc1 -nfca -i8 -ip0 -l132 -lp -nlps -npcs -pi0 -nprs -npsl -saf -sai -sbi0 -sob -ss -ts8 -ut
CXX_INDENT_OPTS = -npro -nbad -bap -nbbb -nbbo -nbc -bl -bli0 -bls -c40 -cbi0 -cd40 -cdw -nce -ci8 -cli0 -cp40 -ncs -d0 -nbfda -di1 -nfc1 -nfca -i8 -ip0 -l132 -lp -nlps -npcs -pi0 -nprs -npsl -saf -sai -sbi0 -sob -ss -ts8 -ut

EXTRA_DIST = VERSION KNOWN-BUGS COPYING.LGPL COPYING.GPL

libqpol:
	$(MAKE) -C $(top_srcdir)/libqpol

libapol:
	$(MAKE) -C $(top_srcdir)/libapol

libpoldiff:
	$(MAKE) -C $(top_srcdir)/libpoldiff

libpolsearch:
	$(MAKE) -C $(top_srcdir)/libpolsearch

libsefs:
	$(MAKE) -C $(top_srcdir)/libsefs

libseaudit:
	$(MAKE) -C $(top_srcdir)/libseaudit

apol: libqpol libapol libsefs packages
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

help:
	@echo "Make targets for SETools:"
	@echo "   all:          build everything, but do not install"
	@echo "   install:      install everything"
	@echo "   uninstall:    remove SETools from your system"
	@echo ""
	@echo "   apol:         build policy analysis tool"
	@echo "   secmds:       build command line tools"
	@echo "   seaudit:      build audit log analysis tools"
	@echo "   sediff:       build semantic policy diff command line tool"
	@echo "   sediffx:      build semantic policy diff graphical tool"
	@echo "   sechecker:    build policy checking tool"
	@echo ""
	@echo "   install-logwatch:   install LogWatch config files for seaudit-report"
	@echo "                       (requires LogWatch and root privileges)"
	@echo ""
	@echo "   clean:        clean up interim files"
	@echo "   distclean:    clean everything not in original distribution"

install-logwatch:
	$(MAKE) -C $(top_srcdir)/seaudit install-logwatch

.PHONY: libqpol libapol libpoldiff libsefs libseaudit \
	apol secmds seaudit sediff sediffx sechecker \
	install-logwatch help \
	seinfo sesearch indexcon findcon replcon searchcon \
	packages

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

packages:
	$(MAKE) -C $(top_srcdir)/packages

distclean-local:
	-rm -r config.tcl

indent:
	find $(top_srcdir) \( -wholename '*/packages/*' -prune \) , \
		\( -name '*.[ch]' -type f -exec indent $(C_INDENT_OPTS) '{}' \; \)
	find $(top_srcdir) -regex '.*\.\(cc\|hh\)' -type f -exec indent $(CXX_INDENT_OPTS) '{}' \;
	find $(top_srcdir) -regex '.*\.\(cc\|hh\)' -type f -exec sed -i 's/\*>>/* > >/g' '{}' \;
	find $(top_srcdir) -name '*.cc' -type f -exec sed -i 's/const \?const/const/g' '{}' \;
	find $(top_srcdir) -name '*.hh' -type f -exec sed -i 's/virtual ~ /virtual ~/g' '{}' \;

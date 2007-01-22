if BUILD_GUI
  MAYBEMANS = apol.1 \
	seaudit.8 seaudit-report.8 \
	sediffx.1
endif

EXTRA_DIST=$(man_MANS) apol.1 \
	seaudit.8 seaudit-report.8.in \
	sediffx.1

man_MANS = findcon.1 indexcon.1 replcon.1 searchcon.1 \
	sechecker.1 \
	sediff.1 \
	seinfo.1 sesearch.1 $(MAYBEMANS)

seaudit-report.8: seaudit-report.8.in Makefile
	sed -e 's|\@setoolsdir\@|$(setoolsdir)|g' $< > $@

CLEANFILES = seaudit-report.8

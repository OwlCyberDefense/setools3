dist_noinst_DATA = setools.spec \
	apol.desktop.in seaudit.desktop.in \
	sediffx.desktop.in seaudit.pam seaudit.console.in

BUILT_SOURCES = apol.desktop seaudit.desktop sediffx.desktop seaudit.console

%: %.in Makefile
	sed -e "s|\@bindir\@|$(bindir)|" -e "s|\@sbindir\@|$(sbindir)|" $< > $@

clean-local:
	-rm -f $(BUILT_SOURCES)

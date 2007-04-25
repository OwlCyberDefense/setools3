bwidget_destdir = @BWIDGET_DESTDIR@
dist_noinst_DATA = BWidget-1.8.0.tar.bz2 combobox.tcl mainframe.tcl notebook.tcl \
	Doxyfile \
	rpm/setools.spec rpm/apol.desktop rpm/seaudit.desktop \
	rpm/sediffx.desktop rpm/seaudit.pam rpm/seaudit.console

install-data-local:
	tar jxf BWidget-1.8.0.tar.bz2
	test -z "$(bwidget_destdir)" || $(mkdir_p) "$(bwidget_destdir)"
	cd BWidget-1.8.0 && find . -type d -exec $(mkdir_p) "$(bwidget_destdir)/{}" \;
	cd BWidget-1.8.0 && find . -type f -exec $(INSTALL_DATA) '{}' $(bwidget_destdir)/'{}' \;

uninstall-local:
	-rm -rf $(bwidget_destdir)/BWidget-1.8.0

clean-local:
	-rm -rf BWidget-1.8.0

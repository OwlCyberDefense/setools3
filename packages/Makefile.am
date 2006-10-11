bwidget_destdir = @BWIDGET_DESTDIR@

dist_noinst_DATA = BWidget-1.8.0.tar.bz2 combobox.tcl mainframe.tcl notebook.tcl Doxyfile

install-data-local:
	tar jxf BWidget-1.8.0.tar.bz2
	mv BWidget-1.8.0 $(bwidget_destdir)

uninstall-local:
	-rm -rf $(bwidget_destdir)/BWidget-1.8.0

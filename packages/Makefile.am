bwidget_destdir = @BWIDGET_DESTDIR@

dist_noinst_DATA = BWidget-1.7.0.tar.gz combobox.tcl

install-data-local:
	tar -zxf BWidget-1.7.0.tar.gz
	mv BWidget-1.7.0 $(bwidget_destdir)

uninstall-local:
	-rm -rf $(bwidget_destdir)

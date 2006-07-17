pkglibdir = @BWIDGET_DESTDIR@

dist_pkglib_DATA = BWidget-1.7.0.tar.gz

noinst_DATA = combobox.tcl

install-data-local:
	tar -zxf BWidget-1.7.0.tar.gz
	mv BWidget-1.7.0 $(pkglibdir)

uninstall-local:
	-rm -rf $(pkglibdir)

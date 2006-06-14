libdir = @libdir@
PKG_DIR = BWidget1.7
pkglibdir = $(libdir)/$(PKG_DIR)

dist_pkglib_DATA = BWidget-1.7.0.tar.gz

install-data-local:
	tar -zxf BWidget-1.7.0.tar.gz
	mv BWidget-1.7.0 $(pkglibdir)

uninstall-local:
	-rm -rf $(pkglibdir)

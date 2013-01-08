EXTRA_DIST =				\
	sesearch.c			\
	seinfo.c			\
	__init__.py			\
	setup.py			\
	$(NULL)

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@
AM_CXXFLAGS = @DEBUGCXXFLAGS@ @WARNCXXFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libapol/src/libapol.so $(top_builddir)/libqpol/src/libqpol.so
all-am: python-build

seinfo_SOURCES = seinfo.c

sesearch_SOURCES = sesearch.c

python-build: sesearch.c seinfo.c
	@mkdir -p setools
	@cp __init__.py setools
	LIBS="$(QPOL_LIB_FLAG) $(APOL_LIB_FLAG)" INCLUDES="$(QPOL_CFLAGS) $(APOL_CFLAGS)" $(PYTHON) setup.py build

install-exec-hook:
	$(PYTHON) setup.py install `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

uninstall-hook: 
	$(PYTHON) setup.py uninstall `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

clean-local:
	$(PYTHON) setup.py clean -a 
	rm -f *~


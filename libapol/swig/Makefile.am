wrappedso_DATA = $(wrappedso_SONAME)
wrappedso_SONAME = _apol.so.@libapol_version@
dist_noinst_DATA = apol.i
BUILT_SOURCES = apol_wrap.c
wrappedsodir = $(libdir)

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ -I$(top_builddir) -fpic \
	-I$(srcdir)/../include -D__attribute__\(x\)=''
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@ \
	@APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libqpol/src/libqpol.so \
	$(top_builddir)/libapol/src/libapol.so
OBJS = $(patsubst %.c,%.o,$(BUILT_SOURCES))

$(BUILT_SOURCES): $(dist_noinst_DATA)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ $<

$(OBJS): $(BUILT_SOURCES)
	$(CC) -o $@ -c $^ $(AM_CFLAGS) $(CFLAGS) $(SWIG_PYTHON_CPPFLAGS)

$(wrappedso_DATA): $(OBJS)
	$(CC) -shared -o $@ $^ $(AM_LDFLAGS) $(LDFLAGS) -Wl,-soname,$(wrappedso_SONAME)
	$(LN_S) -f $@ _apol.so

install-data-hook:
	cd $(DESTDIR)$(wrappedsodir) && $(LN_S) -f $(wrappedso_DATA) _apol.so

uninstall-local:
	-rm -rf $(DESTDIR)$(wrappedsodir)/$(wrappedso_DATA)

CLEANFILES = $(BUILT_SOURCES) $(OBJS) $(patsubst %.i,%.py,$(dist_noinst_DATA)) _apol.so $(wrappedso_DATA)

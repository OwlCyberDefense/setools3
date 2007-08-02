# various setools command line tools

bin_PROGRAMS = seinfo sesearch findcon replcon indexcon

# These are for indexcon so that it is usable on machines without setools
STATICLIBS = ../libsefs/src/libsefs.a ../libapol/src/libapol.a ../libqpol/src/libqpol.a -lsqlite3

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@
AM_CXXFLAGS = @DEBUGCXXFLAGS@ @WARNCXXFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libapol/src/libapol.so $(top_builddir)/libqpol/src/libqpol.so

seinfo_SOURCES = seinfo.c

sesearch_SOURCES = sesearch.c

indexcon_SOURCES = indexcon.cc
indexcon_LDADD = @SELINUX_LIB_FLAG@ $(STATICLIBS)
indexcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/libsefs/src/libsefs.so

findcon_SOURCES = findcon.cc
findcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
findcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/libsefs/src/libsefs.so

replcon_SOURCES = replcon.cc
replcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
replcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/libsefs/src/libsefs.so

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

$(top_builddir)/libsefs/src/libsefs.so:
	$(MAKE) -C $(top_builddir)/libsefs/src $(notdir $@)

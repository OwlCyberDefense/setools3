# various setools command line tools

bin_PROGRAMS = seinfo sesearch

if WANT_LIBSEFS
bin_PROGRAMS += indexcon findcon replcon searchcon
endif

# These are for indexcon so it's usable on machines without libapol
STATICAPOL = ../libapol/src/libapol.a
STATICSEFS = ../libsefs/libsefs.a

AM_CFLAGS = @QPOL_CFLAGS@ @APOL_CFLAGS@

LDADD = @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@
DEPENDENCIES = $(top_builddir)/libapol/src/libapol.so $(top_builddir)/libqpol/src/libqpol.so

seinfo_SOURCES = seinfo.c

sesearch_SOURCES = sesearch.c

indexcon_SOURCES = indexcon.c
indexcon_CFLAGS = $(AM_CFLAGS) @SEFS_CFLAGS@
indexcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
indexcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/libsefs/src/libsefs.so

nodist_EXTRA_findcon_SOURCES = findcon.c
findcon_CFLAGS = $(AM_CFLAGS) @SEFS_CFLAGS@ -DFINDCON
findcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
findcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/libsefs/src/libsefs.so

replcon_SOURCES = replcon.c
replcon_CFLAGS = $(AM_CFLAGS) @SEFS_CFLAGS@
replcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
replcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/libsefs/src/libsefs.so

searchcon_SOURCES = searchcon.c
searchcon_CFLAGS = $(AM_CFLAGS) @SEFS_CFLAGS@
searchcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
searchcon_DEPENDENCIES = $(DEPENDENCIES) $(top_builddir)/libsefs/src/libsefs.so

findcon.c: replcon.c
	$(LN_S) $< $@


$(top_builddir)/libapol/libapol-tcl.a:
	$(MAKE) -C $(top_builddir)/libapol-tcl $(notdir $@)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

$(top_builddir)/libsefs/src/libsefs.so:
	$(MAKE) -C $(top_builddir)/libsefs/src $(notdir $@)

clean-local:
	-rm -f findcon.c

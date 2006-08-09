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
DEPENDENCIES = $(top_srcdir)/libapol/src/libapol.so $(top_srcdir)/libqpol/src/libqpol.so

seinfo_SOURCES = seinfo.c

sesearch_SOURCES = sesearch.c

indexcon_SOURCES = indexcon.c
indexcon_CFLAGS = $(AM_CFLAGS) @SEFS_CFLAGS@
indexcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
indexcon_DEPENDENCIES = $(DEPENDENCIES) $(top_srcdir)/libsefs/libsefs.so

nodist_EXTRA_findcon_SOURCES = findcon.c
findcon_CFLAGS = $(AM_CFLAGS) @SEFS_CFLAGS@ -DFINDCON
findcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
findcon_DEPENDENCIES = $(DEPENDENCIES) $(top_srcdir)/libsefs/libsefs.so

replcon_SOURCES = replcon.c
replcon_CFLAGS = $(AM_CFLAGS) @SEFS_CFLAGS@
replcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
replcon_DEPENDENCIES = $(DEPENDENCIES) $(top_srcdir)/libsefs/libsefs.so

searchcon_SOURCES = searchcon.c
searchcon_CFLAGS = $(AM_CFLAGS) @SEFS_CFLAGS@
searchcon_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
searchcon_DEPENDENCIES = $(DEPENDENCIES) $(top_srcdir)/libsefs/libsefs.so

findcon.c: replcon.c
	$(LN_S) $< $@

$(top_srcdir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_srcdir)/libapol/src $(notdir $@)

$(top_srcdir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_srcdir)/libqpol/src $(notdir $@)

$(top_srcdir)/libsefs/libsefs.so:
	$(MAKE) -C $(top_srcdir)/libsefs $(notdir $@)

clean-local:
	-rm -f findcon.c

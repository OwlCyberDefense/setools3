# various setools command line tools

bin_PROGRAMS = seinfo sesearch

if WANT_LIBSEFS
bin_PROGRAMS += indexcon findcon replcon searchcon 
endif

# These are for indexcon so it's usable on machines without libapol
STATICAPOL = ../libapol/src/libapol.a
STATICSEFS = ../libsefs/libsefs.a

AM_CFLAGS = -I$(top_srcdir)/libqpol/include -I$(top_srcdir)/libapol/include

LDADD = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so @QPOL_LIB_FLAG@

SEFS_CFLAGS = -I$(top_srcdir)/libsefs
SEFS_LDADD = $(top_srcdir)/libsefs/libsefs.a

seinfo_SOURCES = seinfo.c
seinfo_DEPENDENCIES = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so

sesearch_SOURCES = sesearch.c
sesearch_DEPENDENCIES = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so

indexcon_SOURCES = indexcon.c
indexcon_CFLAGS = $(AM_CFLAGS) $(SEFS_CFLAGS)
indexcon_LDADD = $(SEFS_LDADD) $(LDADD)
indexcon_DEPENDENCIES = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so $(top_srcdir)/libsefs/libsefs.a

nodist_EXTRA_findcon_SOURCES = findcon.c
findcon_CFLAGS = $(AM_CFLAGS) $(SEFS_CFLAGS) -DFINDCON
findcon_LDADD = $(SEFS_LDADD) $(LDADD)
findcon_DEPENDENCIES = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so $(top_srcdir)/libsefs/libsefs.a

replcon_SOURCES = replcon.c
replcon_CFLAGS = $(AM_CFLAGS) $(SEFS_CFLAGS)
replcon_LDADD = $(SEFS_LDADD) $(LDADD)
replcon_DEPENDENCIES = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so $(top_srcdir)/libsefs/libsefs.a

searchcon_SOURCES = searchcon.c
searchcon_CFLAGS = $(AM_CFLAGS) $(SEFS_CFLAGS)
searchcon_LDADD = $(SEFS_LDADD) $(LDADD)
searchcon_DEPENDENCIES = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so $(top_srcdir)/libsefs/libsefs.a

findcon.c: replcon.c
	$(LN_S) $< $@

$(top_srcdir)/libapol/src/libapol.a:
	$(MAKE) -C $(top_srcdir)/libapol/src $(notdir $@)

$(top_srcdir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_srcdir)/libqpol/src $(notdir $@)

$(top_srcdir)/libsefs/libsefs.a:
	$(MAKE) -C $(top_srcdir)/libsefs $(notdir $@)

clean-local:
	-rm -f findcon.c

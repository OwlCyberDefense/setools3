# various setools command line tools

bin_PROGRAMS = seinfo sesearch

if WANT_LIBSEFS
bin_PROGRAMS += indexcon findcon replcon searchcon 
endif

# These are for indexcon so it's usable on machines without libapol
STATICAPOL = ../libapol/libapol.a
STATICSEFS = ../libsefs/libsefs.a

AM_CFLAGS = -I$(top_srcdir)/libqpol/include -I$(top_srcdir)/libapol

LDADD = $(top_srcdir)/libapol/libapol.a $(top_srcdir)/libqpol/src/libqpol.so @QPOL_LIB_FLAG@

SEFS_CFLAGS = -I$(top_srcdir)/libsefs
SEFS_LDADD = $(top_srcdir)/libsefs/libsefs.a

seinfo_SOURCES = seinfo.c

sesearch_SOURCES = sesearch.c

indexcon_SOURCES = indexcon.c
indexcon_CFLAGS = $(AM_CFLAGS) $(SEFS_CFLAGS)
indexcon_LDADD = $(SEFS_LDADD) $(LDADD)

nodist_EXTRA_findcon_SOURCES = findcon.c
findcon_CFLAGS = $(AM_CFLAGS) $(SEFS_CFLAGS) -DFINDCON
findcon_LDADD = $(SEFS_LDADD) $(LDADD)

replcon_SOURCES = replcon.c
replcon_CFLAGS = $(AM_CFLAGS) $(SEFS_CFLAGS)
replcon_LDADD = $(SEFS_LDADD) $(LDADD)

searchcon_SOURCES = searchcon.c
searchcon_CFLAGS = $(AM_CFLAGS) $(SEFS_CFLAGS)
searchcon_LDADD = $(SEFS_LDADD) $(LDADD)

findcon.c: replcon.c
	$(LN_S) $< $@

clean-local:
	-rm -f findcon.c

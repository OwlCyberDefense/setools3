lib_LIBRARIES = libseaudit.a

AM_CFLAGS = -fPIC -I$(top_srcdir)/libqpol/include -I$(top_srcdir)/libapol -D_GNU_SOURCE @XML_CFLAGS@

libseaudit_a_SOURCES = \
	auditlog.c auditlog.h auditlog_view.c auditlog_view.h \
	filters.c filters.h filter_criteria.c filter_criteria.h \
	multifilter.c multifilter.h sort.c sort.h parse.c parse.h
libseaudit_a_DEPENDENCIES = $(top_srcdir)/libapol/libapol.a

$(top_srcdir)/libapol/libapol.a:
	$(MAKE) -C $(top_srcdir)/libapol $(notdir $@)

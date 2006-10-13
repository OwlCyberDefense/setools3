lib_LIBRARIES = libseaudit.a

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @XML_CFLAGS@ -fpic

libseaudit_a_SOURCES = \
	auditlog.c auditlog.h auditlog_view.c auditlog_view.h \
	filters.c filters.h filter_criteria.c filter_criteria.h \
	multifilter.c multifilter.h sort.c sort.h parse.c parse.h
libseaudit_a_DEPENDENCIES = $(top_builddir)/libapol/src/libapol.so

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

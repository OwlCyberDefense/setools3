LIB-OBJ        = auditlog.o auditlog_view.o filters.o filter_criteria.o multifilter.o sort.o parse.o
INCLUDE        = -I..
SEAUDIT_LIBS   = ../lib/libseaudit.a ../lib/libapol.a $(LIBS)
CFLAGS		+= -D_GNU_SOURCE
CFLAGS          += -DLIBSEAUDIT_VERSION_STRING='"$(shell cat VERSION)"'
LIBXML_FLAGS   = `pkg-config --cflags libxml`

libseaudit: ../lib/libseaudit.a

../lib/libseaudit.a: ../lib $(LIB-OBJ)
	ar cr $@ $(LIB-OBJ)

../lib/libapol.a: 
	cd ../; $(MAKE) libapol

%.o:  %.c 
	$(CC) $(CFLAGS) $(LIBXML_FLAGS) $(INCLUDE) -c $<

../lib:
	mkdir -p $@
clean:
	rm -f *.o seaudit *~ core*

bare: clean
	rm -f ../lib/libseaudit.a

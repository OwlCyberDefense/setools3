LIB-OBJ        = auditlog.o auditlog_view.o filters.o filter_criteria.o multifilter.o sort.o parse.o
INCLUDE        = -I..
SEAUDIT_LIBS   = libseaudit.a ../libapol/libapol.a $(LIBS)
CFLAGS		+= -D_GNU_SOURCE
CFLAGS          += -DLIBSEAUDIT_VERSION_STRING='"$(shell cat VERSION)"'
LIBXML_FLAGS   = `pkg-config --cflags libxml-2.0`

TARGET = libseaudit.so
SONAME = $(TARGET).1
LIBSO  = $(TARGET).$(shell cat VERSION)

libseaudit: libseaudit.a
libseauditso: $(LIB-OBJ)
	$(CC) $(LDFLAGS) -shared -o $(LIBSO) $(LIB-OBJ) -Wl,-soname,$(SONAME) 

libseaudit.a: $(LIB-OBJ)
	ar cr $@ $(LIB-OBJ)

../libapol/libapol.a: 
	cd ../; $(MAKE) libapol

install-libapol-shared: libseauditso
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf $(LIBSO) $(SONAME) && ln -sf $(SONAME) $(TARGET)

install-libapol-static: libseaudit
	install -m 644 libseaudit.a $(STATIC_LIB_INSTALL_DIR)
	install -m 755 -d $(SETOOLS_INCLUDE)/libseaudit
	install -m 644 *.h $(SETOOLS_INCLUDE)/libseaudit

install: install-libapol-shared install-libapol-static

install-policy:
	chcon system_u:object_r:shlib_t $(SHARED_LIB_INSTALL_DIR)/$(LIBSO)

%.o:  %.c 
	$(CC) $(CFLAGS) $(LIBXML_FLAGS) $(INCLUDE) -c $<

clean:
	rm -f *.o seaudit *~ core*

bare: clean
	rm -f libseaudit.a $(LIBSO)

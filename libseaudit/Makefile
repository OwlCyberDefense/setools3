LIB-OBJ        = auditlog.o auditlog_view.o filters.o filter_criteria.o multifilter.o sort.o parse.o
INCLUDE        = -I..
SEAUDIT_LIBS   = ../lib/libseaudit.a ../lib/libapol.a $(LIBS)
CFLAGS		+= -D_GNU_SOURCE
CFLAGS          += -DLIBSEAUDIT_VERSION_STRING='"$(shell cat VERSION)"'
LIBXML_FLAGS   = `pkg-config --cflags libxml-2.0`

LOBJS = $(patsubst %.o,%.lo,$(LIB-OBJ))

TARGET = libseaudit.so
LIBSO  = $(TARGET).$(shell cat VERSION)

libseaudit: ../lib/libseaudit.a
libseauditso: ../lib/$(LIBSO)

../lib/libseaudit.a: ../lib $(LIB-OBJ)
	ar cr $@ $(LIB-OBJ)

../lib/libapol.a: 
	cd ../; $(MAKE) libapol

../lib/$(LIBSO): ../lib $(LOBJS)
	$(CC) $(LDFLAGS) -shared -o ../lib/$(LIBSO) $(LOBJS) -Wl,-soname,$(LIBSO) 
	
install-libapol-shared: libseauditso
	test -d $(SHARED_LIB_INSTALL_DIR) || install -m 755 -d $(SHARED_LIB_INSTALL_DIR)
	install -m 755 ../lib/$(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	/sbin/ldconfig $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf ./`basename $(SHARED_LIB_INSTALL_DIR)`/$(LIBSO) $(TARGET)

install-libapol-static: libseaudit
	test -d $(STATIC_LIB_INSTALL_DIR) || install -m 755 -d $(STATIC_LIB_INSTALL_DIR)
	install -m 644 ../lib/libseaudit.a $(STATIC_LIB_INSTALL_DIR)
	test -d $(SETOOLS_INCLUDE) || install -m 755 -d $(SETOOLS_INCLUDE)
	install -m 644 *.h $(SETOOLS_INCLUDE)

install: install-libapol-shared install-libapol-static

%.o:  %.c 
	$(CC) $(CFLAGS) $(LIBXML_FLAGS) $(INCLUDE) -c $<

%.lo:  %.c
	$(CC) $(CFLAGS) -fPIC $(LIBXML_FLAGS) $(INCLUDE) -c $< -o $@
	
../lib:
	mkdir -p $@
clean:
	rm -f *.o seaudit *~ core* $(LOBJS)

bare: clean
	rm -f ../lib/libseaudit.a ../lib/$(LIBSO)

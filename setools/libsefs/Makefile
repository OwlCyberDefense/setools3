# libseuser and libseuser-tcl

LIB-OBJ		= fsdata.o

TARGET = libsefs.so
SONAME = $(TARGET).1
LIBSO  = $(TARGET).$(shell cat VERSION)

CFLAGS		+= -I. -I../libapol

all: libsefs libsefsso

libsefs: libsefs.a

libsefsso: $(LIB-OBJ)
	$(CC) $(LDFLAGS) -shared -o $(LIBSO) $(LIB-OBJ) -Wl,-soname,$(SONAME) 

libsefs.a:  $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 

install-libsefs-shared: libsefsso
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf $(LIBSO) $(SONAME) && ln -sf $(SONAME) $(TARGET)

install-libsefs-static: libsefs
	install -m 644 libsefs.a $(STATIC_LIB_INSTALL_DIR)
	install -m 755 -d $(SETOOLS_INCLUDE)/libsefs
	install -m 644 *.h $(SETOOLS_INCLUDE)/libsefs
	
install: install-libsefs-shared install-libsefs-static

install-policy:
	chcon system_u:object_r:shlib_t $(SHARED_LIB_INSTALL_DIR)/$(LIBSO)
	
%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o core *~

bare: clean
	rm -f *.o core *~ libsefs.a $(LIBSO)


# libseuser and libseuser-tcl

SETFILES_PROG = /usr/sbin/setfiles
LIB-OBJ		= seuser_db.o 
LIB-OBJ-TCL 	= $(LIB-OBJ) seuser_tcl.o

CFLAGS      += -DLIBSEUSER_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS      += -DSETFILES_PROG='"$(SETFILES_PROG)"'

TARGET 	    = libseuser.so
LIBSO	    = $(TARGET).$(shell cat VERSION)

all: libseuser libseuser-tcl libseuserso

libseuser: libseuser.a
libseuser-tcl: libseuser-tcl.a
libseuserso: $(LIB-OBJ)
	$(CC) $(LDFLAGS) -shared -o $(LIBSO) $(LIB-OBJ) -Wl,-soname,$(LIBSO)
	
libseuser.a: $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 
	 
libseuser-tcl.a: $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL)

install-libseuser-shared: libseuserso
	test -d $(SHARED_LIB_INSTALL_DIR) || install -m 755 -d $(SHARED_LIB_INSTALL_DIR)
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	/sbin/ldconfig $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf ./`basename $(SHARED_LIB_INSTALL_DIR)`/$(LIBSO) $(TARGET)
	
install-libseuser-static: libseuser
	test -d $(STATIC_LIB_INSTALL_DIR) || install -m 755 -d $(STATIC_LIB_INSTALL_DIR)
	install -m 644 libseuser.a $(STATIC_LIB_INSTALL_DIR)
	test -d $(SETOOLS_INCLUDE) || install -m 755 -d $(SETOOLS_INCLUDE)
	install -m 644 *.h $(SETOOLS_INCLUDE)

install: install-libseuser-shared install-libseuser-static
	
%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o  core *~ 

bare: clean
	rm -f *.o  core *~ libseuser.a libseuser-tcl.a $(LIBSO)


# libseuser and libseuser-tcl

SETFILES_PROG = /usr/sbin/setfiles
LIB-OBJ		= seuser_db.o 
LIB-OBJ-TCL 	= $(LIB-OBJ) seuser_tcl.o

CFLAGS      += -DLIBSEUSER_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS      += -DSETFILES_PROG='"$(SETFILES_PROG)"'

TARGET 	    = libseuser.so
SONAME 	    = $(TARGET).1
LIBSO	    = $(TARGET).$(shell cat VERSION)

TARGETTCL   = libseuser-tcl.so
SONAMETCL   = $(TARGETTCL).1
LIBSOTCL    = $(TARGETTCL).$(shell cat VERSION)
INCLUDE	    = -I../$(SETOOLS_TREE)libapol

all: libseuser libseuser-tcl libseuserso libseuser-tclso

libseuser: libseuser.a
libseuser-tcl: libseuser-tcl.a

libseuserso: $(LIB-OBJ)
	$(CC) $(LDFLAGS) -shared -o $(LIBSO) $(LIB-OBJ) -Wl,-soname,$(SONAME)

libseuser.a: $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 

libseuser-tcl.a: $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL)

libseuser-tclso: $(LIB-OBJ-TCL) 
	$(CC) $(LDFLAGS) -shared -o $(LIBSOTCL) $(LIB-OBJ-TCL) -Wl,-soname,$(SONAMETCL)

install-libseuser-shared: libseuserso
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf $(LIBSO) $(SONAME) && ln -sf $(SONAME) $(TARGET)

install-libseuser-static: libseuser
	install -m 644 libseuser.a $(STATIC_LIB_INSTALL_DIR)
	install -m 755 -d $(SETOOLS_INCLUDE)/libseuser
	install -m 644 *.h $(SETOOLS_INCLUDE)/libseuser

install: install-libseuser-shared install-libseuser-static

install-policy:
	chcon system_u:object_r:shlib_t $(SHARED_LIB_INSTALL_DIR)/$(LIBSO)

%.o:  %.c 
	$(CC) $(CFLAGS) $(INCLUDE) -c $< 

clean:
	rm -f *.o  core *~ 

bare: clean
	rm -f *.o  core *~ libseuser.a libseuser-tcl.a $(LIBSO) $(LIBSOTCL)


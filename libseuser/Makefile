# libseuser and libseuser-tcl

SETFILES_PROG = /usr/sbin/setfiles
LIB-OBJ		= seuser_db.o 
LIB-OBJ-TCL 	= $(LIB-OBJ) seuser_tcl.o
LOBJS		= $(patsubst %.o,%.lo,$(LIB-OBJ))

CFLAGS      += -DLIBSEUSER_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS      += -DSETFILES_PROG='"$(SETFILES_PROG)"'

LIBSO		= libseuser$(shell cat VERSION).so

all: libseuser libseuser-tcl libseuserso

libseuser: ../lib/libseuser.a
libseuser-tcl: ../lib/libseuser-tcl.a
libseuserso: ../lib/$(LIBSO)

../lib/libseuser.a: ../lib $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 
	 
../lib/libseuser-tcl.a: ../lib $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL)

../lib/$(LIBSO): ../lib $(LOBJS)
	$(CC) $(LDFLAGS) -shared -o ../lib/$(LIBSO) $(LOBJS) -Wl,-soname,$(LIBSO)

install-libseuser-shared: libseuserso
	install -m 644 ../lib/$(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	/sbin/ldconfig $(SHARED_LIB_INSTALL_DIR)
	ln -sf $(SHARED_LIB_INSTALL_DIR)/$(LIBSO) $(SHARED_LIB_INSTALL_DIR)/libseuser.so

install-libseuser-static: libseuser
	mkdir -p $(SETOOLS_INCLUDE)
	install -m 644 ../lib/libseuser.a $(STATIC_LIB_INSTALL_DIR)
	install -m 644 *.h $(SETOOLS_INCLUDE)

install: install-libseuser-shared install-libseuser-static
	
%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

%.lo:  %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

../lib:
	mkdir -p $@ 


clean:
	rm -f *.o  core *~ $(LOBJS)

bare: clean
	rm -f *.o  core *~ ../lib/libseuser.a ../lib/libseuser-tcl.a ../lib/$(LIBSO)


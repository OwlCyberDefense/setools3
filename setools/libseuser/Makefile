# libseuser and libseuser-tcl

SETFILES_PROG = /usr/sbin/setfiles
LIB-OBJ		= seuser_db.o 
LIB-OBJ-TCL = $(LIB-OBJ) seuser_tcl.o
CFLAGS      += -DLIBSEUSER_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS      += -DSETFILES_PROG='"$(SETFILES_PROG)"'
PIC_FLAG =

libseuser: ../lib/libseuser.a

libseuser-shared: ../lib/libseuser.$(shell cat VERSION).so

libseuser-tcl: ../lib/libseuser-tcl.a

../lib/libseuser.a: ../lib $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 
	 
../lib/libseuser-tcl.a: ../lib $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL)

../lib/libseuser.$(shell cat VERSION).so : PIC_FLAG = -fPIC
	 
../lib/libseuser.$(shell cat VERSION).so: ../lib $(LIB-OBJ)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$@ \
	    -o $@ $(LIB-OBJ) -lc

install-libseuser-shared: ../lib/libseuser.$(shell cat VERSION).so
	install -m 644 ../lib/libseuser.$(shell cat VERSION).so $(SHARED_LIB_INSTALL_DIR)
	/sbin/ldconfig -n $(SHARED_LIB_INSTALL_DIR)
	ln -sf $(SHARED_LIB_INSTALL_DIR)/libseuser.$(shell cat VERSION).so $(SHARED_LIB_INSTALL_DIR)/libseuser.so

install-libseuser-static: ../lib/libseuser.a
	mkdir -p $(SETOOLS_INCLUDE)
	install -m 644 ../lib/libseuser.a $(STATIC_LIB_INSTALL_DIR)
	install -m 644 *.h $(SETOOLS_INCLUDE)
	
%.o:  %.c 
	$(CC) $(CFLAGS) $(PIC_FLAG) -c $<

install: install-libseuser-shared install-libseuser-static
	
	
../lib:
	mkdir -p $@ 


clean:
	rm -f *.o  core *~

bare:
	rm -f *.o  core *~ ../lib/libseuser.a ../lib/libseuser-tcl.a \
		../lib/libseuser.$(shell cat VERSION).so



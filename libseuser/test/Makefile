# libseuser test

LIBAPOL-TCL	= ../../libapol/libapol-tcl.a ../../libapol/libapol.a
LIBSEUSER-TCL	= ../../libseuser/libseuser-tcl.a ../../libseuser/libseuser.a
LIBSEFS		= ../../libsefs/libsefs.a
OBJS		= test-seuser.o   $(LIBSEUSER-TCL)  $(LIBAPOL-TCL)

test-seuser: $(OBJS)
	$(CC) $(TCL_LIBINC) -o $@ $(OBJS) $(LINKFLAGS) $(TCL_LIBS) $(LIBSELINUX) $(LIBSEFS)

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

	
../../libapol/libapol.a:
	cd ../../ ; $(MAKE) libapol
	
../../libapol/libapol-tcl.a: 
	cd ../../ ; $(MAKE) libapol-tcl

../../libseuser/libseuser-tcl.a:
	cd ../../ ; $(MAKE) libseuser-tcl
	
../../libseuser/libseuser.a:
	cd ../../ ; $(MAKE) libseuser

clean:
	rm -f *.o  core *~ test-seuser

bare:
	rm -f *.o  core *~ test-seuser



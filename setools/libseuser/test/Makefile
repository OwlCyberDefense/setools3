# libseuser test

LIBAPOL-TCL	= ../../lib/libapol-tcl.a ../../lib/libapol.a
LIBSEUSER-TCL	= ../../lib/libseuser-tcl.a ../../lib/libseuser.a
OBJS		= test-seuser.o   $(LIBSEUSER-TCL)  $(LIBAPOL-TCL)

test-seuser: $(OBJS)
	$(CC) $(TCL_LIBINC) -o $@ $(OBJS) $(LINKFLAGS) $(TCL_LIBS)

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

	
../../lib/libapol.a:
	cd ../../ ; $(MAKE) libapol
	
../../lib/libapol-tcl.a: 
	cd ../../ ; $(MAKE) libapol-tcl

../../lib/libseuser-tcl.a:
	cd ../../ ; $(MAKE) libseuser-tcl
	
../../lib/libseuser.a:
	cd ../../ ; $(MAKE) libseuser

clean:
	rm -f *.o  core *~ test-seuser

bare:
	rm -f *.o  core *~ test-seuser



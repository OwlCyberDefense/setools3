# awish tool
LIBAPOL-TCL	= ../lib/libapol-tcl.a ../lib/libapol.a
LIBSEUSER-TCL	= ../lib/libseuser-tcl.a ../lib/libseuser.a
AWISH_OBJ	= awish.o  $(LIBSEUSER-TCL) $(LIBAPOL-TCL)

awish: $(AWISH_OBJ)
	$(CC) $(TCL_LIBINC) -o $@ $(AWISH_OBJ) $(LINKFLAGS) $(TCL_LIBS)


%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

../lib/libapol.a:
	cd ../ ; $(MAKE) libapol
	
../lib/libapol-tcl.a: 
	cd ../ ; $(MAKE) libapol-tcl

../lib/libseuser-tcl.a:
	cd ../ ; $(MAKE) libseuser-tcl
	
../lib/libseuser.a:
	cd ../ ; $(MAKE) libseuser
	
install: awish
	-install -m 755 awish $(BINDIR)

clean:
	rm -f *.o  core awish *~

bare:
	rm -f *.o  core awish *~







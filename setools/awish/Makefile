# awish tool
LIBAPOL-TCL	= ../libapol/libapol-tcl.a ../libapol/libapol.a
LIBSEUSER-TCL	= ../libseuser/libseuser-tcl.a ../libseuser/libseuser.a
AWISH_OBJ	= awish.o  $(LIBSEUSER-TCL) $(LIBAPOL-TCL)

awish: $(AWISH_OBJ)
	$(CC) $(TCL_LIBINC) -o $@ $(AWISH_OBJ) $(LINKFLAGS) $(TCL_LIBS) $(LIBSELINUX)


%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

../libapol/libapol.a:
	cd ../ ; $(MAKE) libapol
	
../libapol/libapol-tcl.a: 
	cd ../ ; $(MAKE) libapol-tcl

../libseuser/libseuser-tcl.a:
	cd ../ ; $(MAKE) libseuser-tcl
	
../libseuser/libseuser.a:
	cd ../ ; $(MAKE) libseuser
	
install: awish
	install -m 755 awish $(BINDIR)

clean:
	rm -f *.o  core awish *~

bare:
	rm -f *.o  core awish *~







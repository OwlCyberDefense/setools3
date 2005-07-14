# awish tool

ifeq ($(DYNAMIC), 0)
LIBAPOL-TCL	= ../libapol/libapol-tcl.a ../libapol/libapol.a

ifeq ($(USE_LIBSEFS), 1)
	LIBSEFS		= ../libsefs/libsefs.a
	else
	LIBSEFS = 
	endif
	
else
LIBAPOL-TCL	= ../libapol/libapol-tcl.a ../libapol/libapol.so.$(shell cat ../libapol/VERSION)

ifeq ($(USE_LIBSEFS), 1)
	LIBSEFS		= ../libsefs/libsefs.so.$(shell cat ../libsefs/VERSION)
	else
	LIBSEFS = 
	endif
endif

AWISH_OBJ	= awish.o $(LIBAPOL-TCL) $(LIBSEFS)

# awish is optionally linked to libselinux. The LIBSELINUX variable is 
# set in the top-level Makefile.
awish: $(AWISH_OBJ)
	$(CC) $(TCL_LIBINC) -o $@ $(AWISH_OBJ) $(LINKFLAGS) $(TCL_LIBS) $(LIBSELINUX)

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

../libapol/libapol.a:
	cd ../ ; $(MAKE) libapol
	
../libapol/libapol-tcl.a: 
	cd ../ ; $(MAKE) libapol-tcl

$(LIBSEFS):
	cd ../ ; $(MAKE) libsefs
		
install: awish
	install -m 755 awish $(BINDIR)

clean:
	rm -f *.o  core awish *~

bare:
	rm -f *.o  core awish *~







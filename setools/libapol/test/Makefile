## NOTE: don't invoke this directly; rather run
## from setools/Makefile!!!

# libapol test

LIBAPOL		= ../../libapol/libapol.a -lselinux -lfl
OBJS		= test-apol.o  $(LIBAPOL)



test-apol: $(OBJS)
	$(CC) $(TCL_LIBINC) -g -o $@ $(OBJS) $(LINKFLAGS) $(LIBS) $(LIBSELINUX)

%.o:  %.c 
	$(CC) $(CFLAGS) -g -c $<

$(LIBAPOL): 
	cd ../../ ; $(MAKE) libapol

clean:
	rm -f *.o  core.* *~ test-apol

bare:
	rm -f *.o  core.* *~ test-apol



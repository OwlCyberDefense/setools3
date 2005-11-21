## NOTE: don't invoke this directly; rather run
## from setools/Makefile!!!

# libapol test

LIBAPOL		= ../../setools/libapol/libapol.a -lselinux -lfl
OBJS		= test-apol.o  $(LIBAPOL)
INCLUDES	= -I../../setools/libapol
CFLAGS		+= $(INCLUDES)

test-apol: $(LIBAPOL) $(OBJS)
	$(CC) $(TCL_LIBINC) $(INCLUDES) -g -o $@ $(OBJS) $(LINKFLAGS) $(LIBS) $(LIBSELINUX)

%.o:  %.c 
	$(CC) $(CFLAGS) -g -c $<

$(LIBAPOL): libapol

libapol: 
	$(MAKE) -C ../../setools libapol

clean:
	rm -f *.o  core.* *~ test-apol

bare:
	rm -f *.o  core.* *~ test-apol



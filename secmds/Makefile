# various setools command line tools

LIBAPOL		= ../lib/libapol.a
LIBSEUSER	= ../lib/libseuser.a

INCLUDE		= -I.. -I../libapol

SE_CMDS		= seinfo sesearch


CFLAGS		+= -DDEFAULT_POLICY='"$(POLICY_SRC_FILE)"'

SHELL = /bin/sh

all: $(SE_CMDS)

seinfo: seinfo.o $(LIBAPOL)
	$(CC) -o $@  seinfo.o $(LIBAPOL) $(LINKFLAGS) $(LIBS)
	
sesearch: sesearch.o $(LIBAPOL)
	$(CC) -o $@ sesearch.o $(LIBAPOL) $(LINKFLAGS) $(LIBS)

install: $(SE_CMDS)
	install -m 755 $(SE_CMDS) $(BINDIR);

%.o:  %.c 
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

$(LIBAPOL): 
	cd ../ ; $(MAKE) libapol
	
$(LIBAPOL-TCL): 
	cd ../ ; $(MAKE) libapol-tcl

$(LIBSEUSER):
	cd ../ ; $(MAKE) libseuser
	
$(LIBSEUSER-TCL):
	cd ../ ; $(MAKE) libseuser-tcl

clean:
	rm -f *.o core* $(SE_CMDS) *~ 
bare:
	rm -f *.o core* $(SE_CMDS) *~







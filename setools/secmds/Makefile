# various setools command line tools

# replcon and findcon only support filesystems featuring Security Labels
SUPPORTED_FILESYSTEMS	= '"ext2 ext3"'
LIBAPOL		= ../lib/libapol.a
LIBSEUSER	= ../lib/libseuser.a

LIBSELINUX      = -lselinux

INCLUDE		= -I.. -I../libapol

SE_CMDS		= seinfo sesearch replcon findcon


CFLAGS		+= -DDEFAULT_POLICY='"$(POLICY_SRC_FILE)"'
CFLAGS  	+= -DSEINFO_VERSION_NUM='"$(shell cat SEINFO_VERSION)"'
CFLAGS  	+= -DSESEARCH_VERSION_NUM='"$(shell cat SESEARCH_VERSION)"'
CFLAGS          += -DREPLCON_VERSION_NUM='"$(shell cat REPLCON_VERSION)"'

SHELL = /bin/sh

all: $(SE_CMDS)

seinfo: seinfo.o $(LIBAPOL)
	$(CC) -o $@  seinfo.o $(LIBAPOL) $(LIBS) $(LINKFLAGS)

sesearch: sesearch.o $(LIBAPOL)
	$(CC) -o $@ sesearch.o $(LIBAPOL) $(LIBS) $(LINKFLAGS)

replcon.o: replcon.c
	$(CC) -c replcon.c -DSUPPORTED_FILESYSTEMS=$(SUPPORTED_FILESYSTEMS) $(CFLAGS) $(INCLUDE)

replcon: replcon.o
	$(CC) -o $@ replcon.o $(LINKFLAGS) $(LIBSELINUX)

findcon.o: replcon.c
	$(CC) -c replcon.c -o findcon.o -DFINDCON -DSUPPORTED_FILESYSTEMS=$(SUPPORTED_FILESYSTEMS) $(CFLAGS) $(INCLUDE)

findcon: findcon.o
	$(CC) -o $@ findcon.o $(LINKFLAGS) $(LIBSELINUX)

install: $(SE_CMDS)
	-install -m 755 $(SE_CMDS) $(BINDIR);
	chcon system_u:object_r:setfiles_exec_t %(BINDIR)/replcon

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

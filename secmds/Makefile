# various setools command line tools

# replcon and findcon only support filesystems featuring Security Labels
SEFS_XATTR_LABELED_FILESYSTEMS	= '"ext2 ext3"'

ifeq ($(DEBUG), 1)
LIBAPOL		= ../libapol/libapol.a
LIBSEFS		= ../libsefs/libsefs.a
LIBSEUSER	= ../libseuser/libseuser.a
else
LIBAPOL		= ../libapol/libapol.so.$(shell cat ../libapol/VERSION)
LIBSEFS		= ../libsefs/libsefs.so.$(shell cat ../libsefs/VERSION)
LIBSEUSER	= ../libseuser/libseuser.so.$(shell cat ../libseuser/VERSION)
endif

LIBSELINUX      = -lselinux

INCLUDE		= -I.. -I../libapol -I../libsefs

SE_CMDS		= seinfo sesearch replcon findcon indexcon searchcon

CFLAGS  	+= -DSEINFO_VERSION_NUM='"$(shell cat SEINFO_VERSION)"'
CFLAGS  	+= -DSESEARCH_VERSION_NUM='"$(shell cat SESEARCH_VERSION)"'
CFLAGS          += -DREPLCON_VERSION_NUM='"$(shell cat REPLCON_VERSION)"'
CFLAGS          += -DFINDCON_VERSION_NUM='"$(shell cat FINDCON_VERSION)"'
CFLAGS          += -DINDEXCON_VERSION_NUM='"$(shell cat INDEXCON_VERSION)"'
CFLAGS          += -DSEARCHCON_VERSION_NUM='"$(shell cat SEARCHCON_VERSION)"'

SHELL = /bin/sh

all: $(SE_CMDS)

seinfo: seinfo.o $(LIBAPOL)
	$(CC) -o $@  seinfo.o $(LIBAPOL) $(LIBS) $(LINKFLAGS)

sesearch: sesearch.o $(LIBAPOL)
	$(CC) -o $@ sesearch.o $(LIBAPOL) $(LIBS) $(LINKFLAGS)

replcon.o: replcon.c
	$(CC) -c replcon.c -DSEFS_XATTR_LABELED_FILESYSTEMS=$(SEFS_XATTR_LABELED_FILESYSTEMS) $(CFLAGS) $(INCLUDE)

replcon: replcon.o
	$(CC) -o $@ replcon.o $(LINKFLAGS) $(LIBSELINUX)

indexcon.o: indexcon.c
	$(CC) -c indexcon.c -DSEFS_XATTR_LABELED_FILESYSTEMS=$(SEFS_XATTR_LABELED_FILESYSTEMS) $(CFLAGS) $(INCLUDE)

indexcon: indexcon.o $(LIBAPOL) $(LIBSEFS)
	$(CC) -static -o $@ indexcon.o $(LINKFLAGS) $(LIBSEFS) $(LIBSELINUX) $(LIBAPOL) $(LIBS)

searchcon.o: searchcon.c
	$(CC) -c searchcon.c -DSEFS_XATTR_LABELED_FILESYSTEMS=$(SEFS_XATTR_LABELED_FILESYSTEMS) $(CFLAGS) $(INCLUDE)

searchcon: searchcon.o
	$(CC) -static -o $@ searchcon.o $(LINKFLAGS) $(LIBSEFS) $(LIBSELINUX) $(LIBAPOL) $(LIBS)

findcon.o: replcon.c
	$(CC) -c replcon.c -o findcon.o -DFINDCON -DSEFS_XATTR_LABELED_FILESYSTEMS=$(SEFS_XATTR_LABELED_FILESYSTEMS) $(CFLAGS) $(INCLUDE)

findcon: findcon.o
	$(CC) -o $@ findcon.o $(LINKFLAGS) $(LIBSELINUX)
	
install: $(SE_CMDS)
	install -m 755 $(SE_CMDS) $(BINDIR);

install-policy:
	-@if [ -e $(BINDIR)/replcon ]; then \
		chcon system_u:object_r:setfiles_exec_t $(BINDIR)/replcon; \
	fi

%.o:  %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

$(LIBAPOL):
	cd ../ ; $(MAKE) libapol

$(LIBAPOL-TCL):
	cd ../ ; $(MAKE) libapol-tcl

$(LIBSEFS):
	cd ../ ; $(MAKE) libsefs

$(LIBSEUSER):
	cd ../ ; $(MAKE) libseuser

$(LIBSEUSER-TCL):
	cd ../ ; $(MAKE) libseuser-tcl

clean:
	rm -f *.o core* $(SE_CMDS) *~
bare:
	rm -f *.o core* $(SE_CMDS) *~

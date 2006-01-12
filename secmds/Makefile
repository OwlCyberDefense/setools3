# various setools command line tools

ifeq ($(DYNAMIC), 0)
LIBAPOL		= ../libapol/libapol.a
LIBSEFS		= ../libsefs/libsefs.a
else
LIBAPOL		= ../libapol/libapol.so.$(shell cat ../libapol/VERSION)
LIBSEFS		= ../libsefs/libsefs.so.$(shell cat ../libsefs/VERSION)
endif

# These are for indexcon so it's usable on machines without libapol
STATICAPOL = ../libapol/libapol.a
STATICSEFS = ../libsefs/libsefs.a

LIBSELINUXSO      = -lselinux

INCLUDE		= -I.. -I../libapol -I../libsefs 

SE_CMDS		= seinfo sesearch 
SELINUX_TOOLS   = replcon findcon indexcon searchcon 
ifeq ($(USE_LIBSEFS), 1)
SE_CMDS += $(SELINUX_TOOLS)
endif


SHELL = /bin/sh

all: $(SE_CMDS) 

# seinfo and sesearch are optionally linked to libselinux.  
# The LIBSELINUX variable is set in the top-level Makefile. 
seinfo: seinfo.o $(LIBAPOL) 
	$(CC) -o $@  seinfo.o $(LIBAPOL) $(LIBS) $(LINKFLAGS) $(LIBSELINUX)

sesearch: sesearch.o $(LIBAPOL) 
	$(CC) -o $@ sesearch.o $(LIBAPOL) $(LIBS) $(LINKFLAGS) $(LIBSELINUX)

# replcon, findcon, indexcon, and searchcon must always be linked to libselinux.  
# We use the LIBSELINUXSO variable (defined above) to do this. 
replcon.o: replcon.c 
	$(CC) -c replcon.c $(CFLAGS) $(INCLUDE)

replcon: replcon.o $(LIBSEFS) $(LIBAPOL)
	$(CC) -o $@ replcon.o $(LINKFLAGS) $(LIBSELINUXSO) $(LIBSEFS) $(LIBAPOL) $(LIBS)

indexcon.o: indexcon.c
	$(CC) -c indexcon.c $(CFLAGS) $(INCLUDE)

indexcon: indexcon.o $(LIBSEFS) $(LIBAPOL)
	$(CC) -o $@ indexcon.o $(LINKFLAGS) $(STATICSEFS) $(LIBSELINUXSO) $(STATICAPOL) $(LIBS)

searchcon.o: searchcon.c
	$(CC) -c searchcon.c $(CFLAGS) $(INCLUDE)

searchcon: searchcon.o $(LIBSEFS) $(LIBAPOL)
	$(CC) -o $@ searchcon.o $(LINKFLAGS) $(LIBSEFS) $(LIBSELINUXSO) $(LIBAPOL) $(LIBS)

findcon.o: replcon.c
	$(CC) -c replcon.c -o findcon.o -DFINDCON $(CFLAGS) $(INCLUDE)

findcon: findcon.o $(LIBSEFS) $(LIBAPOL)
	$(CC) -o $@ findcon.o $(LINKFLAGS) $(LIBSELINUXSO) $(LIBSEFS) $(LIBAPOL) $(LIBS)

install: all
	install -m 755 $(SE_CMDS) $(BINDIR);

install-policy:
	-@if [ -e $(BINDIR)/replcon ]; then \
		chcon system_u:object_r:setfiles_exec_t $(BINDIR)/replcon; \
	fi

%.o:  %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

seinfo.o: CFLAGS += -DSEINFO_VERSION_NUM='"$(shell cat SEINFO_VERSION)"'
sesearch.o: CFLAGS += -DSESEARCH_VERSION_NUM='"$(shell cat SESEARCH_VERSION)"'
replcon.o: CFLAGS += -DREPLCON_VERSION_NUM='"$(shell cat REPLCON_VERSION)"'
findcon.o: CFLAGS += -DFINDCON_VERSION_NUM='"$(shell cat FINDCON_VERSION)"'
indexcon.o: CFLAGS += -DINDEXCON_VERSION_NUM='"$(shell cat INDEXCON_VERSION)"'
searchcon.o: CFLAGS += -DSEARCHCON_VERSION_NUM='"$(shell cat SEARCHCON_VERSION)"'
flowtool.o: CFLAGS += -DAPOL_DEFAULT_PERM_MAP="\"/usr/share/setools/apol_perm_mapping\""

libapol:
	$(MAKE) -C .. libapol

libsefs:
	$(MAKE) -C .. libsefs

clean:
	rm -f *.o core* $(SE_CMDS) $(SELINUX_TOOLS) *~

bare: clean
	rm -f *.o core* $(SE_CMDS) $(SELINUX_TOOLS) *~

.PHONY: bare clean libapol libsefs


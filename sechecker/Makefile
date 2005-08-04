OBJS 		  = sechecker.o register_list.o sechk_parse.o
LIBAPOL 	  = ../libapol/libapol.a
ifeq ($(USE_LIBSEFS), 1)
LIBSEFS           = ../libsefs/libsefs.a
all: libsefs
INCLUDE           += -I../libsefs
else
LIBSEFS           =
endif
MODULES 	  = $(patsubst %.c, %.o, $(wildcard ./modules/*.c))
INCLUDE 	  += -I. -I../libapol
LINKFLAGS 	  = -lfl -lm $(LIBSELINUX)
SECHECKER_VERSION = '"$(shell cat ./VERSION)"'
LIBXML_FLAGS	  = `pkg-config --cflags libxml-2.0`
LIBXML_LIBS       = `pkg-config --libs libxml-2.0`
CFLAGS 		  += -D_GNU_SOURCE

all: libapol sechecker

sechecker: $(LIBAPOL) $(LIBSEFS) modules $(OBJS) sechecker_cli.o
	$(CC) $(CFLAGS) -o $@ sechecker_cli.o  $(OBJS) $(LIBXML_LIBS) $(MODULES) $(LIBAPOL) $(LIBSEFS) $(LINKFLAGS)

sechecker_cli.o: sechecker_cli.c register_list.h sechecker.h
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBXML_FLAGS) -DSECHECKER_VERSION=$(SECHECKER_VERSION) -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBXML_FLAGS) -c $< 

libapol:
	$(MAKE) -C .. libapol

libsefs:
	$(MAKE) -C .. libsefs

modules: 
	$(MAKE) -C ./modules all

register_list.o : register_list.h

sechecker.o: sechecker.h 
sechecker.o sechecker_cli.o: CFLAGS+=-DPROFILE_INSTALL_DIR='"$(INSTALL_LIBDIR)/profiles.sechecker"'

sechk_parse.o: sechk_parse.h

install: all install-profiles
	install -m 755 sechecker $(BINDIR)
	install -m 644 dot_sechecker $(INSTALL_LIBDIR)

install-profiles:
	mkdir -m 755 -p $(INSTALL_LIBDIR)/profiles.sechecker
	install -m 644 profiles/*.sechecker $(INSTALL_LIBDIR)/profiles.sechecker

clean:
	rm -f sechecker *.o; $(MAKE) -C ./modules clean

bare: clean
	rm -f *~ core core.*; $(MAKE) -C ./modules bare

.PHONY: clean bare libapol libsefs modules



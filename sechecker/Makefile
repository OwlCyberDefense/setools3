OBJS 		  = sechecker.o register_list.o
LIBAPOL 	  = ../libapol/libapol.a
LIBSEFS           = ../libsefs/libsefs.a
MODULES 	  = $(patsubst %.c, %.o, $(wildcard ./modules/*.c))
INCLUDE 	  += -I. -I../libapol -I../libsefs
LINKFLAGS 	  = -lfl -lm $(LIBSELINUX)
SECHECKER_VERSION = '"$(shell cat ./VERSION)"'
LIBXML_FLAGS	  = `pkg-config --cflags libxml-2.0`
LIBXML_LIBS       = `pkg-config --libs libxml-2.0`
CFLAGS 		  += -D_GNU_SOURCE

all: sechecker


sechecker: libapol libsefs $(MODULES) $(OBJS) sechecker_cli.o
	$(CC) $(CFLAGS) -o $@ sechecker_cli.o  $(OBJS) $(LIBXML_LIBS) $(MODULES) $(LIBAPOL) $(LIBSEFS) $(LINKFLAGS)

sechecker_cli.o: sechecker_cli.c register_list.h sechecker.h
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBXML_FLAGS) -DSECHECKER_VERSION=$(SECHECKER_VERSION) -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBXML_FLAGS) -c $< 

libapol:
	$(MAKE) -C .. libapol

libsefs:
	$(MAKE) -C .. libsefs

$(MODULES): $(wildcard ./modules/*.c)
	$(MAKE) -C ./modules $(notdir $@)

register_list.o : register_list.h

sechecker.o: sechecker.h

install: all
	install -m 755 sechecker $(BINDIR)
	install -m 644 dot_sechecker $(INSTALL_LIBDIR)

clean:
	rm -f sechecker *.o; $(MAKE) -C ./modules clean

bare: clean
	rm -f *~ core core.*; $(MAKE) -C ./modules bare

.PHONY: clean bare



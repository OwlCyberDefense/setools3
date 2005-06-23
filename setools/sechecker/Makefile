OBJS 		  = sechecker.o
LIBAPOL 	  = ../libapol/libapol.a
MODULES 	  = $(patsubst %.c, %.o, $(wildcard ./modules/*.c))
INCLUDE 	  += -I. -I../libapol
LINKFLAGS 	  = -lfl -lm $(LIBSELINUX)
SECHECKER_VERSION = '"$(shell cat ./VERSION)"'
LIBXML_FLAGS	  = `pkg-config --cflags libxml-2.0`
LIBXML_LIBS       = `pkg-config --libs libxml-2.0`
CFLAGS 		  += -D_GNU_SOURCE

all: sechecker

sechecker:$(LIBAPOL) $(MODULES) $(OBJS) sechecker_cli.o
	$(CC) $(CFLAGS) -o $@ sechecker_cli.o $(OBJS) $(LIBXML_LIBS) $(MODULES) $(LIBAPOL) $(LIBSELINUX) $(LINKFLAGS)

sechecker_cli.o: sechecker_cli.c modules/register_list.h
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBXML_FLAGS) -DSECHECKER_VERSION=$(SECHECKER_VERSION) -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBXML_FLAGS) -c $< 

$(LIBAPOL):
	$(MAKE) -C .. libapol

$(MODULES): $(wildcard ./modules/*.c)
	$(MAKE) -C ./modules $(notdir $@)

clean:
	rm -f sechecker *.o; $(MAKE) -C ./modules clean

bare: clean
	rm -f *~ core core.*; $(MAKE) -C ./modules bare

.PHONY: clean bare



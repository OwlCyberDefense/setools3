OBJS = $(MODULES) sechecker.o
LIBAPOL = ../libapol/libapol.a
MODULES = $(patsubst %.c, %.o, $(wildcard ./modules/*.c))
INCLUDE += -I. -I../libapol
LINKFLAGS = -lfl -lm $(LIBSELINUX)
SECHECKER_VERSION = '"$(shell cat ./VERSION)"'

all: sechecker $(MODULES) $(LIBAPOL)
	

sechecker: $(OBJS) $(LIBAPOL) sechecker_cli.o
	$(CC) $(CFLAGS) -o $@ sechecker_cli.o $(OBJS) $(LIBAPOL) $(LINKFLAGS)

sechecker_cli.o: sechecker_cli.c modules/register_list.h
	$(CC) $(CFLAGS) $(INCLUDE) -DSECHECKER_VERSION=$(SECHECKER_VERSION) -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< 

$(LIBAPOL):
	$(MAKE) -C .. libapol

$(MODULES): $(wildcard ./modules/*.c)
	$(MAKE) -C ./modules $(notdir $@)

clean:
	rm -f sechecker *.o; $(MAKE) -C ./modules clean

bare: clean
	rm -f *~ core core.*; $(MAKE) -C ./modules bare

.PHONY: clean bare



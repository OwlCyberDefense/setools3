# sediff tool

LIBAPOL		= ../libapol/libapol.a
INCLUDE		= -I.. -I../libapol

CFLAGS  	+= -DSEDIFF_VERSION_NUM='"$(shell cat SEDIFF_VERSION)"'

all: sediff

sediff: sediff.o $(LIBAPOL)
	$(CC) -o $@  sediff.o $(LIBAPOL) $(LIBS) $(LINKFLAGS) $(LIBSELINUX)


install: sediff
	install -m 755 $(SE_CMDS) $(BINDIR);

%.o:  %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

$(LIBAPOL):
	cd ../ ; $(MAKE) libapol

clean:
	rm -f *.o core* sediff *~
bare:
	rm -f *.o core* sediff *~

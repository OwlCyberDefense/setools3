# makefile for the batch flow analysis tool

CFLAGS = -I../libapol -Wall -Wshadow -ansi -pedantic -O2 -DAPOL_DEFAULT_PERM_MAP="\"/usr/share/setools/apol_perm_mapping\""
LDFLAGS =
LIBFLAGS = -L../libapol -lapol -lfl

OBJS = flowtool.o

all: flowtool

flowtool: $(OBJS) ../libapol/libapol.a
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBFLAGS) $(LIBSELINUX)

bare clean:
	-rm -f *.o flowtool core core.* y.tab.c y.tab.h lex.yy.c *~ 

.PHONY: clean bare

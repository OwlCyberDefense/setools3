# makefile for the batch flow analysis tool

CFLAGS = -I../libapol -Wall -Wshadow -ansi -pedantic -O2 -DAPOL_DEFAULT_PERM_MAP="\"/usr/share/setools/apol_perm_mapping\"" -g
LDFLAGS = -g
LIBFLAGS = -L../libapol -lapol -lfl

OBJS = flowtool.o

flowtool: $(OBJS) ../libapol/libapol.a
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBFLAGS)

clean:
	-rm *o flowtool core

test:	flowtool
	./flowtool -p ~/policy.conf -m ~/apol_perm_mapping test_query

test2:  flowtool
	./flowtool -p ~/small-policy.conf -m ~/small_perm_mapping test_query

.PHONY: clean test test2

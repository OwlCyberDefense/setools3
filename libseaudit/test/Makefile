CFLAGS = -Wall -g
INCLUDE = -I..
LIBS = ../../lib/libseaudit.a ../../lib/libapol.a
OBJS = test.o

test: $(LIBS) $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $(OBJS) $(LIBS)

../../lib/libseaudit.a:
	cd ../../; $(MAKE) libseaudit

../../lib/libapol.a:
	cd ../../; $(MAKE) libapol

%.o:  %.c 
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

clean:
	rm -f *~ *.o test

bare: 
	clean

CFLAGS 		= -Wall -g
INCLUDE 	= -I..
LIBXML_FLAGS   	= `pkg-config --cflags libxml-2.0`
XML_LIBS       	= `pkg-config --libs libxml-2.0`
LIBS 		= ../libseaudit.a ../../libapol/libapol.a 
OBJS 		= test.o

test-seaudit: $(LIBS) $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $(OBJS) $(LIBS) $(XML_LIBS)

../libseaudit.a:
	cd ../../; $(MAKE) libseaudit

../../libapol/libapol.a:
	cd ../../; $(MAKE) libapol

%.o:  %.c 
	$(CC) $(CFLAGS) $(LIBXML_FLAGS) $(INCLUDE) -c $<

clean:
	rm -f *~ *.o test-seaudit

bare: clean

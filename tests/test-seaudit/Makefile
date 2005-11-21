CFLAGS 		= -Wall -g
INCLUDES 	= -I../../setools/libseaudit
CFLAGS		+= $(INCLUDES)
LIBXML_FLAGS   	= `pkg-config --cflags libxml-2.0`
XML_LIBS       	= `pkg-config --libs libxml-2.0`
LIBS 		= ../../setools/libseaudit/libseaudit.a ../../setools/libapol/libapol.a 
OBJS 		= test.o

test-seaudit: libseaudit libapol $(LIBS) $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $(OBJS) $(LIBS) $(XML_LIBS)

libseaudit:
	$(MAKE) -C ../../setools libseaudit

libapol:
	$(MAKE) -C ../../setools libapol

%.o:  %.c 
	$(CC) $(CFLAGS) $(LIBXML_FLAGS) $(INCLUDE) -c $<

clean:
	rm -f *~ *.o test-seaudit

bare: clean

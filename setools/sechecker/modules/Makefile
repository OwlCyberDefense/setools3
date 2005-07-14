MODS		= $(patsubst %.c, %.o, $(wildcard ./*.c))
LIBXML_FLAGS    = `pkg-config --cflags libxml-2.0`
INCLUDES	+= -I../../libapol -I.. -I../../libsefs


all: $(MODS)

%.o: %.c %.h
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBXML_FLAGS) -c $<

clean: 
	rm -f *.o 

bare: clean
	rm -f *~

.PHONY: clean bare



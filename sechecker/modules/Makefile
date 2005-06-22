MODS = $(patsubst %.c, %.o, $(wildcard ./*.c))
INCLUDES+= -I../../libapol -I..

all: $(MODS)
	

%.o: %.c %.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean: 
	rm -f *.o 

bare: clean
	rm -f *~

.PHONY: clean bare



# libseuser and libseuser-tcl

LIB-OBJ = attach.o auth.o btree.o build.o date.o delete.o expr.o func.o hash.o insert.o legacy.o main.o opcodes.o \
	os_mac.o os_unix.o os_win.o pager.o parse.o pragma.o printf.o random.o select.o table.o tokenize.o trigger.o \
        update.o utf.o util.o vacuum.o vdbeapi.o vdbeaux.o vdbe.o vdbemem.o where.o

CFLAGS = -fPIC -O2
	
TARGET = libsqlite3.so
SONAME = $(TARGET).1
LIBSO  = $(TARGET).$(shell cat VERSION)

all: config.h $(LIB-OBJ)

config: config.c
	$(CC) $(CFLAGS) $@.c -o $@

config.h: config
	./config > $@

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

clean: 
	rm -f *.so *.o config core *~

bare: clean
	rm -f *.o *.so config config.h core *~


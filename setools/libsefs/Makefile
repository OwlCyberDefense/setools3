# libsefs 

LIB-OBJ	= fsdata.o 

SQL-OBJ = sqlite/attach.o sqlite/auth.o sqlite/btree.o sqlite/build.o sqlite/date.o \
	sqlite/delete.o sqlite/expr.o sqlite/func.o sqlite/hash.o sqlite/insert.o sqlite/legacy.o \
	sqlite/main.o sqlite/opcodes.o sqlite/os_mac.o sqlite/os_unix.o sqlite/os_win.o sqlite/pager.o \
	sqlite/parse.o sqlite/pragma.o sqlite/printf.o sqlite/random.o sqlite/select.o sqlite/table.o \
	sqlite/tokenize.o sqlite/trigger.o sqlite/update.o sqlite/utf.o sqlite/util.o sqlite/vacuum.o \
	sqlite/vdbeapi.o sqlite/vdbeaux.o sqlite/vdbe.o sqlite/vdbemem.o sqlite/where.o

TARGET = libsefs.so
SONAME = $(TARGET).1
LIBSO  = $(TARGET).$(shell cat VERSION)


CFLAGS		+= -I. -I../libapol 

all: sqlite libsefs $(LIBSO)

libsefsso: $(LIBSO)

sqlite: nothing
	cd sqlite; $(MAKE)

libsefs: sqlite libsefs.a 

$(LIBSO): $(LIB-OBJ) $(SQL-OBJ)
	$(CC) $(LDFLAGS) -shared -o $(LIBSO) $^ -Wl,-soname,$(SONAME) 

libsefs.a:  $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) $(SQL-OBJ)

install-libsefs-shared: $(LIBSO)
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf $(LIBSO) $(SONAME) && ln -sf $(SONAME) $(TARGET)

install-libsefs-static: libsefs
	install -m 644 libsefs.a $(STATIC_LIB_INSTALL_DIR)
	install -m 755 -d $(SETOOLS_INCLUDE)/libsefs
	install -m 644 *.h $(SETOOLS_INCLUDE)/libsefs

install: install-libsefs-static install-libsefs-shared

install-policy:
	chcon system_u:object_r:shlib_t $(SHARED_LIB_INSTALL_DIR)/$(LIBSO)

fsdata.o: fsdata.c
	$(CC) $(CFLAGS) -c fsdata.c

%.o:  %.c 
	cd sqlite
	$(CC) $(CFLAGS) -c $<

clean:
	cd sqlite; $(MAKE) clean
	rm -f *.o core *~

bare: clean
	rm -f *.o core *~ libsefs.a $(LIBSO) $(SONAME)
	cd sqlite; $(MAKE) bare

nothing:

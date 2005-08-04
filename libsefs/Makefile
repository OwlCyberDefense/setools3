# libsefs 

LIB-OBJ	= fsdata.o file_contexts.o

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

all: libsefs libsefsso

libsefs: libsefs.a 
libsefsso: $(LIBSO)

sqlite: $(SQL-OBJ)
	$(MAKE) -C sqlite all

$(LIBSO): sqlite $(LIB-OBJ)  
	$(CC) $(LDFLAGS) -shared -o $(LIBSO) $(LIB-OBJ) $(SQL-OBJ) -Wl,-soname,$(SONAME) 

libsefs.a: sqlite $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) $(SQL-OBJ)

install-libsefs-shared: $(LIBSO) install-includes
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf $(LIBSO) $(SONAME) && ln -sf $(SONAME) $(TARGET)

install-libsefs-static: libsefs install-includes
	install -m 644 libsefs.a $(STATIC_LIB_INSTALL_DIR)

install-includes:
	test -d $(SETOOLS_INCLUDE)/libsefs || install -m 755 -d $(SETOOLS_INCLUDE)/libsefs
	test -d $(SETOOLS_INCLUDE)/libsefs/sqlite || install -m 755 -d $(SETOOLS_INCLUDE)/libsefs/sqlite
	install -m 644 $(wildcard *.h) $(SETOOLS_INCLUDE)/libsefs
	install -m 644 $(wildcard sqlite/*.h) $(SETOOLS_INCLUDE)/libsefs/sqlite
 
install: install-libsefs-static install-libsefs-shared install-includes

install-policy:
	chcon system_u:object_r:shlib_t $(SHARED_LIB_INSTALL_DIR)/$(LIBSO)

fsdata.o: fsdata.c sqlite
	$(CC) $(CFLAGS) -c fsdata.c

file_contexts.o: file_contexts.c file_contexts.h ../libapol/policy.h
	$(CC) $(CFLAGS) -c $< 

clean:
	cd sqlite; $(MAKE) clean
	rm -f *.o core *~

bare: clean
	rm -f *.o core *~ libsefs.a $(LIBSO) $(SONAME)
	$(MAKE) -C sqlite bare

.PHONY: clean bare 

$(SQL-OBJ): sqlite/config.h
$(SQL-OBJ): CFLAGS = -fPIC -w -O2

sqlite/config.h:
	$(MAKE) -C sqlite $(notdir $@)


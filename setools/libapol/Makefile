# libapol and libapol-tcl

LIB-OBJ	= policy.o policy-query.o policy-io.o queue.o util.o clone.o y.tab.o lex.yy.o
LIB-OBJ +=  avl-util.o policy-avl.o render.o analysis.o perm-map.o cond.o infoflow.o
LIB-OBJ +=  binpol/binpol.o binpol/bpmaps.o binpol/fbuf.o binpol/ebitmap.o

LIB-OBJ-TCL = apol_tcl.o

LOBJS = $(patsubst %.o,%.lo,$(LIB-OBJ))

TARGET = libapol.so
LIBSO  = $(TARGET).$(shell cat VERSION)

CFLAGS  += -DLIBAPOL_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS  += -DAPOL_INSTALL_DIR='"$(INSTALL_LIBDIR)"'
CFLAGS  += -DLIBAPOL_POLICY_INSTALL_DIR='"$(POLICY_INSTALL_DIR)"'
CFLAGS  += -DLIBAPOL_SELINUX_DIR='"$(SELINUX_DIR)"'
CFLAGS	+= -DLIBAPOL_DEFAULT_POLICY='"$(POLICY_SRC_FILE)"'
CFLAGS  += -I.

all: libapol libapol-tcl libapolso

libapol: ../lib/libapol.a
libapol-tcl: ../lib/libapol-tcl.a
libapolso: ../lib/$(LIBSO)

../lib/libapol.a: ../lib $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 

../lib/$(LIBSO): ../lib $(LOBJS)
	$(CC) $(LDFLAGS) -shared -o ../lib/$(LIBSO) $(LOBJS) -Wl,-soname,$(LIBSO) 

../lib/libapol-tcl.a: ../lib $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL) 

install-libapol-shared: libapolso
	test -d $(SHARED_LIB_INSTALL_DIR) || install -m 755 -d $(SHARED_LIB_INSTALL_DIR)
	install -m 755 ../lib/$(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	/sbin/ldconfig $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf ./`basename $(SHARED_LIB_INSTALL_DIR)`/$(LIBSO) $(TARGET)

install-libapol-static: libapol
	test -d $(STATIC_LIB_INSTALL_DIR) || install -m 755 -d $(STATIC_LIB_INSTALL_DIR)
	install -m 644 ../lib/libapol.a $(STATIC_LIB_INSTALL_DIR)
	test -d $(SETOOLS_INCLUDE) || install -m 755 -d $(SETOOLS_INCLUDE)
	install -m 644 *.h $(SETOOLS_INCLUDE)

install: install-libapol-shared install-libapol-static
	
%.o:  %.c 
	$(CC) $(CFLAGS) -o $@ -c $<

%.lo:  %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

y.tab.c: apolicy_parse.y
	$(YACC) -d apolicy_parse.y	

lex.yy.c: apolicy_scan.l
	$(LEX) apolicy_scan.l

../lib:
	mkdir -p $@ 

clean:
	rm -f $(LIB-OBJ) $(LOBJS) *.o  core y.tab.c y.tab.h lex.yy.c *~ 

bare:
	rm -f $(LIB-OBJ) $(LOBJS) *.o  core y.tab.c y.tab.h lex.yy.c *~ ../lib/libapol.a ../lib/libapol-tcl.a \
		../lib/$(LIBSO)



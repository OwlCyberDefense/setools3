# libapol and lipapol-tcl

LIB-OBJ	= policy.o policy-query.o policy-io.o queue.o util.o clone.o y.tab.o lex.yy.o
LIB-OBJ +=  avl-util.o policy-avl.o render.o analysis.o perm-map.o cond.o infoflow.o poldiff.o
LIB-OBJ +=  flowassert.o flowassert_scan.o flowassert_parse.o symtable.o
LIB-OBJ +=  relabel_analysis.o file_contexts.o
LIB-OBJ +=  binpol/binpol.o binpol/bpmaps.o binpol/fbuf.o binpol/ebitmap.o
LIB-OBJ +=  semantic/avhash.o semantic/avsemantics.o

LIB-OBJ-TCL = apol_tcl.o

TARGET = libapol.so
SONAME = $(TARGET).1
LIBSO  = $(TARGET).$(shell cat VERSION)

TARGETTCL = libapol-tcl.so
SONAMETCL = $(TARGETTCL).1
LIBSOTCL  = $(TARGETTCL).$(shell cat VERSION)

CFLAGS  += -DLIBAPOL_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS  += -DAPOL_INSTALL_DIR='"$(INSTALL_LIBDIR)"'
CFLAGS  += -DLIBAPOL_POLICY_INSTALL_DIR='"$(POLICY_INSTALL_DIR)"'
CFLAGS  += -DLIBAPOL_SELINUX_DIR='"$(SELINUX_DIR)"'
CFLAGS	+= -DLIBAPOL_DEFAULT_POLICY='"$(POLICY_SRC_FILE)"'
CFLAGS  += -I.

all: libapol libapol-tcl libapolso libapol-tclso

libapol: libapol.a
libapol-tcl: libapol-tcl.a
libapolso: $(LIB-OBJ)
	$(CC) $(LDFLAGS) -shared -o $(LIBSO) $(LIB-OBJ) -Wl,-soname,$(SONAME) 

libapol-tclso: $(LIB-OBJ-TCL)
	$(CC) $(LDFLAGS) -shared -o $(LIBSOTCL) $(LIB-OBJ-TCL) -Wl,-soname,$(SONAMETCL) 

libapol.a: $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 

libapol-tcl.a: $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL) 

install-libapol-shared: libapolso
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf $(LIBSO) $(SONAME) && ln -sf $(SONAME) $(TARGET)

install-libapol-static: libapol
	install -m 644 libapol.a $(STATIC_LIB_INSTALL_DIR)
	install -m 755 -d $(SETOOLS_INCLUDE)/libapol
	install -m 644 *.h $(SETOOLS_INCLUDE)/libapol
	install -m 755 -d $(SETOOLS_INCLUDE)/libapol/semantic
	install -m 644 *.h $(SETOOLS_INCLUDE)/libapol/semantic
	install -m 755 -d $(SETOOLS_INCLUDE)/libapol/binpol
	install -m 644 *.h $(SETOOLS_INCLUDE)/libapol/binpol

install: install-libapol-shared install-libapol-static

install-policy:
	chcon system_u:object_r:shlib_t $(SHARED_LIB_INSTALL_DIR)/$(LIBSO)

%.o:  %.c 
	$(CC) $(CFLAGS) -o $@ -c $<

y.tab.c: apolicy_parse.y
	$(YACC) -d apolicy_parse.y	

lex.yy.c: apolicy_scan.l
	$(LEX) apolicy_scan.l

flowassert_scan.c: flowassert_scan.l flowassert_parse.c
	flex -o$@ -Pflow $<

flowassert_parse.c: flowassert_parse.y
	bison -o $@ -d -p flow $<

clean:
	rm -f $(LIB-OBJ) *.o core core.* y.tab.c y.tab.h lex.yy.c flowassert_parse.c \
		flowassert_parse.h flowassert_scan.c *~ 

bare:
	rm -f $(LIB-OBJ) *.o  core core.* y.tab.c y.tab.h lex.yy.c *~ \
		flowassert_parse.c flowassert_parse.h flowassert_scan.c libapol.a libapol-tcl.a \
		$(LIBSO) $(LIBSOTCL)



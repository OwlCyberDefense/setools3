# libapol and lipapol-tcl

LIB-OBJ	= policy.o policy-query.o policy-io.o queue.o util.o clone.o y.tab.o lex.yy.o
LIB-OBJ +=  avl-util.o policy-avl.o render.o analysis.o perm-map.o cond.o infoflow.o poldiff.o
LIB-OBJ +=  flowassert.o flowassert_scan.o flowassert_parse.o symtable.o
LIB-OBJ +=  relabel_analysis.o
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

LDFLAGS += -lfl

all: libapol libapol-tcl libapolso libapol-tclso

libapol: libapol.a
libapol-tcl: libapol-tcl.a
libapolso: $(LIB-OBJ)
	$(CC)  -shared -o $(LIBSO) $(LIB-OBJ) $(LDFLAGS) -Wl,-soname,$(SONAME) 

libapol-tclso: $(LIB-OBJ-TCL)
	$(CC) -shared -o $(LIBSOTCL) $(LIB-OBJ-TCL) $(LDFLAGS) -Wl,-soname,$(SONAMETCL) 

libapol.a: $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 

libapol-tcl.a: $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL) 

install-libapol-shared: libapolso install-includes
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf $(LIBSO) $(SONAME) && ln -sf $(SONAME) $(TARGET)

install-libapol-static: libapol install-includes
	install -m 644 libapol.a $(STATIC_LIB_INSTALL_DIR)

install-includes:
	test -d $(SETOOLS_INCLUDE)/libapol || install -m 755 -d $(SETOOLS_INCLUDE)/libapol
	test -d $(SETOOLS_INCLUDE)/libapol/semantic || install -m 755 -d $(SETOOLS_INCLUDE)/libapol/semantic
	test -d $(SETOOLS_INCLUDE)/libapol/binpol || install -m 755 -d $(SETOOLS_INCLUDE)/libapol/binpol
	install -m 644 $(filter-out y.tab.h,$(wildcard *.h)) $(SETOOLS_INCLUDE)/libapol
	install -m 644 $(wildcard semantic/*.h) $(SETOOLS_INCLUDE)/libapol/semantic
	install -m 644 $(wildcard binpol/*.h) $(SETOOLS_INCLUDE)/libapol/binpol

install: install-libapol-shared install-libapol-static install-includes

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

.PHONY: bare clean

# include objects here for header dependencies
analysis.o clone.o flowasser.o infoflow.o perm-map.o policy-io.o: policy.h
policy-avl.o policy-query.o relabel_analysis.o render.o util.o: policy.h
binpol/binpol.o semantic/avhash.o semantic/avsemantics.o: policy.h
poldiff.o policy-io.o binpol/binpol.o: policy-io.h
avl-util.o policy-avl.o:avl-util.h
policy.o cond.o: cond.h
$(filter flowassert, $(LIB-OBJ)): flowassert.h
analysis.o infoflow.o flowassert.o flowassert_parse.o: infoflow.h
flowassert.o policy.o perm-map.o: perm-map.h
analysis.o flowassert_parse.o infoflow.o poldiff.o: policy-query.h
analysis.o infoflow.o policy-io.h queue.o: queue.h
analysis.o avl-util.o clone.o cond.o flowassert.o flowassert_parse.o: util.h
infoflow.o perm-map.o policy-avl.o policy.o polic-io.o policy-query.o: util.h
render.o symtable.o util.o binpol/binpol.o: util.h
analysis.o: analysis.h
clone.o: clone.h
poldiff.o: poldiff.h
policy.o policy-avl.o: policy-avl.h
relabel_analysis.o: relabel_analysis.h
render.o: render.h
symtable.o flowassert_parse.o: symtable.h
binpol/binpol.o policy-io.o: binpol/binpol.h
binpol/binpol.o binpol/bpmaps.o: binpol/bpmaps.h
binpol/binpol.o binpol/ebitmap.o: binpol/borrowed.h
binpol/binpol.o binpol/bpmaps.o binpol/ebitmap.o: binpol/ebitmap.h
binpol/binpol.o binpol/ebitmap.o binpol/fbuf.o: binpol/fbuf.h
poldiff.o relabel_analysis.o render.o: semantic/avhash.h semantic/avsemantics.h
semantic/avhash.o semantic/avsemantics.o: semantic/avhash.h
semantic/avsemantics.o: semantic/avsemantics.h


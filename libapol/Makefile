# libapol and lipapol-tcl

LIB-OBJ	= policy.o policy-query.o queue.o util.o clone.o y.tab.o lex.yy.o
LIB-OBJ +=  avl-util.o policy-avl.o render.o analysis.o perm-map.o cond.o infoflow.o poldiff.o
LIB-OBJ +=  relabel_analysis.o dta.o
LIB-OBJ +=  binpol/binpol.o binpol/bpmaps.o binpol/fbuf.o binpol/ebitmap.o
LIB-OBJ +=  semantic/avhash.o semantic/avsemantics.o

# new LIB-OBJS below
LIB-OBJ += policy-io.o
LIB-OBJ += vector.o

QUERY-OBJ = component-query.o context-query.o mls-query.o \
	type-query.o class-perm-query.o role-query.o user-query.o \
	bool-query.o netcon-query.o fscon-query.o
LIB-OBJ += $(QUERY-OBJ)

LIB-OBJ-TCL = apol_tcl_other.o apol_tcl_render.o apol_tcl_components.o apol_tcl_rules.o apol_tcl_fc.o apol_tcl_analysis.o
#libapol
TARGET = libapol.so
SONAME = $(TARGET).1
LIBSO  = $(TARGET).$(shell cat VERSION)

TARGETTCL = libapol-tcl.so
SONAMETCL = $(TARGETTCL).1
LIBSOTCL  = $(TARGETTCL).$(shell cat VERSION)

CFLAGS  += -DLIBAPOL_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS  += -DLIBAPOL_POLICY_INSTALL_DIR='"$(POLICY_INSTALL_DIR)"'
CFLAGS  += -DLIBAPOL_SELINUX_DIR='"$(SELINUX_DIR)"'
CFLAGS	+= -DLIBAPOL_DEFAULT_POLICY='"$(POLICY_SRC_FILE)"'
CFLAGS  += -I.

LDFLAGS += -lfl

all: libapol libapol-tcl libapolso libapol-tclso

libapol: libapol.a
libapol-tcl: libapol-tcl.a
libapolso: $(LIBSO) 

$(LIBSO): $(LIB-OBJ)
	$(CC)  -shared -o $(LIBSO) $(LIB-OBJ) $(LDFLAGS) -Wl,-soname,$(SONAME) 

libapol-tclso: $(LIBSOTCL)

$(LIBSOTCL):$(LIB-OBJ-TCL)
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
	test -d $(INCLUDE_DIR)/libapol || install -m 755 -d $(INCLUDE_DIR)/libapol
	test -d $(INCLUDE_DIR)/libapol/semantic || install -m 755 -d $(INCLUDE_DIR)/libapol/semantic
	test -d $(INCLUDE_DIR)/libapol/binpol || install -m 755 -d $(INCLUDE_DIR)/libapol/binpol
	install -m 644 $(filter-out y.tab.h,$(wildcard *.h)) $(INCLUDE_DIR)/libapol
	install -m 644 $(wildcard semantic/*.h) $(INCLUDE_DIR)/libapol/semantic
	install -m 644 $(wildcard binpol/*.h) $(INCLUDE_DIR)/libapol/binpol

install: install-libapol-shared install-libapol-static install-includes

install-policy:
	chcon system_u:object_r:shlib_t $(SHARED_LIB_INSTALL_DIR)/$(LIBSO)

%.o:  %.c 
	$(CC) $(CFLAGS) -o $@ -c $<

y.tab.c: apolicy_parse.y
	$(YACC) $(YFLAGS) -d apolicy_parse.y	

lex.yy.c: apolicy_scan.l
	$(LEX) $(LFLAGS) apolicy_scan.l

clean:
	rm -f $(LIB-OBJ) *.o core core.* y.tab.c y.tab.h lex.yy.c *~ 

bare:
	rm -f $(LIB-OBJ) *.o  core core.* y.tab.c y.tab.h lex.yy.c *~ \
		libapol.a libapol-tcl.a \
		$(LIBSO) $(LIBSOTCL)

.PHONY: bare clean

# include objects here for header dependencies
analysis.o clone.o infoflow.o perm-map.o policy-io.o: policy.h
policy-avl.o policy-query.o relabel_analysis.o render.o util.o: policy.h
binpol/binpol.o semantic/avhash.o semantic/avsemantics.o dta.o: policy.h
poldiff.o policy-io.o binpol/binpol.o: policy-io.h
avl-util.o policy-avl.o:avl-util.h
policy.o cond.o: cond.h
analysis.o infoflow.o: infoflow.h
policy.o perm-map.o: perm-map.h
analysis.o infoflow.o poldiff.o: policy-query.h
analysis.o infoflow.o policy-io.h queue.o: queue.h
analysis.o avl-util.o clone.o cond.o: util.h
infoflow.o perm-map.o policy-avl.o policy.o polic-io.o policy-query.o: util.h
render.o util.o binpol/binpol.o: util.h
analysis.o: analysis.h
clone.o: clone.h
poldiff.o: poldiff.h
policy.o policy-avl.o: policy-avl.h
relabel_analysis.o: relabel_analysis.h
render.o: render.h
binpol/binpol.o policy-io.o: binpol/binpol.h
binpol/binpol.o binpol/bpmaps.o: binpol/bpmaps.h
binpol/binpol.o binpol/ebitmap.o: binpol/borrowed.h
binpol/binpol.o binpol/bpmaps.o binpol/ebitmap.o: binpol/ebitmap.h
binpol/binpol.o binpol/ebitmap.o binpol/fbuf.o: binpol/fbuf.h
poldiff.o relabel_analysis.o render.o dta.o: semantic/avhash.h semantic/avsemantics.h
semantic/avhash.o semantic/avsemantics.o: semantic/avhash.h
semantic/avsemantics.o: semantic/avsemantics.h
dta.o: dta.h
apol_tcl_other.o util.o: CFLAGS  += -DAPOL_INSTALL_DIR='"$(INSTALL_LIBDIR)"' -DAPOL_HELP_DIR='"$(INSTALL_HELPDIR)"'

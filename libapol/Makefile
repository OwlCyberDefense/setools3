# libapol and lipapol-tcl

LIB-OBJ	= policy.o policy-query.o policy-io.o queue.o util.o clone.o y.tab.o lex.yy.o
LIB-OBJ +=  avl-util.o policy-avl.o render.o analysis.o perm-map.o cond.o infoflow.o
LIB-OBJ +=  binpol/binpol.o binpol/bpmaps.o binpol/fbuf.o binpol/ebitmap.o
LIB-OBJ-TCL = apol_tcl.o
CFLAGS  += -DLIBAPOL_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS  += -DAPOL_INSTALL_DIR='"$(INSTALL_LIBDIR)"'
CFLAGS  += -DLIBAPOL_POLICY_INSTALL_DIR='"$(POLICY_INSTALL_DIR)"'
CFLAGS  += -DLIBAPOL_SELINUX_DIR='"$(SELINUX_DIR)"'
CFLAGS	+= -DLIBAPOL_DEFAULT_POLICY='"$(POLICY_SRC_FILE)"'
PIC_FLAG =

libapol: ../lib/libapol.a

libapol-tcl: ../lib/libapol-tcl.a

libapol-shared: ../lib/libapol.$(shell cat VERSION).so

../lib/libapol.a: ../lib $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 

../lib/libapol-tcl.a: ../lib $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL) 
	 
../lib/libapol.$(shell cat VERSION).so : PIC_FLAG = -fPIC

../lib/libapol.$(shell cat VERSION).so: ../lib $(LIB-OBJ)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$@ \
	    -o $@ $(LIB-OBJ) 
	    
install-libapol-shared: ../lib/libapol.$(shell cat VERSION).so
	install -m 644 ../lib/libapol.$(shell cat VERSION).so $(SHARED_LIB_INSTALL_DIR)
	/sbin/ldconfig -n $(SHARED_LIB_INSTALL_DIR)
	ln -sf $(SHARED_LIB_INSTALL_DIR)/libapol.$(shell cat VERSION).so $(SHARED_LIB_INSTALL_DIR)/libapol.so

install-libapol-static: ../lib/libapol.a
	mkdir -p $(SETOOLS_INCLUDE)
	install -m 644 ../lib/libapol.a $(STATIC_LIB_INSTALL_DIR)
	install -m 644 *.h $(SETOOLS_INCLUDE)
	
%.o:  %.c 
	$(CC) $(CFLAGS) $(PIC_FLAG) -o $@ -c $<

y.tab.c: apolicy_parse.y
	$(YACC) -d apolicy_parse.y	

lex.yy.c: apolicy_scan.l
	$(LEX) apolicy_scan.l

install: install-libapol-shared install-libapol-static

../lib:
	mkdir -p $@ 

clean:
	rm -f $(LIB-OBJ) *.o  core y.tab.c y.tab.h lex.yy.c *~ 

bare:
	rm -f $(LIB-OBJ) *.o  core y.tab.c y.tab.h lex.yy.c *~ ../lib/libapol.a ../lib/libapol-tcl.a \
		../lib/libseuser.$(shell cat VERSION).so



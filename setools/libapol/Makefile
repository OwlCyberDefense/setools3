# libapol and lipapol-tcl

LIB-OBJ	= policy.o policy-query.o policy-io.o queue.o util.o clone.o y.tab.o lex.yy.o
LIB-OBJ +=  avl-util.o policy-avl.o render.o analysis.o perm-map.o cond.o infoflow.o
LIB-OBJ +=  binpol/binpol.o binpol/bpmaps.o binpol/fbuf.o binpol/ebitmap.o
LIB-OBJ-TCL = apol_tcl.o
CFLAGS  += -DLIBAPOL_VERSION_STRING='"$(shell cat VERSION)"'
CFLAGS  += -DAPOL_INSTALL_DIR='"$(INSTALL_LIBDIR)"'

libapol: ../lib/libapol.a

libapol-tcl: ../lib/libapol-tcl.a


../lib/libapol.a: ../lib $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 


../lib/libapol-tcl.a: ../lib $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL) 

%.o:  %.c 
	$(CC) $(CFLAGS) -o $@ -c $<

y.tab.c: apolicy_parse.y
	$(YACC) -d apolicy_parse.y	

lex.yy.c: apolicy_scan.l
	$(LEX) apolicy_scan.l

../lib:
	mkdir -p $@ 

clean:
	rm -f $(LIB-OBJ) *.o  core y.tab.c y.tab.h lex.yy.c *~ 

bare:
	rm -f $(LIB-OBJ) *.o  core y.tab.c y.tab.h lex.yy.c *~ ../lib/libapol.a ../lib/libapol-tcl.a



# libapol and lipapol-tcl

LIB-OBJ	= policy.o policy-query.o policy-io.o queue.o util.o clone.o 
LIB-OBJ += y.tab.o lex.yy.o avl-util.o policy-avl.o render.o analysis.o 
LIB-OBJ += perm-map.o cond.o 
LIB-OBJ-TCL = apol_tcl.o
CFLAGS  += -DLIBAPOL_VERSION_STRING='"$(shell cat VERSION)"'

libapol: ../lib/libapol.a

libapol-tcl: ../lib/libapol-tcl.a


../lib/libapol.a: ../lib $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 


../lib/libapol-tcl.a: ../lib $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL) 

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

y.tab.c: apolicy_parse.y
	$(YACC) -d apolicy_parse.y	

lex.yy.c: apolicy_scan.l
	$(LEX) apolicy_scan.l

../lib:
	mkdir -p $@ 

clean:
	rm -f *.o  core y.tab.c y.tab.h lex.yy.c *~ 

bare:
	rm -f *.o  core y.tab.c y.tab.h lex.yy.c *~ ../lib/libapol.a ../lib/libapol-tcl.a



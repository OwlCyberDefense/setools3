# libseuser and libseuser-tcl

LIB-OBJ		= seuser_db.o 
LIB-OBJ-TCL = $(LIB-OBJ) seuser_tcl.o
CFLAGS      += -DLIBSEUSER_VERSION_STRING='"$(shell cat VERSION)"'


libseuser: ../lib/libseuser.a

libseuser-tcl: ../lib/libseuser-tcl.a

../lib/libseuser.a: ../lib $(LIB-OBJ) 
	 ar cr $@ $(LIB-OBJ) 
	 
../lib/libseuser-tcl.a: ../lib $(LIB-OBJ-TCL) 
	 ar cr $@ $(LIB-OBJ-TCL)

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

	
../lib:
	mkdir -p $@ 


clean:
	rm -f *.o  core *~

bare:
	rm -f *.o  core *~ ../lib/libseuser.a ../lib/libseuser-tcl.a 



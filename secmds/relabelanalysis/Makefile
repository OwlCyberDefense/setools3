CC = gcc
CFLAGS = -I. -I../../libapol/ -Wall 
LINKFLAGS = -lm -lselinux 

OBJS =  
LIBAPOL = ../../libapol/libapol.a 

most: $(OBJS) cmd-line-tool

all: most ../../libapol/relabel_analysis.o

cmd-line-tool: $(OBJS) ./relabel_analysis_tool.o
	$(CC) $(OBJS) relabel_analysis_tool.o $(LIBAPOL) -o relabel-analysis-tool $(LINKFLAGS) -lfl

test: $(OBJS) 
	cd ./test/; make ra-test

%.o : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean: test-clean
	rm -f core* *.o *~ relabel-analysis-tool

test-clean:
	cd ./test/; $(MAKE) clean

bare: clean
	rm -f core.* *.swap

test-bare: 
	cd ./test/; $(MAKE) bare

nuke: bare test-bare

again: clean test-clean all




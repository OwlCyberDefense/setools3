CC = gcc
CFLAGS = -I. -I../../libapol/ -Wall
LIBAPOL = ../../libapol/libapol.a
LINKFLAGS = -lm -lselinux -lfl

OBJS = relabel_analysis_test.o ../relabel_analysis.o

ra-test:  $(OBJS)
	$(CC) $(CFLAGS) -o ra-test $(OBJS) $(LIBAPOL) $(LINKFLAGS)
%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o core* *~

bare: clean
	rm -f ra-test core.*

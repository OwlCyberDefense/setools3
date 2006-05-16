PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(DESTDIR)/lib

LIBA = libqpol.a
TARGET = libqpol.so
SONAME = $(TARGET).1
LIBSO = $(TARGET).$(shell cat ../VERSION)

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

override CFLAGS += -I. -I../include

all: $(LIBA) $(LIBSO)

$(LIBA): $(OBJS)
	$(AR) cr $@ $^

$(LIBSO): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -Wl,-soname,$(SONAME)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	@echo "add install targets"

clean:
	-rm -f $(OBJS)

bare: clean
	-rm -f core core* *~ $(LIBA) $(LIBSO) $(TARGET)

.PHONY: all clean install bare

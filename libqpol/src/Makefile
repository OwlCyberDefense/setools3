PREFIX ?= $(DESTDIR)/usr
STATIC_LIB_INSTALL_DIR ?= $(PREFIX)/lib
SHARED_LIB_INSTALL_DIR ?= $(PREFIX)/lib

LIBA = libqpol.a
TARGET = libqpol.so
SONAME = $(TARGET).1
LIBSO = $(TARGET).$(shell cat ../VERSION)

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

SEPOL_DIR = /home/mowery/nsa-mainline/trunk/libsepol

LIBSEPOL = $(SEPOL_DIR)/src/libsepol.a
SEPOL_INCLUDE = $(SEPOL_DIR)/include

override CFLAGS += -I. -I../include -fpic -I$(SEPOL_INCLUDE)

all: $(LIBA) $(LIBSO) $(TARGET) $(SONAME)

$(LIBA): $(OBJS) $(LIBSEPOL)
	mkdir -p tmp_sepol
	rm -f tmp_sepol/*
	cp $(LIBSEPOL) tmp_sepol
	(cd tmp_sepol; ar x libsepol.a)
	$(AR) crs $@ $(OBJS) tmp_sepol/*.o
	rm -rf tmp_sepol

$(LIBSO): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) -Wl,-soname,$(SONAME),--version-script=./libqpol.map,-z,defs -Wl,--whole-archive $(LIBSEPOL) -Wl,--no-whole-archive

$(TARGET): $(LIBSO)
	ln -sf $< $@

$(SONAME): $(LIBSO)
	ln -sf $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: install-static install-shared

install-static: $(LIBA)
	test -d $(STATIC_LIB_INSTALL_DIR) || install -m 755 -d $(STATIC_LIB_INSTALL_DIR)
	install -m 644 libqpol.a $(STATIC_LIB_INSTALL_DIR)

install-shared: $(LIBSO)
	test -d $(SHARED_LIB_INSTALL_DIR) || install -m 755 -d $(SHARED_LIB_INSTALL_DIR)
	install -m 755 $(LIBSO) $(SHARED_LIB_INSTALL_DIR)
	cd $(SHARED_LIB_INSTALL_DIR) && ln -sf $(LIBSO) $(TARGET) && ln -sf $(LIBSO) $(SONAME)

clean:
	-rm -f $(OBJS)

bare: clean
	-rm -f core core* *~ $(LIBA) $(LIBSO) $(TARGET) $(SONAME)

.PHONY: all clean install bare

# sediff tools - command-line and GUI

LIBAPOL		= ../libapol/libapol.a
INCLUDE		= -I.. -I../libapol
GUI-OBJS	= sediff_gui.o sediff_treemodel.o utilgui.o sediff_rename_types.o sediff_find_window.o
GTK_CFLAGS      = `pkg-config --cflags libglade-2.0`
GTK_LIBS        = `pkg-config --libs libglade-2.0`
#ifdef G_THREADS_ENABLED
G_THREADS       =  `pkg-config --libs gthread-2.0`
#endif
GLADE_FILES     = sediff.glade

all: libapol sediff sediffx

sediff: sediff.o $(LIBAPOL) 
	$(CC) -o $@ sediff.o $(LIBAPOL) $(LIBS) $(LDFLAGS) $(LIBSELINUX) 

sediffx: $(LIBAPOL) $(GUI-OBJS)
	$(CC) $(GUI-OBJS) -o $@ -export-dynamic $(LIBAPOL) $(LDFLAGS) $(LIBSELINUX) $(LIBS) $(GTK_LIBS) $(G_THREADS)

install-nogui: sediff 
	install -m 755 sediff $(BINDIR);

	test -d $(MANDIR)/man1 || install -m 755 -d $(MANDIR)/man1
	install -m 644 ../man/sediff.1 $(MANDIR)/man1

install: all
	install -m 755 sediff sediffx $(BINDIR);
	install -m 644 $(GLADE_FILES) $(INSTALL_LIBDIR)
	install -m 644 sediff_help.txt $(INSTALL_HELPDIR)

	test -d $(MANDIR)/man1 || install -m 755 -d $(MANDIR)/man1
	install -m 644 ../man/sediff.1 $(MANDIR)/man1
	install -m 644 ../man/sediffx.1 $(MANDIR)/man1

%.o:  %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

$(GUI-OBJS): CFLAGS += $(GTK_CFLAGS)
sediff.o: CFLAGS += -DSEDIFF_VERSION_NUM='"$(shell cat SEDIFF_VERSION)"'
sediff_gui.o: CFLAGS += -DSEDIFF_VERSION_NUM='"$(shell cat SEDIFF_VERSION)"'
sediff_gui.o: CFLAGS += -DSEDIFF_GUI_VERSION_NUM='"$(shell cat SEDIFF_GUI_VERSION)"'

libapol:
	$(MAKE) -C .. libapol

clean:
	rm -f *.o core* sediff sediffx *~ *.bak *.gladep

bare: clean

.PHONY: clean bare libapol 

# include objects here for header dependencies
sediff_gui.o sediff_rename_types.o: sediff_gui.h
sediff_gui.o sediff_rename_types.o: sediff_rename_types.h
sediff_gui.o sediff_find_window.o: sediff_gui.h
sediff_gui.o sediff_find_window.o: sediff_find_window.h
sediff_treemodel.o: sediff_treemodel.h
support.o: support.h
sediff_gui.o utilgui.o: utilgui.h


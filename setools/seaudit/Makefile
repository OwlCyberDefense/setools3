OBJS	          = auditlogmodel.o seaudit.o query_window.o filter_window.o multifilter_window.o utilgui.o preferences.o seaudit_window.o seaudit_callback.o filtered_view.o
INCLUDE           = -I.. -I../libseaudit
GTK_CFLAGS        = `pkg-config --cflags libglade-2.0`
GTK_LIBS          = `pkg-config --libs libglade-2.0`
SEAUDIT_LIBS      = ../lib/libseaudit.a ../lib/libapol.a $(LIBS)
GLADE_FILES       = customize_filter_window.glade filter_window.glade prefer_window.glade query_window.glade multifilter_window.glade seaudit.glade
CFLAGS	          += -DDEFAULT_POLICY='"$(POLICY_SRC_FILE)"'
CFLAGS	          += -DDEFAULT_LOG='"$(DEFAULT_LOG_FILE)"' 
CFLAGS            += -DINSTALL_LIBDIR='"$(INSTALL_LIBDIR)"'
CFLAGS            += -DSEAUDIT_GUI_VERSION_STRING='"$(shell cat VERSION)"'

seaudit: $(OBJS) $(GTK-SOURCEVIEW-OBJS) ../lib/libseaudit.a ../lib/libapol.a
	$(CC) $(CFLAGS) $(INCLUDE) $(OBJS) -o $@ $(SEAUDIT_LIBS) $(GTK_LIBS)

../lib/libseaudit.a:
	cd ../; $(MAKE) libseaudit

../lib/libapol.a: 
	cd ../; $(MAKE) libapol

%.o:  %.c 
	$(CC) $(CFLAGS) $(GTK_CFLAGS) $(INCLUDE) -c $<

../lib:
	mkdir -p $@

install: seaudit
	install -m 755 seaudit $(BINDIR)
	install -m 644 $(GLADE_FILES) $(INSTALL_LIBDIR)
	install -m 644 seaudit_help.txt  $(INSTALL_LIBDIR)
	install -m 444 dot_seaudit $(INSTALL_LIBDIR)

clean:
	rm -f *.o seaudit *~ core* *.bak *.gladep

bare: clean
	rm -f ../lib/libseaudit.a

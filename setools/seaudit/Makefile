OBJS	          = auditlogmodel.o seaudit.o query_window.o filter_window.o multifilter_window.o utilgui.o preferences.o seaudit_window.o seaudit_callback.o filtered_view.o
INCLUDE           = -I.. -I../libseaudit
GTK_CFLAGS        = `pkg-config --cflags libglade-2.0`
GTK_LIBS          = `pkg-config --libs libglade-2.0`
SEAUDIT_LIBS      = ../libseaudit/libseaudit.a ../libapol/libapol.a $(LIBS)
GLADE_FILES       = customize_filter_window.glade filter_window.glade prefer_window.glade query_window.glade multifilter_window.glade seaudit.glade

CFLAGS	          += -DDEFAULT_LOG='"$(DEFAULT_LOG_FILE)"' 
CFLAGS            += -DINSTALL_LIBDIR='"$(INSTALL_LIBDIR)"'
CFLAGS            += -DSEAUDIT_GUI_VERSION_STRING='"$(shell cat VERSION)"'

LIBSELINUX      = -lselinux



ifeq ($(DEBUG), 1)
SEAUDIT_LIBS	= ../libseaudit/libseaudit.a ../libapol/libapol.a 
seaudit: $(OBJS) $(GTK-SOURCEVIEW-OBJS) $(SEAUDIT_LIBS)
	$(CC) $(CFLAGS) $(INCLUDE) $(OBJS) -o $@ $(SEAUDIT_LIBS) $(LIBS) $(GTK_LIBS)
else
SEAUDIT_LIBS	= ../libseaudit/libseaudit.so.$(shell cat ../libseaudit/VERSION) \
		  ../libapol/libapol.so.$(shell cat ../libapol/VERSION) $(LIBS)
seaudit: $(OBJS) $(GTK-SOURCEVIEW-OBJS) $(SEAUDIT_LIBS)
	$(CC) $(CFLAGS) $(INCLUDE) $(OBJS) -o $@ $(SEAUDIT_LIBS) $(LIBS) $(GTK_LIBS)
endif

../libseaudit/libseaudit.a:
	cd ../libseaudit; $(MAKE) libseaudit

../libseaudit/libseaudit.so.$(shell cat ../libseaudit/VERSION):
	cd ../libseaudit; $(MAKE) libseauditso

../libapol/libapol.a: 
	cd ../libapol; $(MAKE) libapol

../libapol/libapol.so.$(shell cat ../libapol/VERSION): 
	cd ../libapol; $(MAKE) libapolso

%.o:  %.c 
	$(CC) $(CFLAGS) $(GTK_CFLAGS) $(INCLUDE) -c $<

install: seaudit
	install -m 755 seaudit $(BINDIR)
	install -m 644 $(GLADE_FILES) $(INSTALL_LIBDIR)
	install -m 644 seaudit_help.txt  $(INSTALL_LIBDIR)
	install -m 444 dot_seaudit $(INSTALL_LIBDIR)

clean:
	rm -f *.o seaudit *~ core* *.bak *.gladep

bare: clean
	

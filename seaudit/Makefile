OBJS	          = auditlogmodel.o seaudit.o query_window.o filter_window.o multifilter_window.o utilgui.o preferences.o seaudit_window.o seaudit_callback.o filtered_view.o report_window.o
INCLUDE           = -I.. -I../libseaudit -I../libapol
GTK_CFLAGS        = `pkg-config --cflags libglade-2.0`
GTK_LIBS          = `pkg-config --libs libglade-2.0`
SEAUDIT_LIBS      = ../libseaudit/libseaudit.a ../libapol/libapol.a $(LIBS)
GLADE_FILES       = customize_filter_window.glade filter_window.glade prefer_window.glade query_window.glade multifilter_window.glade report_window.glade seaudit.glade

CFLAGS	          += -DDEFAULT_LOG='"$(DEFAULT_LOG_FILE)"' 
CFLAGS            += -DINSTALL_LIBDIR='"$(INSTALL_LIBDIR)"'
CFLAGS            += -DSEAUDIT_GUI_VERSION_STRING='"$(shell cat SEAUDIT_GUI_VERSION)"'
CFLAGS            += -DSEREPORT_VERSION_NUM='"$(shell cat SEAUDIT_REPORT_VERSION)"'

SEAUDIT_REPORT_BACKEND  = report.o

LIBXML_FLAGS    = `pkg-config --cflags libxml-2.0`
LIBXML_LIBS     = `pkg-config --libs libxml-2.0`

SEAUDIT_REPORT_CONF_FILE = seaudit-report.conf
SEAUDIT_REPORT_STYLESHEET = seaudit-report.css

LOGWATCH_DIR = /etc/log.d
LOGWATCH_GROUP = $(LOGWATCH_DIR)/conf/logfiles
LOGWATCH_SERVICE = $(LOGWATCH_DIR)/conf/services
LOGWATH_FILTER = $(LOGWATCH_DIR)/scripts/services

ifeq ($(DYNAMIC), 0)
SEAUDIT_LIBS	= ../libseaudit/libseaudit.a ../libapol/libapol.a $(LIBSELINUX)	
else
SEAUDIT_LIBS	= ../libseaudit/libseaudit.so.$(shell cat ../libseaudit/VERSION) \
		  ../libapol/libapol.so.$(shell cat ../libapol/VERSION) $(LIBS) $(LIBSELINUX)
endif

all: seaudit seaudit-report

seaudit: $(OBJS) $(SEAUDIT_LIBS) $(GTK-SOURCEVIEW-OBJS) $(SEAUDIT_REPORT_BACKEND)  
	$(CC) $(CFLAGS) $(INCLUDE) $(OBJS) -o $@ $(SEAUDIT_LIBS) $(SEAUDIT_REPORT_BACKEND) $(LIBS) $(GTK_LIBS) 

seaudit-report: $(SEAUDIT_REPORT_BACKEND) seaudit-report.o $(SEAUDIT_LIBS) 
	$(CC) $(INCLUDE) $(LINKFLAGS) -o $@ $(SEAUDIT_REPORT_BACKEND) seaudit-report.o $(SEAUDIT_LIBS) $(LIBXML_LIBS) $(LIBS) 
		
../libseaudit/libseaudit.a:
	cd ../libseaudit; $(MAKE) libseaudit

../libseaudit/libseaudit.so.$(shell cat ../libseaudit/VERSION):
	cd ../libseaudit; $(MAKE) libseauditso

../libapol/libapol.a: 
	cd ../libapol; $(MAKE) libapol

../libapol/libapol.so.$(shell cat ../libapol/VERSION): 
	cd ../libapol; $(MAKE) libapolso

%.o:  %.c 
	$(CC) $(CFLAGS) $(GTK_CFLAGS) $(LIBXML_FLAGS) $(INCLUDE) -c $<

install: seaudit seaudit-report
	install -m 755 seaudit $(BINDIR)
	install -m 755 seaudit-report $(BINDIR)
	install -m 644 $(GLADE_FILES) $(INSTALL_LIBDIR)
	install -m 644 seaudit_help.txt $(INSTALL_LIBDIR)
	install -m 444 dot_seaudit $(INSTALL_LIBDIR)
	install -m 644 $(SEAUDIT_REPORT_CONF_FILE) $(INSTALL_LIBDIR)
	install -m 644 $(SEAUDIT_REPORT_STYLESHEET) $(INSTALL_LIBDIR)

install-logwatch-service: 
	install -m 644 -Z system_u:object_r:etc_t seaudit-report-group.conf $(LOGWATCH_GROUP)
	install -m 644 -Z system_u:object_r:etc_t seaudit-report-service.conf $(LOGWATCH_SERVICE)
	install -m 755 -Z system_u:object_r:etc_t seaudit-report-service $(LOGWATH_FILTER)

clean:
	rm -f *.o seaudit seaudit-report *~ core* *.bak *.gladep

bare: clean
	

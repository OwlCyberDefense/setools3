# sepcut tool

TCL-STRIP-FILES = db.tcl top.tcl browser.tcl customize.tcl test.tcl tail.tcl
TCL-FILES	= head.tcl tmp.tcl
SEPCUT_HELP_FILE	= sepcut_help.txt

sepcut: $(TCL-FILES)
	cat $(TCL-FILES) | \
	sed -e 's/SEPCUT_GUI_VERSION/$(shell cat VERSION)/g' | \
	sed -e 's|SEPCUT_INSTALL_DIR|$(INSTALL_LIBDIR)|g' > $@ 
	chmod 755 $@

tmp.tcl: $(TCL-STRIP_FILES)
	cat $(TCL-STRIP-FILES) > $@
	# compact it by removing comments and empty lines
	perl -p -i -e 's/^\s*(\#[^!]*){0,1}$$//s' $@
	

%.o:  %.c 
	$(CC) $(CFLAGS) -c $<

%.tcl: 
# do nothing

install: sepcut
	install -m 755 sepcut $(BINDIR)
	install -m 644 $(SEPCUT_HELP_FILE) $(INSTALL_LIBDIR)

clean:
	rm -f sepcut *~ tmp.tcl

bare:
	rm -f sepcut *~ tmp.tcl







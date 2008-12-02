# This is the Makefile to install BWidget-1.4.1
# created September 22, 2003
# by Kevin Carr kcarr@tresys.com

# INSTALL_PATH is set based upon your current 
# version of tcl using the tcl_vars script.
INSTALL_PATH	= $(DESTDIR)/usr/share/tcl$(shell env tclsh ../tcl_vars)/.

install:
	tar -zxvf BWidget-1.4.1.tar.gz
	mv BWidget-1.4.1 $(INSTALL_PATH)

remove:
	rm -r $(INSTALL_PATH)/BWidget-1.4.1

clean:
	rm -Rf BWidget-1.4.1

bare:	clean
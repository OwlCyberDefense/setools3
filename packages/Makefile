# This is the Makefile to install BWidget-1.4.1
# created September 22, 2003
# by Kevin Carr kcarr@tresys.com

# Make sure INSTALL_PATH is set properly for your system!
INSTALL_PATH=/usr/share/tcl8.3/


install:
	tar -zxvf BWidget-1.4.1.tar.gz
	mv BWidget-1.4.1 $(INSTALL_PATH)

remove:
	rm -r $(INSTALL_PATH)/BWidget-1.4.1

rpm:
	rpmbuild -ta BWidget-1.4.1.tar.gz

clean:
	rm -rf BWidget-1.4.1/

bare:
	clean
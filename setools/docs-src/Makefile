# SE Tools Documentation makefile
TOP-DOCS = INSTALL INSTALL-RPM KNOWN-BUGS README


docs: apol-doc sepcut-doc seuser-doc seaudit-doc top-docs

top-docs:
	for file in $(TOP-DOCS); do \
		rm -f ../$$file; \
		cat $$file.in | sed -e 's/RELEASE_VERSION/$(shell cat ../VERSION)/g' | \
		sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../$$file; \
	done 
	
apol-doc: 
	rm -f ../apol/apol_help.txt; \
	cat apol_help_text.in | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat ../apol/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../apol/apol_help.txt
	
sepcut-doc: 
	rm -f ../sepct/sepcut_help.txt; \
	cat sepcut_help_text.in | \
	sed -e 's/SEPCUT_GUI_VERSION/$(shell cat ../sepct/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../sepct/sepcut_help.txt
	
seuser-doc: 
	rm -f ../seuser/seuser_help.txt; \
	cat seuser_help_text.in | \
	sed -e 's/SEUSER_GUI_VERSION/$(shell cat ../seuser/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../seuser/seuser_help.txt

seaudit-doc: 
	rm -f ../seaudit/seaudit_help.txt; \
	cat seaudit_help_text.in | \
	sed -e 's/SEAUDIT_GUI_VERSION/$(shell cat ../seaudit/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../seaudit/seaudit_help.txt


	
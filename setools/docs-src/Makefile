# SE Tools Documentation makefile
TOP-DOCS = INSTALL KNOWN-BUGS README
INSTALL_DOCS = KNOWN-BUGS README apol/*.txt sepct/sepcut_help.txt \
	       seuser/seuser_help.txt seaudit/seaudit_help.txt

docs: apol-doc sepcut-doc seuser-doc seaudit-doc top-docs

top-docs:
	for file in $(TOP-DOCS); do \
		rm -f ../$$file; \
		cat $$file.in | sed -e 's/RELEASE_VERSION/$(shell cat ../VERSION)/g' | \
		sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../$$file; \
	done 
	
apol-doc: 
	rm -f ../apol/*.txt; \
	cat apol_help_text.in | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat ../apol/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../apol/apol_help.txt \
	
	cat dta_help.in | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat ../apol/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../apol/dta_help.txt \
	
	cat iflow_help.in | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat ../apol/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../apol/iflow_help.txt
	
	cat obj_perms_help.in | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat ../apol/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../apol/obj_perms_help.txt
	
	cat types_relation_help.in | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat ../apol/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../apol/types_relation_help.txt
	
	cat file_relabel_help.in | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat ../apol/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../apol/file_relabel_help.txt
	
	cat flow_assertion_help.in | \
	sed -e 's/APOL_GUI_VERSION/$(shell cat ../apol/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../apol/flow_assertion_help.txt
	
sepcut-doc: 
	rm -f ../sepct/*.txt; \
	cat sepcut_help_text.in | \
	sed -e 's/SEPCUT_GUI_VERSION/$(shell cat ../sepct/VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../sepct/sepcut_help.txt
	
seuser-doc: 
	rm -f ../seuser/*.txt; \
	cat seuser_help_text.in | \
	sed -e 's/SEUSER_GUI_VERSION/$(shell cat ../seuser/GUI_VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../seuser/seuser_help.txt

seaudit-doc: 
	rm -f ../seaudit/*.txt; \
	cat seaudit_help_text.in | \
	sed -e 's/SEAUDIT_GUI_VERSION/$(shell cat ../seaudit/SEAUDIT_GUI_VERSION)/g' | \
	sed -e 's/MOD_DATE/$(shell date '+%B %d, %G')/g' > ../seaudit/seaudit_help.txt

remove-docs :
	rm -f ../apol/*.txt; \
	rm -f ../sepct/*.txt; \
	rm -f ../seuser/*.txt; \
	rm -f ../seaudit/*.txt; 
	for file in $(TOP-DOCS); do \
		rm -f ../$$file; \
	done

install:
	cd ..; \
	for file in $(INSTALL_DOCS); do \
		install -m 644 $$file ${INSTALL_HELPDIR}; \
	done 
	 
top:
	@echo "build from top directory"

install:
	test -d $(INCLUDE_DIR)/qpol || install -m 755 -d $(INCLUDE_DIR)/qpol
	install -m 644 $(wildcard qpol/*.h) $(INCLUDE_DIR)/qpol


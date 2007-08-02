if DO_SWIGIFY
  MAYBE_SWIG = swig
endif

SUBDIRS = src include tests $(MAYBE_SWIG)

libapol.a libapol.so:
	$(MAKE) -C src $@

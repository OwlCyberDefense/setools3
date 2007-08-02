if DO_SWIGIFY
  MAYBE_SWIG = swig
endif

SUBDIRS = src include tests $(MAYBE_SWIG)

libpoldiff.a libpoldiff.so:
	$(MAKE) -C src $@

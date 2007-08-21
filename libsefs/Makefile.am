if DO_SWIGIFY
  MAYBE_SWIG = swig
endif

SUBDIRS = src include tests $(MAYBE_SWIG)

libsefs.a libsefs.so:
	$(MAKE) -C src $@

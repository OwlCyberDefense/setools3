if DO_SWIGIFY
  MAYBE_SWIG = swig
endif

SUBDIRS = src include $(MAYBE_SWIG)

libpoldiff.a libpoldiff.so:
	$(MAKE) -C src $@

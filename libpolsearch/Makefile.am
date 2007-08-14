if DO_SWIGIFY
  MAYBE_SWIG = swig
endif

SUBDIRS = src include tests $(MAYBE_SWIG)

libpolsearch.a libpolsearch.so:
	$(MAKE) -C src $@

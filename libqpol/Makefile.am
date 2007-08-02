if DO_SWIGIFY
  MAYBE_SWIG = swig
endif

SUBDIRS = src include tests $(MAYBE_SWIG)

libqpol.a libqpol.so:
	$(MAKE) -C src $@

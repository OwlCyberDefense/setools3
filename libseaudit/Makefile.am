if DO_SWIGIFY
  MAYBE_SWIG = swig
endif

SUBDIRS = src include $(MAYBE_SWIG)

libseaudit.a libseaudit.so:
	$(MAKE) -C src $@

if DO_SWIGIFY_PYTHON
  MAYBE_PYSWIG = python
endif

if DO_SWIGIFY_JAVA
  MAYBE_JSWIG = java
endif

SUBDIRS = $(MAYBE_PYSWIG) $(MAYBE_JSWIG)

dist_noinst_DATA = qpol.i

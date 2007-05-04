if DO_SWIGIFY_PYTHON
  MAYBE_PYSWIG = python
endif

if DO_SWIGIFY_JAVA
  MAYBE_JSWIG = java
endif

if DO_SWIGIFY_TCL
  MAYBE_TCLSWIG = tcl
endif

SUBDIRS = $(MAYBE_PYSWIG) $(MAYBE_JSWIG) $(MAYBE_TCLSWIG)

dist_noinst_DATA = poldiff.i

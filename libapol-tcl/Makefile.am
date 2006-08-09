lib_LIBRARIES = libapol-tcl.a

AM_CFLAGS = -fpic @QPOL_CFLAGS@ @APOL_CFLAGS@ -DAPOL_INSTALL_DIR='"${apol_install_dir}"'

libapol_tcl_a_SOURCES = apol_tcl_other.c apol_tcl_other.h \
	apol_tcl_render.c apol_tcl_render.h \
	apol_tcl_components.c apol_tcl_components.h \
	apol_tcl_rules.c apol_tcl_rules.h \
	apol_tcl_fc.c apol_tcl_fc.h \
	apol_tcl_analysis.c apol_tcl_analysis.h
libapol_tcl_a_CFLAGS = $(AM_CFLAGS) @TCL_INCLUDES@

lib_LIBRARIES = libapol.a libapol-tcl.a

AM_CFLAGS = -fpic -I$(top_srcdir)/libqpol/include \
	-DAPOL_INSTALL_DIR='"${apol_install_dir}"' \
	-DAPOL_HELP_DIR='"${apol_help_dir}"' \
	-DLIBAPOL_POLICY_INSTALL_DIR='"@selinux_policy_dir@/policy"' \
	-DLIBAPOL_DEFAULT_POLICY='"@selinux_default_policy@"'

libapol_a_SOURCES = \
	policy.c policy.h \
	queue.c queue.h util.c util.h \
	avl-util.c avl-util.h \
	render.c render.h perm-map.c perm-map.h \
	analysis.c analysis.h \
	infoflow.c infoflow.h \
	dta.c dta.h poldiff.c poldiff.h old-policy-query.c old-policy-query.h \
	policy-io.c policy-io.h vector.c vector.h \
	policy-query.c policy-query.h \
	context-query.c context-query.h mls-query.c mls-query.h \
	type-query.c type-query.h class-perm-query.c class-perm-query.h \
	role-query.c role-query.h user-query.c user-query.h \
	bool-query.c bool-query.h isid-query.c isid-query.h \
	netcon-query.c netcon-query.h fscon-query.c fscon-query.h \
	avrule-query.c avrule-query.h terule-query.c terule-query.h \
	condrule-query.c condrule-query.h \
	rbacrule-query.c rbacrule-query.h rangetrans-query.c rangetrans-query.h \
	constraint-query.c constraint-query.h \
	relabel-analysis.c relabel-analysis.h

libapol_tcl_a_SOURCES = apol_tcl_other.c apol_tcl_other.h \
	apol_tcl_render.c apol_tcl_render.h \
	apol_tcl_components.c apol_tcl_components.h \
	apol_tcl_rules.c apol_tcl_rules.h \
	apol_tcl_fc.c apol_tcl_fc.h \
	apol_tcl_analysis.c apol_tcl_analysis.h
libapol_tcl_a_CFLAGS = $(AM_CFLAGS) @TCL_INCLUDES@

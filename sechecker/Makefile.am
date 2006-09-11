setoolsdir = @setoolsdir@
bin_PROGRAMS = sechecker

dist_setools_DATA = \
	sechecker_help.txt

profilesdir = @profile_install_dir@
dist_profiles_DATA = \
	profiles/all-checks.sechecker \
	profiles/analysis-checks.sechecker \
	profiles/devel-checks.sechecker \
	profiles/sechecker.dtd

AM_CFLAGS = @DEBUGCFLAGS@ @WARNCFLAGS@ @PROFILECFLAGS@ @SELINUX_CFLAGS@ \
	@QPOL_CFLAGS@ @APOL_CFLAGS@ @SEFS_CFLAGS@ @XML_CFLAGS@ \
	-DPROFILE_INSTALL_DIR='"${profile_install_dir}"'
AM_LDFLAGS = @DEBUGLDFLAGS@ @WARNLDFLAGS@ @PROFILELDFLAGS@

LDADD = @SELINUX_LIB_FLAG@ @APOL_LIB_FLAG@ @QPOL_LIB_FLAG@ @XML_LIBS@
sechecker_DEPENDENCIES = $(top_builddir)/libapol/src/libapol.so $(top_builddir)/libqpol/src/libqpol.so

if WANT_LIBSEFS
sechecker_LDADD = @SEFS_LIB_FLAG@ $(LDADD)
sechecker_DEPENDENCIES += $(top_builddir)/libsefs/src/libsefs.so
else
sechecker_LDADD = $(LDADD)
endif

sechecker_SOURCES = \
	sechecker.c sechecker.h \
	register_list.c register_list.h \
	sechk_parse.c sechk_parse.h \
	sechecker_cli.c \
	modules/attribs_wo_rules.c modules/attribs_wo_rules.h \
	modules/attribs_wo_types.c modules/attribs_wo_types.h \
	modules/domain_and_file.c modules/domain_and_file.h \
	modules/domains_wo_roles.c modules/domains_wo_roles.h \
	modules/find_assoc_types.c modules/find_assoc_types.h \
	modules/find_domains.c modules/find_domains.h \
	modules/find_file_types.c modules/find_file_types.h \
	modules/find_net_domains.c modules/find_net_domains.h \
	modules/find_netif_types.c modules/find_netif_types.h \
	modules/find_node_types.c modules/find_node_types.h \
	modules/find_port_types.c modules/find_port_types.h \
	modules/imp_range_trans.c modules/imp_range_trans.h \
	modules/inc_dom_trans.c modules/inc_dom_trans.h \
	modules/inc_mount.c modules/inc_mount.h \
	modules/inc_net_access.c modules/inc_net_access.h \
	modules/roles_wo_allow.c modules/roles_wo_allow.h \
	modules/roles_wo_types.c modules/roles_wo_types.h \
	modules/roles_wo_users.c modules/roles_wo_users.h \
	modules/spurious_audit.c modules/spurious_audit.h \
	modules/types_wo_allow.c modules/types_wo_allow.h \
	modules/unreachable_doms.c modules/unreachable_doms.h \
	modules/users_wo_roles.c modules/users_wo_roles.h

$(top_builddir)/libapol/libapol-tcl.a:
	$(MAKE) -C $(top_builddir)/libapol-tcl $(notdir $@)

$(top_builddir)/libapol/src/libapol.so:
	$(MAKE) -C $(top_builddir)/libapol/src $(notdir $@)

$(top_builddir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_builddir)/libqpol/src $(notdir $@)

$(top_builddir)/libsefs/src/libsefs.so:
	$(MAKE) -C $(top_builddir)/libsefs/src $(notdir $@)

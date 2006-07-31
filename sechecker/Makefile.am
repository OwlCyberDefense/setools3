bin_PROGRAMS = sechecker

profilesdir = @profile_install_dir@
profiles_DATA = \
	profiles/all-checks.sechecker \
	profiles/analysis-checks.sechecker \
	profiles/devel-checks.sechecker \
	profiles/sechecker.dtd

AM_CFLAGS = -I$(top_srcdir)/libqpol/include -I$(top_srcdir)/libapol/include \
	@XML_CFLAGS@ \
	-DPROFILE_INSTALL_DIR='"${profile_install_dir}"' \
	-DBASE_PATH='"${prefix}/share/setools-@VERSION@"'

LDADD = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so \
        @QPOL_LIB_FLAG@ @XML_LIBS@
sechecker_DEPENDENCIES = $(top_srcdir)/libapol/src/libapol.a $(top_srcdir)/libqpol/src/libqpol.so

if WANT_LIBSEFS
sechecker_LDADD = $(LDADD) $(top_srcdir)/libsefs/libsefs.a
sechecker_DEPENDENCIES += $(top_srcdir)/libsefs/libsefs.a
else
sechecker_LDADD = $(LDADD)
endif

sechecker_SOURCES = \
	sechecker.c sechecker.h \
	register_list.c register_list.h \
	sechk_parse.c sechk_pares.h \
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

$(top_srcdir)/libapol/src/libapol.a:
	$(MAKE) -C $(top_srcdir)/libapol/src $(notdir $@)

$(top_srcdir)/libqpol/src/libqpol.so:
	$(MAKE) -C $(top_srcdir)/libqpol/src $(notdir $@)

mostlyclean-local:
	-rm -f modules/*.o
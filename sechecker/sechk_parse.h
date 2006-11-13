/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#ifndef SECHK_PARSE_H
#define SECHK_PARSE_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "sechecker.h"

#include <libxml/xmlreader.h>
#include <assert.h>

/* sechecker parser keywords - this subset is exported because
 * they are predefined 'values' also used in the lib */
#define SECHK_PARSE_REQUIRE_POL_TYPE      "policy_type"
#define SECHK_PARSE_REQUIRE_POL_TYPE_SRC  "source"
#define SECHK_PARSE_REQUIRE_POL_TYPE_BIN  "binary"
#define SECHK_PARSE_REQUIRE_POL_VER       "policy_version"
#define SECHK_PARSE_REQUIRE_SELINUX       "selinux"
#define SECHK_PARSE_REQUIRE_MLS_POLICY    "mls_policy"
#define SECHK_PARSE_REQUIRE_MLS_SYSTEM    "mls_system"
#define SECHK_PARSE_REQUIRE_DEF_CTX       "default_ctx"

#define sechk_lib_parse_profile(path, lib)     sechk_lib_parse_xml_file(path, lib)

	int sechk_lib_parse_xml_file(const char *filename, sechk_lib_t * lib);
	int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t * lib);

#ifdef	__cplusplus
}
#endif

#endif

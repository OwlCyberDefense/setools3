/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/*
 * Author: jmowery@tresys.com
 *
 */

#ifndef SECHK_PARSE_H
#define SECHK_PARSE_H

#include "sechecker.h"

#include <libxml/xmlreader.h>
#include <assert.h>

/* xml parser keywords */
#define SECHK_PARSE_SECHECKER_TAG         "sechecker"
#define SECHK_PARSE_PROFILE_TAG           "profile"
#define SECHK_PARSE_MODULE_TAG            "module"
#define SECHK_PARSE_OPTION_TAG            "option"
#define SECHK_PARSE_REQUIRE_TAG           "require"
#define SECHK_PARSE_DEPENDENCY_TAG        "dependency"
#define SECHK_PARSE_OUTPUT_TAG            "output"
#define SECHK_PARSE_VALUE_ATTRIB          "value"
#define SECHK_PARSE_NAME_ATTRIB           "name"
#define SECHK_PARSE_VERSION_ATTRIB        "version"
#define SECHK_PARSE_OUTPUT_NONE           "none"
#define SECHK_PARSE_OUTPUT_SHORT          "short"
#define SECHK_PARSE_OUTPUT_QUIET          "quiet"
#define SECHK_PARSE_OUTPUT_LONG           "long"
#define SECHK_PARSE_OUTPUT_VERBOSE        "verbose"
#define SECHK_PARSE_REQUIRE_POL_TYPE      "policy_type"
#define SECHK_PARSE_REQUIRE_POL_TYPE_SRC  "source"
#define SECHK_PARSE_REQUIRE_POL_TYPE_BIN  "binary"
#define SECHK_PARSE_REQUIRE_POL_VER       "policy_version"
#define SECHK_PARSE_REQUIRE_SELINUX       "selinux"
#define SECHK_PARSE_REQUIRE_MLS_POLICY    "mls_policy"
#define SECHK_PARSE_REQUIRE_MLS_SYSTEM    "mls_system"

#define sechk_lib_parse_config_file(path, lib) sechk_lib_parse_xml_file(path, lib)
#define sechk_lib_parse_profile(path, lib)     sechk_lib_parse_xml_file(path, lib)

int sechk_lib_parse_xml_file(const char *filename, sechk_lib_t *lib);
int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t *lib);
int sechk_lib_grow_modules(sechk_lib_t *lib);

#endif

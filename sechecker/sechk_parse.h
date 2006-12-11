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

#define sechk_lib_parse_profile(path, lib)     sechk_lib_parse_xml_file(path, lib)

	int sechk_lib_parse_xml_file(const char *filename, sechk_lib_t * lib);
	int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t * lib);

#ifdef	__cplusplus
}
#endif

#endif

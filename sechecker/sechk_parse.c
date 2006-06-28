/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "sechk_parse.h"
#include "util.h"
#include <libxml/xmlreader.h>
#include <errno.h>

/* xml parser keywords */
#define SECHK_PARSE_SECHECKER_TAG         "sechecker"
#define SECHK_PARSE_PROFILE_TAG           "profile"
#define SECHK_PARSE_MODULE_TAG            "module"
#define SECHK_PARSE_OPTION_TAG            "option"
#define SECHK_PARSE_ITEM_TAG              "item"
#define SECHK_PARSE_OUTPUT_TAG            "output"
#define SECHK_PARSE_VALUE_ATTRIB          "value"
#define SECHK_PARSE_NAME_ATTRIB           "name"
#define SECHK_PARSE_VERSION_ATTRIB        "version"
#define SECHK_PARSE_OUTPUT_NONE           "none"
#define SECHK_PARSE_OUTPUT_QUIET          "quiet"
#define SECHK_PARSE_OUTPUT_SHORT          "short"
#define SECHK_PARSE_OUTPUT_VERBOSE        "verbose"

static char *build_dtd_path(void)
{
	char *path = NULL;
	int path_sz = 0;
	
	#ifdef PROFILE_INSTALL_DIR
	if (append_str(&path, &path_sz, "file://localhost") == -1)
		return NULL;

	if (append_str(&path, &path_sz, BASE_PATH) == -1)
		return NULL;

	if (append_str(&path, &path_sz, "/") == -1)
		return NULL;

	if (append_str(&path, &path_sz, PROFILE_INSTALL_DIR) == -1)
		return NULL;

	if (append_str(&path, &path_sz, "/sechecker.dtd") == -1)
		return NULL;

	return path;
	#endif
	
	return NULL;
}

 /* Parsing functions */

/* Parse the configuration file. */
int sechk_lib_parse_xml_file(const char *filename, sechk_lib_t *lib) 
{
	xmlTextReaderPtr reader = NULL;
	xmlDtdPtr dtd = NULL;
	xmlDocPtr xml = NULL;
	xmlValidCtxtPtr ctxt = NULL;
	int tmp, ret = 0;
	char *dtd_path = NULL;

	/* this initializes the XML library and checks potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used. */
	LIBXML_TEST_VERSION;
	reader = xmlReaderForFile(filename, NULL, 0);
	if (!reader) {
		ret = errno;
		if (ret != ENOENT)
			fprintf(stderr, "Error: Could not create xmlReader.\n");
		goto exit_err;
	}
	
	dtd_path = build_dtd_path();
	if (!dtd_path) {
		fprintf(stderr, "Error: getting DTD path\n");
		goto exit_err;
	}
	dtd = xmlParseDTD(NULL, (const xmlChar *)dtd_path);
	free(dtd_path);
	
	if (!dtd) {
		fprintf(stderr, "Error: parsing DTD\n");
		goto exit_err;
	}

	xml = xmlParseFile(filename);
	if (!xml) {
		fprintf(stderr, "Error: parsing sechecker profile\n");
		goto exit_err;
	}

	ctxt = xmlNewValidCtxt();
	if (!ctxt) {
		fprintf(stderr, "Error: out of memory\n");
		goto exit_err;
	}
	/* validate profile against the DTD */
	if (xmlValidateDtd(ctxt, xml, dtd) == 0) {
		fprintf(stderr, "Error: SEChecker profile contains invalid XML. Aborting.\n");
		goto exit_err;
	}

	while (1) {
		ret = xmlTextReaderRead(reader);
		if (ret == -1) {
			ret = errno;
			fprintf(stderr, "Error: Error reading xml.\n");
			goto exit_err;
		}
		if (ret == 0) /* no more nodes to read */
			break;
		
		tmp = sechk_lib_process_xml_node(reader, lib);
		if (tmp == -1)
			goto exit_err;
		if (tmp == 1) {
			ret = xmlTextReaderNext(reader);
			if (ret == 0)
				break;
			if (ret == -1) {
				ret = errno;
				fprintf(stderr, "Error in xmlTextReaderNext()\n");
				goto exit_err;
			}			
		}				
	}

	/* cleanup function for the XML library */
	xmlCleanupParser();
	xmlFreeTextReader(reader);
	return 0;

 exit_err:
	xmlCleanupParser();
	if (reader)
		xmlFreeTextReader(reader);
	if (ret)
		errno = ret;
	return -1;
}

/* process a single node in the xml file */
int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t *lib)
{
	xmlChar *attrib = NULL;
	int idx;
	sechk_name_value_t *nv = NULL;
	static xmlChar *option = NULL;
	static xmlChar *value = NULL;
	static sechk_module_t *current_module=NULL;	

	switch (xmlTextReaderNodeType(reader)) {

	case XML_ELEMENT_DECL: /* closing tags */
		if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_MODULE_TAG) == 1) {
			current_module = NULL;
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_OPTION_TAG) == 1) {
			free(option);
			option = NULL;
		} 
		break;

	case XML_ELEMENT_NODE: /* opening tags */

		if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_SECHECKER_TAG) == 1) {
			/* parsing the <sechecker> tag */
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VERSION_ATTRIB);
			if (attrib) {
				#ifdef SECHECKER_VERSION
				if (atof((const char *)attrib) > atof(SECHECKER_VERSION)) {
					fprintf(stderr, "Error: sechecker version in profile is incorrect: expected %1.1f got %1.1f\n",
						atof(SECHECKER_VERSION), atof((const char *)attrib));
					goto exit_err;
				}
				#endif

				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Warning: sechecker version is not specified.\n");
			}
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_MODULE_TAG) == 1) {
			/* parsing the <module> tag */
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				if ((idx = sechk_lib_get_module_idx((const char*)attrib, lib)) == -1) {
						fprintf(stderr, "Warning: module %s not found.\n", (const char*)attrib);
						return 1; /* not a fatal error */
				} else {
					/* set the values on the existing module */
					current_module = apol_vector_get_element(lib->modules, idx);
					current_module->selected = TRUE;
				}
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: module name is not specified.\n");
				goto exit_err;
			}
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_OPTION_TAG) == 1) {
			/* parsing the <option> tag */
			if (!current_module) {
				fprintf(stderr, "Error: 'option' specified outside the scope of a module.\n");
				goto exit_err;
			}
			/* read the name of the option */
			option = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (!option) {
				fprintf(stderr, "Error: option name is not specified.\n");
				goto exit_err;
			}
			/* clear the options with this name that were set by defualt for this module */
			sechk_lib_module_clear_option(current_module, (char*)option);

		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_ITEM_TAG) == 1) {
			/* parsing the <item> tag */
			assert(current_module);
			nv = sechk_name_value_new((char*)option, NULL);
			/* read the value for this name value pair */
			value = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (!value) {
				fprintf(stderr, "Error: item value is not specified.\n");
				goto exit_err;
			}
			nv->value = strdup((char*)value);
			/* add the nv pair to the module options */
			apol_vector_append(current_module->options, (void*)nv);

		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_OUTPUT_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'output' specified outside the scope of a module.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_QUIET) == 1) {
					current_module->outputformat = SECHK_OUT_QUIET;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_VERBOSE) == 1) {
					current_module->outputformat = SECHK_OUT_VERBOSE;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_SHORT) == 1) {
					current_module->outputformat = SECHK_OUT_SHORT;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_NONE) == 1) {
				       current_module->outputformat = SECHK_OUT_NONE;
				} else {
					fprintf(stderr, "Error: invalid output value %s.\n",attrib);
						goto exit_err;
				}
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: output value is not specified.\n");
				goto exit_err;
			}
		}
		break;
	}
	return 0;

 exit_err:
	sechk_name_value_free(nv);
	errno = EIO;
	return -1;
}


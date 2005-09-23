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

#define WHITESPACE " \t\n\r"

/* Parsing functions */

/*
 * Parse the configuration file. */
int sechk_lib_parse_xml_file(const char *filename, sechk_lib_t *lib) 
{
	xmlTextReaderPtr reader = NULL;
	int ret;

	/* this initializes the XML library and checks potential ABI mismatches
	 * between the version it was compiled for and the actual shared
	 * library used. */
	LIBXML_TEST_VERSION;
	reader = xmlReaderForFile(filename, NULL, 0);
	if (!reader) {
		fprintf(stderr, "Error: Could not create xmlReader.");
		goto exit_err;
	}
	
	while (1) {
		ret = xmlTextReaderRead(reader);
		if (ret == -1) {
			fprintf(stderr, "Error: Error reading xml.");
			goto exit_err;
		}
		if (ret == 0) /* no more nodes to read */
			break;
		if (sechk_lib_process_xml_node(reader, lib) != 0)
			goto exit_err;
	}

	/* cleanup function for the XML library */
	xmlCleanupParser();
	xmlFreeTextReader(reader);
	return 0;

 exit_err:
	xmlCleanupParser();
	if (reader)
		xmlFreeTextReader(reader);
	return -1;
}

/* options are now lists, this will parse the list remove any instances of the option that existed before
   in the module, and overwrite them */
static int sechk_lib_parse_module_option_list(sechk_module_t *module, xmlChar *option, const xmlChar *text_in)
{
	char *text = NULL;
	char *token = NULL;
	sechk_name_value_t *nv = NULL;
	int rt;
	if (!module || !option || !text_in) 
		return -1;
	/* put our text into something we can chop up */
	text = strdup((char *)text_in);
	/* chop it up and only grab the text */
	token = strsep(&text,WHITESPACE);
	while (token) {
		rt = trim_string(&token);
		if (rt < 0)
			return -1;
		if (strlen(token) > 0) 
			nv = sechk_name_value_prepend(nv,(char *)option,token);
		token = strsep(&text,WHITESPACE);
	}
	/* if we got anything in this nv we need to add it to the current one */
	if (nv) {
		sechk_lib_module_del_option(module,(char *)option);
		sechk_lib_module_add_option_list(module,nv);
	}
	return 0;
}

/*
 * process a single node in the xml file */
int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t *lib)
{
	xmlChar *attrib = NULL;
	static xmlChar *option = NULL;
	int idx;
	sechk_name_value_t *nv = NULL;
	static sechk_module_t *current_module=NULL;	
	static bool_t profile = FALSE;

	switch (xmlTextReaderNodeType(reader)) {

	case XML_ELEMENT_DECL: /* closing tags */
		if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_MODULE_TAG) == 1) {
			current_module = NULL;
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_OPTION_TAG) == 1) {
			free(option);
			option = NULL;
		}
		break;
	case XML_TEXT_NODE: /* this should only be the list */
		if (!option) {
			fprintf(stderr, "Warning: no option name specified for this option value\n");
			goto exit_err;
		}
		sechk_lib_parse_module_option_list(current_module, option, xmlTextReaderConstValue(reader));

	case XML_ELEMENT_NODE: /* opening tags */

		if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_SECHECKER_TAG) == 1) {
			/* parsing the <sechecker> tag */
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VERSION_ATTRIB);
			if (attrib) {
				/* TODO: add version logic */
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Warning: sechecker version is not specified.\n");
			}
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_PROFILE_TAG) == 1) {
			profile = TRUE; /* tell the parser that this is a test profile not a config file */
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_MODULE_TAG) == 1) {
			/* parsing the <module> tag */
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				if ((idx = sechk_lib_get_module_idx((const char*)attrib, lib)) == -1) {
					if (profile) {
						fprintf(stderr, "Error: module %s not found.\n", (const char*)attrib);
						goto exit_err;
					}
					/* set the values on a new module b/c it doesn't already exist */
					if (sechk_lib_grow_modules(lib) != 0)
						goto exit_err;
					lib->num_modules++;
					assert(lib->modules && lib->num_modules > 0);
					lib->modules[lib->num_modules-1].name = strdup((const char*)attrib);
					current_module = &lib->modules[lib->num_modules-1];
				} else {
					/* set the values on the existing module */
					current_module = &lib->modules[idx];
					lib->module_selection[idx] = TRUE;
				}
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: module name is not specified.\n");
				goto exit_err;
			}
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_OPTION_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'option' specified outside the scope of a module.\n");
				goto exit_err;
			}
			option = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (!option) {
				fprintf(stderr, "Error: option name is not specified.\n");
				goto exit_err;
			}
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
					if (profile) {
						current_module->outputformat = SECHK_OUT_NONE;
					} else {
						fprintf(stderr, "Error: output value of \"none\" is only valid in profiles.\n");
						goto exit_err;
					}
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
	if (nv) {
		sechk_name_value_destroy(nv);
	}
	return -1;
}


 

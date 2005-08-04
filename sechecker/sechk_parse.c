/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "sechk_parse.h"
#include <libxml/xmlreader.h>

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

/*
 * process a single node in the xml file */
int sechk_lib_process_xml_node(xmlTextReaderPtr reader, sechk_lib_t *lib)
{
	xmlChar *attrib = NULL;
	int idx;
	sechk_name_value_t *nv = NULL;
	static sechk_module_t *current_module=NULL;
	static bool_t profile = FALSE;


	switch (xmlTextReaderNodeType(reader)) {

	case XML_ELEMENT_DECL: /* closing tags */
		if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_MODULE_TAG) == 1) {
			current_module = NULL;
		} 
		break;

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
					if (profile) {
						/* set the values on the existing module */
						current_module = &lib->modules[idx];
						lib->module_selection[idx] = TRUE;
					} else {
						fprintf(stderr, "Error: duplicate definition of module %s in configuration file\n", (const char*)attrib);
						goto exit_err;
					}
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
			nv = sechk_name_value_new();
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				nv->name = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: option name is not specified.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				nv->value = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: option value is not specified.\n");
				goto exit_err;
			}

			nv->next = current_module->options;
			current_module->options = nv;
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_REQUIRE_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'require' specified outside the scope of a module.\n");
				goto exit_err;
			}
			if (profile) {
				fprintf(stderr, "Error: 'require' specified in profile (only valid in configuration file).\n");
				goto exit_err;
			}
			nv = sechk_name_value_new();
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				nv->name = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: require name is not specified in configuration file.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				nv->value = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: require value is not specified in configuration file.\n");
				goto exit_err;
			}
			nv->next = current_module->requirements;
			current_module->requirements = nv;
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_DEPENDENCY_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'dependency' specified outside the scope of a module.\n");
				goto exit_err;
			}
			if (profile) {
				fprintf(stderr, "Error: 'dependency' specified in profile (only valid in configuration file).\n");
				goto exit_err;
			}
			nv = sechk_name_value_new();
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_NAME_ATTRIB);
			if (attrib) {
				nv->name = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: dependency name is not specified in configuration file.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				nv->value = strdup((char*)attrib);
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: dependency value is not specified in configuration file.\n");
				goto exit_err;
			}
			nv->next = current_module->dependencies;
			current_module->dependencies = nv;
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_OUTPUT_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'output' specified outside the scope of a module.\n");
				goto exit_err;
			}
			attrib = xmlTextReaderGetAttribute(reader, (xmlChar*)SECHK_PARSE_VALUE_ATTRIB);
			if (attrib) {
				if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_SHORT) == 1) {
					current_module->outputformat = SECHK_OUT_SHORT;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_QUIET) == 1) {
					current_module->outputformat = SECHK_OUT_QUIET;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_LONG) == 1) {
					current_module->outputformat = SECHK_OUT_LONG;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_VERBOSE) == 1) {
					current_module->outputformat = SECHK_OUT_VERBOSE;
				} else if (xmlStrEqual(attrib, (xmlChar*)SECHK_PARSE_OUTPUT_NONE) == 1) {
					if (profile) {
						current_module->outputformat = SECHK_OUT_NONE;
					} else {
						fprintf(stderr, "Error: output value of \"none\" is only valid in profiles.\n");
						goto exit_err;
					}
				} else {
						fprintf(stderr, "Error: invalid output value.\n");
						goto exit_err;
				}
				free(attrib);
				attrib = NULL;
			} else {
				fprintf(stderr, "Error: output value is not specified.\n");
				goto exit_err;
			}
		} else if (xmlStrEqual(xmlTextReaderConstName(reader), (xmlChar*)SECHK_PARSE_HEADER_TAG) == 1) {
			if (!current_module) {
				fprintf(stderr, "Error: 'header' specified outside the scope of a module.\n");
				goto exit_err;
			}
			if (profile) {
				fprintf(stderr, "Error: 'header' specified in profile (only valid in configuration file).\n");
				goto exit_err;
			}
			attrib = xmlTextReaderReadString(reader);
			current_module->header = strdup((char*)attrib);
			free(attrib);
			attrib = NULL;
			
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

/*
 * check the size and grow appropriately - the array of modules and 
 * the boolean array of selected modules */
int sechk_lib_grow_modules(sechk_lib_t *lib)
{
	int i;

	if (lib == NULL)
		return -1;
	/* check if we need to grow */
	if (lib->modules_size <= lib->num_modules) {
		/* first grow the modules array */
		lib->modules = (sechk_module_t*)realloc(lib->modules, sizeof(sechk_module_t) * (lib->modules_size + LIST_SZ));
		if (!lib->modules) {
			fprintf(stderr, "Error: out of memory.\n");
			return -1;
		}
		/* then grow the selection array */
		lib->module_selection = (bool_t*)realloc(lib->module_selection, sizeof(bool_t) * (lib->modules_size + LIST_SZ));

		/* initialize any newly allocated memory */
		for (i = lib->num_modules; i < lib->num_modules + LIST_SZ; i++) {
			lib->module_selection[i] = FALSE;
			memset(&lib->modules[i], 0,  sizeof(sechk_module_t));
		}
		lib->modules_size += LIST_SZ;
	}
	return 0;
}

 

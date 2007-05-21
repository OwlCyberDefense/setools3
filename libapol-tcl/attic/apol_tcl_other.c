/**
 * @file
 *
 * Miscellaneous routines that translate between apol (a Tcl/Tk
 * application) and libapol.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2002-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <tcl.h>
#include <unistd.h>

#include <apol/perm-map.h>
#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>

#include "apol_tcl_render.h"
#include "apol_tcl_components.h"
#include "apol_tcl_rules.h"
#include "apol_tcl_fc.h"
#include "apol_tcl_analysis.h"

#include <qpol/policy.h>
#include <qpol/policy_extend.h>

apol_policy_t *policydb = NULL;
qpol_policy_t *qpolicydb = NULL;

/** severity of most recent message */
static int msg_level = INT_MAX;

/** pointer to most recent message string */
static char *message = NULL;

/** flag to indicate if a permission map has been loaded */
static int is_permmap_loaded = 0;

/**
 * Take the formated string, allocate space for it, and then write it
 * the policy's msg_callback_arg.  If there is already a string
 * stored, then append to the string if the message level is equal to
 * the previous one, overwrite the string if message level is less
 * than previous, else ignore the message.
 */
static void apol_tcl_route_handle_to_string(void *varg
					    __attribute__ ((unused)), apol_policy_t * p
					    __attribute__ ((unused)), int level, const char *fmt, va_list ap)
{
	char *s, *t;
	if (level == APOL_MSG_INFO && msg_level >= APOL_MSG_INFO) {
		/* generate an info event */
		free(message);
		message = NULL;
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(ENOMEM));
			return;
		}
		message = s;
		msg_level = level;
		Tcl_DoOneEvent(TCL_IDLE_EVENTS | TCL_DONT_WAIT);
	} else if (message == NULL || level < msg_level) {
		/* overwrite the existing stored message string with a
		 * new, higher priority message */
		free(message);
		message = NULL;
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(ENOMEM));
			return;
		}
		message = s;
		msg_level = level;
	} else if (level == msg_level) {
		/* append to existing error message */
		if (vasprintf(&s, fmt, ap) < 0) {
			fprintf(stderr, "%s\n", strerror(ENOMEM));
			return;
		}
		if (asprintf(&t, "%s\n%s", message, s) < 0) {
			free(s);
			fprintf(stderr, "%s\n", strerror(ENOMEM));
			return;
		}
		free(s);
		free(message);
		message = t;
	}
}

void apol_tcl_clear_error(void)
{
	free(message);
	message = NULL;
	msg_level = INT_MAX;
}

void apol_tcl_write_error(Tcl_Interp * interp)
{
	if (message != NULL) {
		Tcl_Obj *obj = Tcl_NewStringObj(message, -1);
		Tcl_ResetResult(interp);
		Tcl_SetObjResult(interp, obj);
		apol_tcl_clear_error();
	}
}

int apol_tcl_string_to_level(Tcl_Interp * interp, const char *level_string, apol_mls_level_t * level)
{
	Tcl_Obj *level_obj, *sens_obj, *cats_list_obj, *cats_obj;
	const char *sens_string, *cat_string;
	qpol_level_t *sens;
	qpol_cat_t *cat;
	int num_cats, i;

	if (policydb == NULL) {
		/* no policy, so nothing to convert */
		return 1;
	}
	level_obj = Tcl_NewStringObj(level_string, -1);
	if (Tcl_ListObjIndex(interp, level_obj, 0, &sens_obj) == TCL_ERROR ||
	    Tcl_ListObjIndex(interp, level_obj, 1, &cats_list_obj) == TCL_ERROR) {
		return -1;
	}
	if (sens_obj == NULL || cats_list_obj == NULL) {
		/* no sensitivity given -- this is an error */
		ERR(policydb, "%s", "Sensitivity string did not have two elements within it.");
		return -1;
	}
	sens_string = Tcl_GetString(sens_obj);
	if (qpol_policy_get_level_by_name(qpolicydb, sens_string, &sens) < 0) {
		/* unknown sensitivity */
		return 1;
	}
	if (apol_mls_level_set_sens(policydb, level, sens_string) < 0 ||
	    Tcl_ListObjLength(interp, cats_list_obj, &num_cats) == TCL_ERROR) {
		return -1;
	}
	for (i = 0; i < num_cats; i++) {
		if (Tcl_ListObjIndex(interp, cats_list_obj, i, &cats_obj) == TCL_ERROR) {
			return -1;
		}
		cat_string = Tcl_GetString(cats_obj);
		if (qpol_policy_get_cat_by_name(qpolicydb, cat_string, &cat) < 0) {
			/* unknown category */
			return 1;
		}
		if (apol_mls_level_append_cats(policydb, level, cat_string) < 0) {
			return -1;
		}
	}
	return 0;
}

int apol_tcl_string_to_range(Tcl_Interp * interp, const char *range_string, apol_mls_range_t * range)
{
	Tcl_Obj *range_obj = NULL, *low_obj, *high_obj;
	const char *low_string, *high_string;
	apol_mls_level_t *low_level = NULL, *high_level = NULL;
	int retval = -1, list_len;

	range_obj = Tcl_NewStringObj(range_string, -1);

	/* extract low level from string and process it */
	if (Tcl_ListObjIndex(interp, range_obj, 0, &low_obj) == TCL_ERROR) {
		goto cleanup;
	}
	if (low_obj == NULL) {
		ERR(policydb, "%s", "Range string must have at least one level given.");
		goto cleanup;
	}
	low_string = Tcl_GetString(low_obj);
	if ((low_level = apol_mls_level_create()) == NULL) {
		ERR(policydb, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	if ((retval = apol_tcl_string_to_level(interp, low_string, low_level)) != 0) {
		goto cleanup;
	}
	/* for now set the high level to be the same as low level --
	 * if there really is a high level in the string then that
	 * will overwrite this entry */
	if (apol_mls_range_set_low(policydb, range, low_level) < 0 || apol_mls_range_set_high(policydb, range, low_level)) {
		goto cleanup;
	}
	low_level = NULL;
	retval = -1;

	if (Tcl_ListObjLength(interp, range_obj, &list_len) == TCL_ERROR) {
		goto cleanup;
	}
	if (list_len != 1) {
		/* extract high level and process it */
		if (Tcl_ListObjIndex(interp, range_obj, 1, &high_obj) == TCL_ERROR) {
			goto cleanup;
		}
		high_string = Tcl_GetString(high_obj);
		if ((high_level = apol_mls_level_create()) == NULL) {
			ERR(policydb, "%s", strerror(ENOMEM));
			goto cleanup;
		}
		if ((retval = apol_tcl_string_to_level(interp, high_string, high_level)) != 0 ||
		    apol_mls_range_set_high(policydb, range, high_level) < 0) {
			goto cleanup;
		}
		high_level = NULL;
	}

	retval = 0;
      cleanup:
	apol_mls_level_destroy(&low_level);
	apol_mls_level_destroy(&high_level);
	return retval;
}

int apol_tcl_string_to_range_match(Tcl_Interp * interp, const char *range_match_string, unsigned int *flags)
{
	unsigned new_flag;
	if (strcmp(range_match_string, "exact") == 0) {
		new_flag = APOL_QUERY_EXACT;
	} else if (strcmp(range_match_string, "subset") == 0) {
		new_flag = APOL_QUERY_SUB;
	} else if (strcmp(range_match_string, "superset") == 0) {
		new_flag = APOL_QUERY_SUPER;
	} else if (strcmp(range_match_string, "intersect") == 0) {
		new_flag = APOL_QUERY_INTERSECT;
	} else {
		ERR(policydb, "Invalid range match string %s.", range_match_string);
		return -1;
	}
	*flags = (*flags & ~APOL_QUERY_FLAGS) | new_flag;
	return 0;
}

int apol_tcl_string_to_context(Tcl_Interp * interp, const char *context_string, apol_context_t * context)
{
	int num_elems;
	const char **context_elem = NULL;
	const char *user, *role, *type, *range_string;
	apol_mls_range_t *range = NULL;
	int retval = -1, retval2;
	if (Tcl_SplitList(interp, context_string, &num_elems, &context_elem) == TCL_ERROR) {
		goto cleanup;
	}
	if (num_elems < 3 || num_elems > 4) {
		ERR(policydb, "Invalid Tcl context object: %s.", context_string);
		goto cleanup;
	}
	user = context_elem[0];
	role = context_elem[1];
	type = context_elem[2];
	if ((*user != '\0' && apol_context_set_user(policydb, context, user) < 0) ||
	    (*role != '\0' && apol_context_set_role(policydb, context, role) < 0) ||
	    (*type != '\0' && apol_context_set_type(policydb, context, type) < 0)) {
		goto cleanup;
	}
	if (num_elems == 4) {
		range_string = context_elem[3];
		if (*range_string != '\0') {
			if ((range = apol_mls_range_create()) == NULL) {
				ERR(policydb, "%s", strerror(ENOMEM));
				goto cleanup;
			}
			retval2 = apol_tcl_string_to_range(interp, range_string, range);
			if (retval2 != 0) {
				retval = retval2;
				goto cleanup;
			}
			if (apol_context_set_range(policydb, context, range) < 0) {
				goto cleanup;
			}
			range = NULL;
		}
	}
	retval = 0;
      cleanup:
	apol_mls_range_destroy(&range);
	if (context_elem != NULL) {
		Tcl_Free((char *)context_elem);
	}
	return retval;
}

static void apol_tcl_reset_globals(void)
{
	apol_tcl_clear_error();
	is_permmap_loaded = 0;
	qpolicydb = NULL;
}

/**
 * Returns the policy version number for the currently opened policy.
 * If the policy is modular, return the maximum allowed policy as per
 * libsepol.
 */
static int Apol_GetPolicyVersionNumber(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	unsigned int version;
	Tcl_Obj *version_obj;

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		return TCL_ERROR;
	}
	if (apol_policy_get_policy_type(policydb) != QPOL_POLICY_MODULE_BINARY) {
		if (qpol_policy_get_policy_version(qpolicydb, &version) < 0) {
			apol_tcl_write_error(interp);
			return TCL_ERROR;
		}
	} else {
		version = SEPOL_POLICY_VERSION_MAX;
	}
	version_obj = Tcl_NewIntObj(version);
	Tcl_SetObjResult(interp, version_obj);
	return TCL_OK;
}

/**
 * Appends a name and size to a stats list, conveniently in a format
 * suitable for [array set].
 *
 * @param interp Tcl interpreter object.
 * @param name Statistic key.
 * @param size Value for statistic.
 * @param result_obj Tcl object to which append.
 *
 * @return 0 on success, < 0 on error.
 */
static int append_stats(Tcl_Interp * interp, char *name, size_t size, Tcl_Obj * result_list)
{
	Tcl_Obj *stat_elem[2];
	stat_elem[0] = Tcl_NewStringObj(name, -1);
	stat_elem[1] = Tcl_NewIntObj(size);
	if (Tcl_ListObjAppendElement(interp, result_list, stat_elem[0]) != TCL_OK ||
	    Tcl_ListObjAppendElement(interp, result_list, stat_elem[1]) != TCL_OK) {
		return -1;
	}
	return 0;
}

struct policy_stat
{
	char *name;
	int (*iter_func) (qpol_policy_t * policy, qpol_iterator_t ** iter);
};

/**
 * Checks if the permission map has been loaded yet.  Returns 1 if so,
 * 0 if not.
 */
static int Apol_IsPermMapLoaded(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	Tcl_SetResult(interp, (policydb != NULL && is_permmap_loaded ? "1" : "0"), TCL_STATIC);
	return TCL_OK;
}

/**
 * Find the default permission map file given its base name, and
 * return a newly allocated string to the path and file.
 *
 * @param perm_map_fname Base name of permission map file.
 *
 * @return An allocated string to the fully qualified path, or NULL on
 * error.  The caller is responsible for free()ing this string
 * afterwards.
 */
static char *find_perm_map_file(const char *perm_map_fname)
{
	char *script = NULL, *var = NULL;

	if (perm_map_fname == NULL)
		return NULL;

	/* first check environment variable */
	var = getenv(APOL_ENVIRON_VAR_NAME);
	if (var != NULL) {
		if (asprintf(&script, "%s/%s", var, perm_map_fname) == -1) {
			return NULL;
		}
		if (access(script, R_OK) == 0) {
			return script;
		}
	}

	/* next try installed directory */
	free(script);
	if (asprintf(&script, "%s/%s", APOL_INSTALL_DIR, perm_map_fname) == -1) {
		return NULL;
	}
	if (access(script, R_OK) == 0) {
		return script;
	}

	/* didn't find it! */
	free(script);
	return NULL;
}

/**
 * Given a base name, determine the full path to the permission map
 * file.  If no matching file was found then return an empty string.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>base name for permission map file
 * </ol>
 */
static int Apol_GetDefault_PermMap(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	char *pmap_file;
	if (argc != 2) {
		Tcl_SetResult(interp, "Need a permission map base name.", TCL_STATIC);
		return TCL_ERROR;
	}

	pmap_file = find_perm_map_file(argv[1]);
	if (pmap_file == NULL) {
		/* There is no system default perm map. User will have
		 * to load one explicitly. */
		return TCL_OK;
	}
	Tcl_SetResult(interp, pmap_file, TCL_VOLATILE);
	free(pmap_file);
	return TCL_OK;
}

/**
 * Load a perm map from disk.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>permission map file name
 * </ol>
 */
static int Apol_LoadPermMap(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	int retval = TCL_ERROR, rt = 0;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a permission map file name.");
		goto cleanup;
	}
	if ((rt = apol_permmap_load(policydb, argv[1])) < 0) {
		goto cleanup;
	}
	is_permmap_loaded = 1;
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR || rt > 0) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Save a permission map to disk.
 *
 * @param argv This function takes one parameter:
 * <ol>
 *   <li>permission map file name
 * </ol>
 */
static int Apol_SavePermMap(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	int retval = TCL_ERROR;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (!is_permmap_loaded) {
		ERR(policydb, "%s", "No permission map currently loaded!");
		goto cleanup;
	}
	if (argc != 2) {
		ERR(policydb, "%s", "Need a permission map file name.");
		goto cleanup;
	}
	if (apol_permmap_save(policydb, argv[1]) < 0) {
		goto cleanup;
	}

	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Look up a specific permission within the policy's permission map.
 * Return a Tcl string that represents that map:
 * <code>
 *   { perm_name map_type weight }
 * </code>
 *
 * @param interp Tcl interpreter object.
 * @param class_name Permission's class.
 * @param perm_name Name of permission.
 * @param Destination to create Tcl object representing mapping.
 *
 * @return 0 if permission was found, < 0 on error.
 */
static int build_tcl_perm_list(Tcl_Interp * interp, char *class_name, char *perm_name, Tcl_Obj ** obj)
{
	int map, weight;
	char *map_str;
	Tcl_Obj *perm_elem[3];

	if (apol_permmap_get(policydb, class_name, perm_name, &map, &weight) < 0) {
		return -1;
	}
	perm_elem[0] = Tcl_NewStringObj(perm_name, -1);
	switch (map) {
	case APOL_PERMMAP_READ:
		map_str = "r";
		break;
	case APOL_PERMMAP_WRITE:
		map_str = "w";
		break;
	case APOL_PERMMAP_BOTH:
		map_str = "b";
		break;
	case APOL_PERMMAP_NONE:
		map_str = "n";
		break;
	case APOL_PERMMAP_UNMAPPED:
		map_str = "u";
		break;
	default:
		map_str = "?";
	}
	perm_elem[1] = Tcl_NewStringObj(map_str, -1);
	perm_elem[2] = Tcl_NewIntObj(weight);
	*obj = Tcl_NewListObj(3, perm_elem);
	return 0;
}

/**
 * Return the currently loaded permission map as an unsorted list of
 * class entries.  Each class tuple consists of:
 * <ul>
 *   <li>class name
 *   <li>unsorted list of permission tuples
 * </ul>
 *
 * Each permission tuple consists of:
 * <ul>
 *   <li>permission name
 *   <li>mapping type, one of 'r', 'w', 'b', 'n', or 'u'
 *   <li>permission weight (an integer)
 * </ul>
 *
 * If a parameter is passed, then only the class tuple for the given
 * parameter is returned.
 */
static int Apol_GetPermMap(ClientData clientData, Tcl_Interp * interp, int argc, const char *argv[])
{
	int retval = TCL_ERROR;
	qpol_iterator_t *class_iter = NULL, *perm_iter = NULL, *common_iter = NULL;
	Tcl_Obj *result_obj = Tcl_NewListObj(0, NULL);

	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (!is_permmap_loaded) {
		ERR(policydb, "%s", "No permission map currently loaded!");
		goto cleanup;
	}
	if (qpol_policy_get_class_iter(qpolicydb, &class_iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(class_iter); qpol_iterator_next(class_iter)) {
		qpol_class_t *c;
		qpol_common_t *common;
		char *class_name, *perm_name;
		Tcl_Obj *class_elem[2], *class_list, *perm_list;
		if (qpol_iterator_get_item(class_iter, (void **)&c) < 0 || qpol_class_get_name(qpolicydb, c, &class_name) < 0) {
			goto cleanup;
		}
		if (argc >= 2 && strcmp(argv[1], class_name) != 0) {
			continue;
		}
		if (qpol_class_get_perm_iter(qpolicydb, c, &perm_iter) < 0 || qpol_class_get_common(qpolicydb, c, &common) < 0) {
			goto cleanup;
		}
		if (common != NULL && qpol_common_get_perm_iter(qpolicydb, common, &common_iter) < 0) {
			goto cleanup;
		}
		class_elem[0] = Tcl_NewStringObj(class_name, -1);
		class_elem[1] = Tcl_NewListObj(0, NULL);
		for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
			if (qpol_iterator_get_item(perm_iter, (void **)&perm_name) < 0 ||
			    build_tcl_perm_list(interp, class_name, perm_name,
						&perm_list) < 0 ||
			    Tcl_ListObjAppendElement(interp, class_elem[1], perm_list) == TCL_ERROR) {
				goto cleanup;
			}
		}
		for (; common_iter != NULL && !qpol_iterator_end(common_iter); qpol_iterator_next(common_iter)) {
			if (qpol_iterator_get_item(common_iter, (void **)&perm_name) < 0 ||
			    build_tcl_perm_list(interp, class_name, perm_name,
						&perm_list) < 0 ||
			    Tcl_ListObjAppendElement(interp, class_elem[1], perm_list) == TCL_ERROR) {
				goto cleanup;
			}
		}
		class_list = Tcl_NewListObj(2, class_elem);
		if (Tcl_ListObjAppendElement(interp, result_obj, class_list) == TCL_ERROR) {
			goto cleanup;
		}
		qpol_iterator_destroy(&perm_iter);
		qpol_iterator_destroy(&common_iter);
	}
	Tcl_SetObjResult(interp, result_obj);
	retval = TCL_OK;
      cleanup:
	qpol_iterator_destroy(&class_iter);
	qpol_iterator_destroy(&perm_iter);
	qpol_iterator_destroy(&common_iter);
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/**
 * Sets an individual permission mapping within the current policy.
 *
 * @param argv This function takes four parameter:
 * <ol>
 *   <li>class containing permission to change
 *   <li>name of permission to change
 *   <li>new map, one of "r", "w", "b", "n", or "u"
 *   <li>new weight, between APOL_PERMMAP_MIN_WEIGHT to
 *   APOL_PERMMAP_MAX_WEIGHT, inclusive
 * </ol>
 */
static int Apol_SetPermMap(ClientData clientData, Tcl_Interp * interp, int argc, CONST char *argv[])
{
	int retval = TCL_ERROR, map, weight;
	apol_tcl_clear_error();
	if (policydb == NULL) {
		Tcl_SetResult(interp, "No current policy file is opened!", TCL_STATIC);
		goto cleanup;
	}
	if (!is_permmap_loaded) {
		ERR(policydb, "%s", "No permission map currently loaded!");
		goto cleanup;
	}
	if (argc != 5) {
		ERR(policydb, "%s", "Need a class, permission, new map, and new weight.");
		goto cleanup;
	}
	switch (*argv[3]) {
	case 'r':
		map = APOL_PERMMAP_READ;
		break;
	case 'w':
		map = APOL_PERMMAP_WRITE;
		break;
	case 'b':
		map = APOL_PERMMAP_BOTH;
		break;
	case 'n':
		map = APOL_PERMMAP_NONE;
		break;
	case 'u':
		map = APOL_PERMMAP_UNMAPPED;
		break;
	default:
		ERR(policydb, "Invalid perm map %s.", argv[3]);
		goto cleanup;
	}
	if (Tcl_GetInt(interp, argv[4], &weight) == TCL_ERROR) {
		goto cleanup;
	}
	if (apol_permmap_set(policydb, argv[1], argv[2], map, weight) < 0) {
		goto cleanup;
	}
	retval = TCL_OK;
      cleanup:
	if (retval == TCL_ERROR) {
		apol_tcl_write_error(interp);
	}
	return retval;
}

/* Package initialization */
int apol_tcl_init(Tcl_Interp * interp)
{
	Tcl_CreateCommand(interp, "apol_GetPolicyVersionNumber", Apol_GetPolicyVersionNumber, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_IsPermMapLoaded", Apol_IsPermMapLoaded, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetDefault_PermMap", Apol_GetDefault_PermMap, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_LoadPermMap", Apol_LoadPermMap, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SavePermMap", Apol_SavePermMap, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_GetPermMap", Apol_GetPermMap, NULL, NULL);
	Tcl_CreateCommand(interp, "apol_SetPermMap", Apol_SetPermMap, NULL, NULL);

	if (apol_tcl_render_init(interp) != TCL_OK ||
	    apol_tcl_components_init(interp) != TCL_OK ||
	    apol_tcl_rules_init(interp) != TCL_OK ||
	    apol_tcl_fc_init(interp) != TCL_OK || apol_tcl_analysis_init(interp) != TCL_OK) {
		return TCL_ERROR;
	}
	Tcl_PkgProvide(interp, "apol", (char *)libapol_get_version());

	return TCL_OK;
}

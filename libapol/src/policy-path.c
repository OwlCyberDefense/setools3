/**
 * @file
 *
 * Implementation of policy path object.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#include <apol/policy-path.h>
#include <apol/util.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct apol_policy_path
{
	apol_policy_path_type_e path_type;
	char *base;
	apol_vector_t *modules;
};

apol_policy_path_t *apol_policy_path_create(apol_policy_path_type_e path_type, const char *path, const apol_vector_t * modules)
{
	apol_policy_path_t *p = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((p = calloc(1, sizeof(*p))) == NULL) {
		return NULL;
	}
	p->path_type = path_type;
	if ((p->base = strdup(path)) == NULL) {
		apol_policy_path_destroy(&p);
		return NULL;
	}
	if (p->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		if (modules == NULL) {
			p->modules = apol_vector_create();
		} else {
			p->modules = apol_vector_create_from_vector(modules, apol_str_strdup, NULL);
		}
		if (p->modules == NULL) {
			apol_policy_path_destroy(&p);
			return NULL;
		}
	}
	return p;
}

apol_policy_path_t *apol_policy_path_create_from_string(const char *path_string)
{
	apol_policy_path_t *p = NULL;
	apol_vector_t *tokens = NULL;
	apol_policy_path_type_e path_type;
	char *s;
	size_t i;
	if (path_string == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((tokens = apol_str_split(path_string, ":")) == NULL) {
		return NULL;
	}

	/* first token identifies the path type */
	if (apol_vector_get_size(tokens) < 2) {
		apol_vector_destroy(&tokens, free);
		return NULL;
	}
	s = apol_vector_get_element(tokens, 0);
	if (strcmp(s, "monolithic") == 0) {
		path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	} else if (strcmp(s, "modular") == 0) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
	} else {
		apol_vector_destroy(&tokens, free);
		errno = EINVAL;
		return NULL;
	}

	/* second token identifies gives base path */
	s = apol_vector_get_element(tokens, 1);
	if ((p = apol_policy_path_create(path_type, s, NULL)) == NULL) {
		apol_vector_destroy(&tokens, free);
		return NULL;
	}

	if (path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		/* remainder are module paths */
		for (i = 2; i < apol_vector_get_size(tokens); i++) {
			s = apol_vector_get_element(tokens, i);
			if ((s = strdup(s)) == NULL || apol_vector_append(p->modules, s) < 0) {
				free(s);
				apol_vector_destroy(&tokens, free);
				apol_policy_path_destroy(&p);
				return NULL;
			}
		}
	}
	return p;
}

void apol_policy_path_destroy(apol_policy_path_t ** path)
{
	if (path != NULL && *path != NULL) {
		free((*path)->base);
		apol_vector_destroy(&(*path)->modules, free);
		free(*path);
		*path = NULL;
	}
}

apol_policy_path_type_e apol_policy_path_get_type(const apol_policy_path_t * path)
{
	if (path == NULL) {
		errno = EINVAL;
		return APOL_POLICY_PATH_TYPE_MONOLITHIC;
	}
	return path->path_type;
}

const char *apol_policy_path_type_get_primary(const apol_policy_path_t * path)
{
	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return path->base;
}

const apol_vector_t *apol_policy_path_type_get_modules(const apol_policy_path_t * path)
{
	if (path == NULL || path->path_type != APOL_POLICY_PATH_TYPE_MODULAR) {
		errno = EINVAL;
		return NULL;
	}
	return path->modules;
}

char *apol_policy_path_to_string(const apol_policy_path_t * path)
{
	char *path_type;
	char *s = NULL;
	size_t len = 0, i;
	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (path->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		path_type = "modular";
	} else {
		path_type = "monolithic";
	}
	if (apol_str_appendf(&s, &len, "%s:%s", path_type, path->base) < 0) {
		return NULL;
	}
	if (path->path_type == APOL_POLICY_PATH_TYPE_MODULAR) {
		for (i = 0; i < apol_vector_get_size(path->modules); i++) {
			char *m = apol_vector_get_element(path->modules, i);
			if (apol_str_appendf(&s, &len, ":%s", m) < 0) {
				return NULL;
			}
		}
	}
	return s;
}

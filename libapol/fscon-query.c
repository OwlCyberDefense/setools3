/**
 * @file fscon-query.c
 *
 * Provides a way for setools to make queries about genfscons and
 * fs_use statements within a policy.  The caller obtains a query
 * object, fills in its parameters, and then runs the query; it
 * obtains a vector of results.  Searches are conjunctive -- all
 * fields of the search query must match for a datum to be added to
 * the results query.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

#include "component-query.h"

struct apol_genfscon_query {
        char *fs, *path;
	int objclass;
        apol_context_t *context;
	unsigned int flags;
};

struct apol_fs_use_query {
	char *fs;
	int behavior;
        apol_context_t *context;
	unsigned int flags;
};

/******************** genfscon queries ********************/

int apol_get_genfscon_by_query(apol_policy_t *p,
			       apol_genfscon_query_t *g,
			       apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1, retval2;
	sepol_genfscon_t *genfscon = NULL;
	*v = NULL;
	if (sepol_policydb_get_genfscon_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, (void **) &genfscon) < 0) {
			goto cleanup;
		}
		if (g != NULL) {
			char *fs, *path;
			uint32_t objclass;
			sepol_context_struct_t *context;
			if (sepol_genfscon_get_name(p->sh, p->p, genfscon, &fs) < 0 ||
			    sepol_genfscon_get_path(p->sh, p->p, genfscon, &path) < 0 ||
			    sepol_genfscon_get_class(p->sh, p->p, genfscon, &objclass) < 0 ||
			    sepol_genfscon_get_context(p->sh, p->p, genfscon, &context) < 0) {
				goto cleanup;
			}
			retval2 = apol_compare(p, fs, g->fs, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				free(genfscon);
				continue;
			}
			retval2 = apol_compare(p, path, g->path, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				free(genfscon);
				continue;
			}
			if (g->objclass >= 0 && g->objclass != objclass) {
				free(genfscon);
				continue;
			}
			retval2 = apol_compare_context(p, context, g->context, g->flags);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				free(genfscon);
				continue;
			}
		}
		if (apol_vector_append(*v, genfscon)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, free);
		free(genfscon);
	}
	sepol_iterator_destroy(&iter);
	return retval;
}

apol_genfscon_query_t *apol_genfscon_query_create(void)
{
	apol_genfscon_query_t *g = calloc(1, sizeof(apol_genfscon_query_t));
	if (g != NULL) {
		g->objclass = -1;
	}
	return g;
}

void apol_genfscon_query_destroy(apol_genfscon_query_t **g)
{
	if (*g != NULL) {
		free((*g)->fs);
		free((*g)->path);
		apol_context_destroy(&((*g)->context));
		free(*g);
		*g = NULL;
	}
}

int apol_genfscon_query_set_filesystem(apol_policy_t *p,
                                       apol_genfscon_query_t *g,
                                       const char *fs)
{
        return apol_query_set(p, &g->fs, NULL, fs);
}

int apol_genfscon_query_set_path(apol_policy_t *p,
				 apol_genfscon_query_t *g,
				 const char *path)
{
        return apol_query_set(p, &g->path, NULL, path);
}

int apol_genfscon_query_set_objclass(apol_policy_t *p,
				     apol_genfscon_query_t *g,
				     int objclass)
{
	if (objclass < 0) {
		g->objclass = -1;
	}
	else {
		switch (objclass) {
		case SEPOL_CLASS_BLK_FILE:
		case SEPOL_CLASS_CHR_FILE:
		case SEPOL_CLASS_DIR:
		case SEPOL_CLASS_FIFO_FILE:
		case SEPOL_CLASS_FILE:
		case SEPOL_CLASS_LNK_FILE:
		case SEPOL_CLASS_SOCK_FILE:
		case SEPOL_CLASS_ALL: {
			g->objclass = (int) objclass;
			break;
		}
		default:
			ERR(p, "Invalid object class given.");
			return -1;
		}
	}
	return 0;
}

int apol_genfscon_query_set_context(apol_policy_t *p __attribute__ ((unused)),
                                    apol_genfscon_query_t *g,
                                    apol_context_t *context,
                                    unsigned int range_match)
{
	if (g->context != NULL) {
		apol_context_destroy(&g->context);
	}
	g->context = context;
	g->flags = (g->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

/******************** fs_use queries ********************/

int apol_get_fs_use_by_query(apol_policy_t *p,
			     apol_fs_use_query_t *f,
			     apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1, retval2;
	sepol_fs_use_t *fs_use = NULL;
	*v = NULL;
	if (sepol_policydb_get_fs_use_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, (void **) &fs_use) < 0) {
			goto cleanup;
		}
		if (f != NULL) {
			char *fs;
			uint32_t behavior;
			sepol_context_struct_t *context;
			if (sepol_fs_use_get_name(p->sh, p->p, fs_use, &fs) < 0 ||
			    sepol_fs_use_get_behavior(p->sh, p->p, fs_use, &behavior) < 0 ||
			    sepol_fs_use_get_context(p->sh, p->p, fs_use, &context) < 0) {
				goto cleanup;
			}
			retval2 = apol_compare(p, fs, f->fs, 0, NULL);
			if (retval2 < 0) {
				goto cleanup;
			}
			else if (retval2 == 0) {
				continue;
			}
			if (f->behavior >= 0 && f->behavior != behavior) {
				continue;
			}
			/* recall that fs_use_psid statements do not
			 * have contexts */
			if (f->context != NULL && behavior == SEPOL_FS_USE_PSID) {
				retval2 = 0;
			}
			else {
				retval2 = apol_compare_context(p, context, f->context, f->flags);
				if (retval2 < 0) {
					goto cleanup;
				}
			}
			if (retval2 == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, fs_use)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	return retval;
}

apol_fs_use_query_t *apol_fs_use_query_create(void)
{
	apol_fs_use_query_t *f = calloc(1, sizeof(apol_fs_use_query_t));
	if (f != NULL) {
		f->behavior = -1;
	}
	return f;
}

void apol_fs_use_query_destroy(apol_fs_use_query_t **f)
{
	if (*f != NULL) {
		free((*f)->fs);
		apol_context_destroy(&((*f)->context));
		free(*f);
		*f = NULL;
	}
}

int apol_fs_use_query_set_filesystem(apol_policy_t *p,
				     apol_fs_use_query_t *f,
				     const char *fs)
{
	return apol_query_set(p, &f->fs, NULL, fs);
}

int apol_fs_use_query_set_behavior(apol_policy_t *p,
				   apol_fs_use_query_t *f,
				   int behavior)
{
	if (behavior < 0) {
		f->behavior = -1;
	}
	else {
		switch (behavior) {
		case SEPOL_FS_USE_XATTR:
		case SEPOL_FS_USE_TASK:
		case SEPOL_FS_USE_TRANS:
		case SEPOL_FS_USE_GENFS:
		case SEPOL_FS_USE_NONE:
		case SEPOL_FS_USE_PSID: {
			f->behavior = (int) behavior;
			break;
		}
		default:
			ERR(p, "Invalid fs_use behavior given.");
			return -1;
		}
	}
	return 0;
}

int apol_fs_use_query_set_context(apol_policy_t *p __attribute__ ((unused)),
				  apol_fs_use_query_t *f,
				  apol_context_t *context,
				  unsigned int range_match)
{
	if (f->context != NULL) {
		apol_context_destroy(&f->context);
	}
	f->context = context;
	f->flags = (f->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

/**
 *  @file
 *  Implementation of the sefs_fclist class.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#include "sefs_internal.hh"

#include <apol/util.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int fclist_sefs_context_node_comp(const void *a, const void *b, void *arg __attribute__ ((unused)))
{
	const struct sefs_context_node *n1 = static_cast < const struct sefs_context_node *>(a);
	const struct sefs_context_node *n2 = static_cast < const struct sefs_context_node *>(b);
	if (n1->type != n2->type)
	{
		return (int)n1->type - (int)n2->type;
	}
	if (n1->user != n2->user)
	{
		return (int)n1->user - (int)n2->user;
	}
	if (n1->role != n2->role)
	{
		return (int)n1->role - (int)n2->role;
	}
	return (int)n1->range - (int)n2->range;
}

static void fclist_sefs_context_node_free(void *elem)
{
	if (elem != NULL)
	{
		struct sefs_context_node *node = static_cast < struct sefs_context_node *>(elem);
		apol_context_destroy(&node->context);
		free(node->context_str);
		free(node);
	}
}

/******************** public functions below ********************/

sefs_fclist::~sefs_fclist()
{
	apol_bst_destroy(&user_tree);
	apol_bst_destroy(&role_tree);
	apol_bst_destroy(&type_tree);
	apol_bst_destroy(&range_tree);
	apol_bst_destroy(&path_tree);
	apol_bst_destroy(&context_tree);
}

void sefs_fclist::associatePolicy(apol_policy_t * new_policy)
{
	policy = new_policy;
	// FIX ME: convert all context nodes
}

apol_policy_t *sefs_fclist::associatePolicy() const
{
	return policy;
}

sefs_fclist_type_e sefs_fclist::type() const
{
	return fclist_type;
}

/******************** protected functions below ********************/

sefs_fclist::sefs_fclist(sefs_fclist_type_e type, sefs_callback_fn_t callback, void *varg)throw(std::bad_alloc)
{
	fclist_type = type;
	_callback = callback;
	_varg = varg;
	policy = NULL;
	user_tree = role_tree = type_tree = range_tree = path_tree = NULL;
	try
	{
		if ((user_tree = apol_bst_create(apol_str_strcmp, free)) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((role_tree = apol_bst_create(apol_str_strcmp, free)) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((type_tree = apol_bst_create(apol_str_strcmp, free)) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((range_tree = apol_bst_create(apol_str_strcmp, free)) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((path_tree = apol_bst_create(apol_str_strcmp, free)) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((context_tree = apol_bst_create(fclist_sefs_context_node_comp, fclist_sefs_context_node_free)) == NULL)
		{
			throw std::bad_alloc();
		}
	}
	catch(...)
	{
		apol_bst_destroy(&user_tree);
		apol_bst_destroy(&role_tree);
		apol_bst_destroy(&type_tree);
		apol_bst_destroy(&range_tree);
		apol_bst_destroy(&path_tree);
		apol_bst_destroy(&context_tree);
		throw;
	}
}

static void sefs_handle_default_callback(void *arg __attribute__ ((unused)),
					 sefs_fclist * f __attribute__ ((unused)), int level, const char *fmt, va_list va_args)
{
	switch (level)
	{
	case SEFS_MSG_INFO:
	{
		/* by default do not display these messages */
		return;
	}
	case SEFS_MSG_WARN:
	{
		fprintf(stderr, "WARNING: ");
		break;
	}
	case SEFS_MSG_ERR:
	default:
	{
		fprintf(stderr, "ERROR: ");
		break;
	}
	}
	vfprintf(stderr, fmt, va_args);
	fprintf(stderr, "\n");
}

void sefs_fclist::handleMsg(int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (_callback == NULL)
	{
		sefs_handle_default_callback(NULL, this, level, fmt, ap);
	}
	else
	{
		_callback(_varg, this, level, fmt, ap);
	}
	va_end(ap);
}

struct sefs_context_node *sefs_fclist::getContext(const char *user, const char *role, const char *type,
						  const char *range) throw(std::bad_alloc)
{
	char *u = NULL, *r = NULL, *t = NULL, *m = NULL;
	if ((u = strdup(user)) == NULL)
	{
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}
	if (apol_bst_insert_and_get(user_tree, (void **)&u, NULL) < 0)
	{
		free(u);
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}

	if ((r = strdup(role)) == NULL)
	{
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}
	if (apol_bst_insert_and_get(role_tree, (void **)&r, NULL) < 0)
	{
		free(r);
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}

	if ((t = strdup(type)) == NULL)
	{
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}
	if (apol_bst_insert_and_get(type_tree, (void **)&t, NULL) < 0)
	{
		free(t);
		SEFS_ERR("%s", strerror(errno));
		throw std::runtime_error(strerror(errno));
	}

	if (range == NULL)
	{
		m = NULL;
	}
	else
	{
		if ((m = strdup(range)) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (apol_bst_insert_and_get(range_tree, (void **)&m, NULL) < 0)
		{
			free(m);
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
	}

	struct sefs_context_node *node = NULL;
	apol_context_t *context = NULL;
	try
	{
		if ((node = static_cast < struct sefs_context_node * >(calloc(1, sizeof(*node)))) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}

		node->user = u;
		node->role = r;
		node->type = t;
		node->range = m;

		void *v;
		if (apol_bst_get_element(context_tree, node, NULL, &v) == 0)
		{
			// context already exists
			fclist_sefs_context_node_free(node);
			return static_cast < struct sefs_context_node *>(v);
		}
		if ((context = apol_context_create()) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
		if (apol_context_set_user(NULL, context, u) < 0 ||
		    apol_context_set_role(NULL, context, r) < 0 || apol_context_set_type(NULL, context, t) < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}

		// FIX ME: set the range

		node->context = context;
		context = NULL;

		// FIX ME: set this to <<none>> if nothing is set
		// FIX ME: if not MLS, don't print the star
		if ((node->context_str = apol_context_render(policy, node->context)) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}

		if (apol_bst_insert(context_tree, node, NULL) != 0)
		{
			SEFS_ERR("%s", strerror(errno));
			throw std::runtime_error(strerror(errno));
		}
	}
	catch(...)
	{
		fclist_sefs_context_node_free(node);
		apol_context_destroy(&context);
		throw;
	}

	return node;
}

/******************** C functions below ********************/

void sefs_fclist_destroy(sefs_fclist_t ** fclist)
{
	if (fclist != NULL && *fclist != NULL)
	{
		delete(*fclist);
		*fclist = NULL;
	}
}

apol_vector_t *sefs_fclist_run_query(sefs_fclist_t * fclist, sefs_query_t * query)
{
	if (fclist == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	apol_vector_t *v = NULL;
	try
	{
		v = fclist->runQuery(query);
	}
	catch(...)
	{
		return NULL;
	}
	return v;
}

bool sefs_fclist_get_is_mls(const sefs_fclist_t * fclist)
{
	if (fclist == NULL)
	{
		return false;
	}
	return fclist->isMLS();
}

void sefs_fclist_associate_policy(sefs_fclist_t * fclist, apol_policy_t * policy)
{
	if (fclist == NULL)
	{
		errno = EINVAL;
	}
	else
	{
		fclist->associatePolicy(policy);
	}
}

sefs_fclist_type_e sefs_fclist_get_type(sefs_fclist_t * fclist)
{
	if (fclist == NULL)
	{
		return SEFS_FCLIST_TYPE_NONE;
	}
	return fclist->type();
}

/******************** private static functions below ********************/

bool str_compare(const char *target, const char *str, const regex_t * regex, const bool regex_flag)
{
	if (str == NULL || str[0] == '\0' || target == NULL || target[0] == '\0')
	{
		return true;
	}
	if (regex_flag)
	{
		if (regexec(regex, target, 0, NULL, 0) == 0)
		{
			return true;
		}
		return false;
	}
	else
	{
		if (strcmp(target, str) == 0)
		{
			return true;
		}
		return false;
	}
}

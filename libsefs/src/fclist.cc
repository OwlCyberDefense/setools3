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

#include <sefs/entry.hh>
#include <apol/util.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <selinux/context.h>
#include <sys/types.h>

static int fclist_sefs_context_node_comp(const void *a, const void *b, void *arg __attribute__ ((unused)))
{
	const struct sefs_context_node *n1 = static_cast < const struct sefs_context_node *>(a);
	const struct sefs_context_node *n2 = static_cast < const struct sefs_context_node *>(b);
	if (n1->type != n2->type)
	{
		return static_cast < int >(reinterpret_cast < ssize_t > (n1->type) - reinterpret_cast < ssize_t > (n2->type));
	}
	if (n1->user != n2->user)
	{
		return static_cast < int >(reinterpret_cast < ssize_t > (n1->user) - reinterpret_cast < ssize_t > (n2->user));
	}
	if (n1->role != n2->role)
	{
		return static_cast < int >(reinterpret_cast < ssize_t > (n1->role) - reinterpret_cast < ssize_t > (n2->role));
	}
	return static_cast < int >(reinterpret_cast < ssize_t > (n1->range) - reinterpret_cast < ssize_t > (n2->range));
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

static int fclist_sefs_node_make_string(struct sefs_context_node *node)
{
	free(node->context_str);
	node->context_str = NULL;
	if (node->user[0] == '\0' && node->role[0] == '\0' && node->type[0] == '\0' &&
	    (node->range == NULL || node->range[0] == '\0'))
	{
		if ((node->context_str = strdup("<<none>>")) == NULL)
		{
			return -1;
		}
	}
	else
	{
		// instead of calling apol_context_render(), use a custom
		// rendering function if no range is set
		char *s = NULL;
		if (asprintf(&s, "%s:%s:%s", node->user, node->role, node->type) < 0)
		{
			return -1;
		}
		if (node->range != NULL)
		{
			size_t len = strlen(s) + 1;
			if (apol_str_appendf(&s, &len, ":%s", node->range) < 0)
			{
				free(s);
				return -1;
			}
		}
		node->context_str = s;
	}
	return 0;
}

static int fclist_sefs_node_convert(void *data, void *arg)
{
	struct sefs_context_node *node = static_cast < struct sefs_context_node *>(data);
	sefs_fclist *fclist = static_cast < sefs_fclist * >(arg);
	apol_policy_t *p = fclist->associatePolicy();
	if (p != NULL)
	{
		int retval = apol_context_convert(p, node->context);
		if (retval < 0)
		{
			return retval;
		}
		if ((retval = fclist_sefs_node_make_string(node)) < 0)
		{
			return retval;
		}
	}
	return 0;
}

/******************** public functions below ********************/

sefs_fclist::~sefs_fclist()
{
	apol_bst_destroy(&user_tree);
	apol_bst_destroy(&role_tree);
	apol_bst_destroy(&type_tree);
	apol_bst_destroy(&range_tree);
	apol_bst_destroy(&path_tree);
	apol_bst_destroy(&dev_tree);
	apol_bst_destroy(&context_tree);
}

static int map_to_vector(sefs_fclist * fclist, const sefs_entry * entry, void *data)
{
	apol_vector_t *v = static_cast < apol_vector_t * >(data);
	sefs_entry *new_entry = new sefs_entry(entry);
	if (apol_vector_append(v, new_entry) < 0)
	{
		return -1;
	}
	return 0;
}

static void fclist_entry_free(void *elem)
{
	if (elem != NULL)
	{
		sefs_entry *entry = static_cast < sefs_entry * >(elem);
		delete entry;
	}
}

apol_vector_t *sefs_fclist::runQuery(sefs_query * query) throw(std::bad_alloc, std::runtime_error)
{
	apol_vector_t *v = NULL;
	try
	{
		if ((v = apol_vector_create(fclist_entry_free)) == NULL)
		{
			throw std::bad_alloc();
		}
		if (runQueryMap(query, map_to_vector, v) < 0)
		{
			throw std::bad_alloc();
		}
	}
	catch(...)
	{
		apol_vector_destroy(&v);
		throw;
	}
	return v;
}

void sefs_fclist::associatePolicy(apol_policy_t * new_policy)
{
	policy = new_policy;
	if (policy != NULL)
	{
		if (apol_bst_inorder_map(context_tree, fclist_sefs_node_convert, policy) < 0)
		{
			throw new std::bad_alloc();
		}
	}
}

apol_policy_t *sefs_fclist::associatePolicy() const
{
	return policy;
}

sefs_fclist_type_e sefs_fclist::fclist_type() const
{
	return _fclist_type;
}

/******************** protected functions below ********************/

sefs_fclist::sefs_fclist(sefs_fclist_type_e type, sefs_callback_fn_t callback, void *varg)throw(std::bad_alloc)
{
	_fclist_type = type;
	_callback = callback;
	_varg = varg;
	policy = NULL;
	user_tree = role_tree = type_tree = range_tree = path_tree = NULL;
	dev_tree = NULL;
	context_tree = NULL;
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
		if ((dev_tree = apol_bst_create(apol_str_strcmp, free)) == NULL)
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
		apol_bst_destroy(&dev_tree);
		apol_bst_destroy(&context_tree);
		throw;
	}
}

static void sefs_handle_default_callback(void *arg __attribute__ ((unused)),
					 const sefs_fclist * f
					 __attribute__ ((unused)), int level, const char *fmt, va_list va_args)
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

void sefs_fclist::handleMsg(int level, const char *fmt, ...) const
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

	if (range == NULL || range[0] == '\0')
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

		apol_mls_range_t *apol_range = NULL;
		if (m != NULL)
		{
			if ((apol_range = apol_mls_range_create_from_literal(m)) == NULL)
			{
				SEFS_ERR("%s", strerror(errno));
				throw std::bad_alloc();
			}
		}

		if ((context = apol_context_create()) == NULL)
		{
			SEFS_ERR("%s", strerror(errno));
			apol_mls_range_destroy(&apol_range);
			throw std::runtime_error(strerror(errno));
		}
		if (apol_context_set_user(NULL, context, u) < 0 ||
		    apol_context_set_role(NULL, context, r) < 0 || apol_context_set_type(NULL, context, t) < 0 ||
		    apol_context_set_range(NULL, context, apol_range) < 0)
		{
			SEFS_ERR("%s", strerror(errno));
			apol_mls_range_destroy(&apol_range);
			throw std::runtime_error(strerror(errno));
		}

		node->context = context;
		context = NULL;

		if (fclist_sefs_node_make_string(node) < 0)
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

struct sefs_context_node *sefs_fclist::getContext(const security_context_t scon) throw(std::bad_alloc)
{
	context_t con;
	if ((con = context_new(scon)) == 0)
	{
		throw std::bad_alloc();
	}
	const char *user = context_user_get(con);
	const char *role = context_role_get(con);
	const char *type = context_type_get(con);
	const char *range = context_range_get(con);
	struct sefs_context_node *node = NULL;
	try
	{
		node = getContext(user, role, type, range);
	}
	catch(...)
	{
		context_free(con);
		throw;
	}
	context_free(con);
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

int sefs_fclist_run_query_map(sefs_fclist_t * fclist, sefs_query_t * query, sefs_fclist_map_fn_t fn, void *data)
{
	if (fclist == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	int retval;
	try
	{
		retval = fclist->runQueryMap(query, fn, data);
	}
	catch(...)
	{
		return -1;
	}
	return retval;
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

sefs_fclist_type_e sefs_fclist_get_fclist_type(const sefs_fclist_t * fclist)
{
	if (fclist == NULL)
	{
		return SEFS_FCLIST_TYPE_NONE;
	}
	return fclist->fclist_type();
}

/******************** private static functions below ********************/

/**
 * Given a type name, obtain its qpol_type_t pointer (relative to a
 * policy).  If the type is really its alias, get its primary instead.
 * (Attributes are considered to be always primary.)
 *
 * @param p Policy in which to look up types.
 * @param type_name Name of type to find.
 *
 * @return Qpol datum for type, or NULL if not found.
 */
static const qpol_type_t *query_get_type(apol_policy_t * p, const char *type_name)
{
	unsigned char isalias;
	const qpol_type_t *type = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	if (qpol_policy_get_type_by_name(q, type_name, &type) < 0 || qpol_type_get_isalias(q, type, &isalias) < 0)
	{
		return NULL;
	}
	if (isalias)
	{
		const char *primary_name;
		if (qpol_type_get_name(q, type, &primary_name) < 0 || qpol_policy_get_type_by_name(q, primary_name, &type) < 0)
		{
			return NULL;
		}
	}
	return type;
}

/**
 * Append a non-aliased type name to a vector.  If the passed in type
 * is an alias, find its primary type and append that name instead.
 *
 * @param p Policy in which to look up types.
 * @param v Vector in which append the non-aliased type name.
 * @param type Type or attribute to append.  If this is an alias,
 * append its primary.
 *
 * @return 0 on success, < 0 on error.
 */
static int query_append_type(apol_policy_t * p, apol_vector_t * v, const qpol_type_t * type)
{
	qpol_policy_t *q = apol_policy_get_qpol(p);
	unsigned char isalias;
	const qpol_type_t *real_type = type;
	const char *name;
	if (qpol_type_get_isattr(q, type, &isalias) < 0)
	{
		return -1;
	}
	if (isalias)
	{
		if (qpol_type_get_name(q, type, &name) < 0 || qpol_policy_get_type_by_name(q, name, &real_type) < 0)
		{
			return -1;
		}
	}
	if (qpol_type_get_name(q, type, &name) < 0 ||
	    apol_vector_append(v, const_cast < void *>(static_cast < const void *>(name))) < 0)
	{
		return -1;
	}
	return 0;
}

apol_vector_t *query_create_candidate_type(apol_policy_t * policy, const char *str, const regex_t * regex, const bool regex_flag,
					   const bool indirect)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	apol_vector_t *list = apol_vector_create(NULL);
	const qpol_type_t *type;
	qpol_iterator_t *iter = NULL, *alias_iter = NULL;
	const char *type_name;
	bool compval;

	try
	{
		if (list == NULL)
		{
			throw new std::bad_alloc();
		}

		if (!regex_flag && (type = query_get_type(policy, str)) != NULL)
		{
			if (query_append_type(policy, list, type) < 0)
			{
				throw new std::bad_alloc();
			}
		}

		if (regex_flag)
		{
			if (qpol_policy_get_type_iter(q, &iter) < 0)
			{
				throw new std::bad_alloc();
			}
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
			{
				if (qpol_iterator_get_item(iter, (void **)&type) < 0 || qpol_type_get_name(q, type, &type_name) < 0)
				{
					throw new std::runtime_error(strerror(errno));
				}
				compval = query_str_compare(type_name, str, regex, true);
				if (compval)
				{
					if (query_append_type(policy, list, type) < 0)
					{
						throw new std::bad_alloc();
					}
					continue;
				}
				if (qpol_type_get_alias_iter(q, type, &alias_iter) < 0)
				{
					throw new std::bad_alloc();
				}
				for (; !qpol_iterator_end(alias_iter); qpol_iterator_next(alias_iter))
				{
					if (qpol_iterator_get_item(alias_iter, (void **)&type_name) < 0)
					{
						throw new std::runtime_error(strerror(errno));
					}
					compval = query_str_compare(type_name, str, regex, true);
					if (compval)
					{
						if (query_append_type(policy, list, type))
						{
							throw new std::bad_alloc();
						}
						break;
					}
				}
				qpol_iterator_destroy(&alias_iter);
			}
			qpol_iterator_destroy(&iter);
		}

		if (indirect)
		{
			size_t orig_vector_size = apol_vector_get_size(list);
			unsigned char isattr, isalias;
			for (size_t i = 0; i < orig_vector_size; i++)
			{
				type = static_cast < qpol_type_t * >(apol_vector_get_element(list, i));
				if (qpol_type_get_isalias(q, type, &isalias) < 0 || qpol_type_get_isattr(q, type, &isattr) < 0)
				{
					throw new std::runtime_error(strerror(errno));
				}
				if (isalias)
				{
					continue;
				}
				if ((isattr &&
				     qpol_type_get_type_iter(q, type, &iter) < 0) ||
				    (!isattr && qpol_type_get_attr_iter(q, type, &iter) < 0))
				{
					throw new std::bad_alloc();
				}
				for (; !qpol_iterator_end(iter); qpol_iterator_next(iter))
				{
					if (qpol_iterator_get_item(iter, (void **)&type) < 0)
					{
						throw new std::runtime_error(strerror(errno));
					}
					if (query_append_type(policy, list, type))
					{
						throw new std::bad_alloc();
					}
				}
				qpol_iterator_destroy(&iter);
			}
		}

		apol_vector_sort_uniquify(list, NULL, NULL);
	}
	catch(...)
	{
		apol_vector_destroy(&list);
	}
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&alias_iter);
	return list;
}

bool query_str_compare(const char *target, const char *str, const regex_t * regex, const bool regex_flag)
{
	if (str == NULL || str[0] == '\0')
	{
		return true;
	}
	if (target == NULL || target[0] == '\0')
	{
		return false;
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

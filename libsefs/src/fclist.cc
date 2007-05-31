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

/******************** public functions below ********************/

sefs_fclist::~sefs_fclist()
{
	apol_bst_destroy(&user_tree);
	apol_bst_destroy(&role_tree);
	apol_bst_destroy(&type_tree);
	apol_bst_destroy(&range_tree);
	apol_bst_destroy(&path_tree);
}

void sefs_fclist::associatePolicy(apol_policy_t * new_policy)
{
	policy = new_policy;
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
	try {
		if ((user_tree = apol_bst_create(apol_str_strcmp, free)) == NULL) {
			throw new std::bad_alloc;
		}
		if ((role_tree = apol_bst_create(apol_str_strcmp, free)) == NULL) {
			throw new std::bad_alloc;
		}
		if ((type_tree = apol_bst_create(apol_str_strcmp, free)) == NULL) {
			throw new std::bad_alloc;
		}
		if ((range_tree = apol_bst_create(apol_str_strcmp, free)) == NULL) {
			throw new std::bad_alloc;
		}
		if ((path_tree = apol_bst_create(apol_str_strcmp, free)) == NULL) {
			throw new std::bad_alloc;
		}
	}
	catch(...) {
		apol_bst_destroy(&user_tree);
		apol_bst_destroy(&role_tree);
		apol_bst_destroy(&type_tree);
		apol_bst_destroy(&range_tree);
		apol_bst_destroy(&path_tree);
		throw;
	}
}

static void sefs_handle_default_callback(void *arg __attribute__ ((unused)),
					 sefs_fclist * f __attribute__ ((unused)), int level, const char *fmt, va_list va_args)
{
	switch (level) {
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
	if (_callback == NULL) {
		sefs_handle_default_callback(NULL, this, level, fmt, ap);
	} else {
		_callback(_varg, this, level, fmt, ap);
	}
	va_end(ap);
}

/******************** C functions below ********************/

void sefs_fclist_destroy(sefs_fclist_t ** fclist)
{
	if (fclist != NULL) {
		if (*fclist != NULL) {
			delete(*fclist);
		}
		*fclist = NULL;
	}
}

sefs_fclist_type_e sefs_fclist_get_type(sefs_fclist_t * fclist)
{
	if (fclist == NULL) {
		return SEFS_FCLIST_TYPE_NONE;
	}
	return fclist->type();
}

bool sefs_fclist_get_is_mls(const sefs_fclist_t * fclist)
{
	if (fclist == NULL) {
		return false;
	}
	return fclist->isMLS();
}

void sefs_fclist_associate_policy(sefs_fclist_t * fclist, apol_policy_t * policy)
{
	if (fclist == NULL) {
		errno = EINVAL;
	} else {
		fclist->associatePolicy(policy);
	}
}

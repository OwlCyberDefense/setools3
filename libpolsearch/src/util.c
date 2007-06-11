/**
 * @file
 *
 * Implementation of utility functions for libpolsearch.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2007 Tresys Technology, LLC
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

#include <polsearch/util.h>

#include <errno.h>

const char *libpolsearch_get_version(void)
{
	return LIBPOLSEARCH_VERSION_STRING;
}

const char *libpolsearch_symbol_get_name(const void *symbol, polsearch_symbol_e sym_type, const apol_policy_t * p)
{
	//TODO
	if (!p) {
		errno = EINVAL;
		return NULL;
	}
	qpol_policy_t *qp = apol_policy_get_qpol(p);
	const char *name = NULL;
	switch (sym_type) {
	case POLSEARCH_SYMBOL_TYPE:
	case POLSEARCH_SYMBOL_ATTRIBUTE:
	{
		qpol_type_get_name(qp, symbol, &name);
		break;
	}
	case POLSEARCH_SYMBOL_ROLE:
	{
	}
	case POLSEARCH_SYMBOL_USER:
	{
	}
	case POLSEARCH_SYMBOL_CLASS:
	{
	}
	case POLSEARCH_SYMBOL_COMMON:
	{
	}
	case POLSEARCH_SYMBOL_CATEGORY:
	{
	}
	case POLSEARCH_SYMBOL_LEVEL:
	{
	}
	case POLSEARCH_SYMBOL_BOOL:
	{
	}
	case POLSEARCH_SYMBOL_NONE:
	default:
	{
		errno = EINVAL;
		return NULL;
	}
	}
	return name;
}

const char *polsearch_symbol_type_to_string(polsearch_symbol_e sym_type)
{
	//TODO
	return "";
}

polsearch_symbol_e polsearch_sting_to_symbol_type(const char *str)
{
	//TODO
	return POLSEARCH_SYMBOL_NONE;
}

const char *polsearch_element_type_to_string(polsearch_element_e elem_type)
{
	//TODO
	return "";
}

polsearch_element_e polsearch_sting_to_element_type(const char *str)
{
	//TODO
	return POLSEARCH_ELEMENT_NONE;
}

char *polsearch_element_to_string(const void *elem, polsearch_element_e elem_type, const apol_policy_t * p,
				  const sefs_fclist_t * fclist)
{
	//TODO
	return strdup("");
}

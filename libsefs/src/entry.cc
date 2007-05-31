/**
 *  @file
 *  Implementation of the sefs_entry class.
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
#include <qpol/genfscon_query.h>

#include <assert.h>
#include <errno.h>

/******************** public functions below ********************/

const apol_context_t *sefs_entry::context() const
{
	return _context;
}

ino64_t sefs_entry::inode() const
{
	return _inode;
}

dev_t sefs_entry::dev() const
{
	return _dev;
}

uint32_t sefs_entry::objectClass() const
{
	return _objectClass;
}

const apol_vector_t *sefs_entry::paths() const
{
	return _paths;
}

const char *sefs_entry::origin() const
{
	return _origin;
}

char *sefs_entry::toString() const throw(std::bad_alloc)
{
	char *class_str, *context_str;

	switch (_objectClass)
	{
	case QPOL_CLASS_ALL:
		class_str = "  ";
		break;
	case QPOL_CLASS_BLK_FILE:
		class_str = "-b";
		break;
	case QPOL_CLASS_CHR_FILE:
		class_str = "-c";
		break;
	case QPOL_CLASS_DIR:
		class_str = "-d";
		break;
	case QPOL_CLASS_FIFO_FILE:
		class_str = "-p";
		break;
	case QPOL_CLASS_FILE:
		class_str = "--";
		break;
	case QPOL_CLASS_LNK_FILE:
		class_str = "-l";
		break;
	case QPOL_CLASS_SOCK_FILE:
		class_str = "-s";
		break;
	default:
		// should never get here
		assert(0);
		class_str = "-?";
	}

	apol_policy_t *p = _fclist->associatePolicy();
	if ((context_str = apol_context_render(p, _context)) == NULL)
	{
		throw std::bad_alloc();
	}

	char *s = NULL;
	size_t len = 0;
	for (size_t i = 0; i < apol_vector_get_size(_paths); i++)
	{
		char *path = static_cast < char *>(apol_vector_get_element(_paths, i));
		if (apol_str_appendf(&s, &len, "%s\t%s\t%s", path, class_str, context_str) < 0)
		{
			_fclist->SEFS_ERR("%s", strerror(errno));
			free(s);
			free(context_str);
			throw std::bad_alloc();
		}
	}
	return s;
}

/******************** private functions below ********************/

sefs_entry::sefs_entry(class sefs_fclist * fclist, const apol_context_t * context, uint32_t objectClass, const char *path,
		       const char *origin)throw(std::bad_alloc)
{
	_fclist = fclist;
	_context = context;
	_objectClass = objectClass;
	_paths = NULL;
	_inode = 0;
	_dev = 0;
	_origin = origin;
	try
	{
		if ((_paths = apol_vector_create_with_capacity(1, NULL)) == NULL)
		{
			_fclist->SEFS_ERR("%s", strerror(errno));
			throw std::bad_alloc();
		}
		// cast below is safe because the string is never
		// modified by this class, and header file says that
		// user must never change the string
		if (apol_vector_append(_paths, const_cast < char *>(path)) < 0)
		{
			_fclist->SEFS_ERR("%s", strerror(errno));
			throw std::bad_alloc();
		}
	}
	catch(...)
	{
		apol_vector_destroy(&_paths);
		throw;
	}
}

/******************** C functions below ********************/

const apol_context_t *sefs_entry_get_context(const sefs_entry_t * ent)
{
	if (ent == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	return ent->context();
}

ino64_t sefs_entry_get_inode(const sefs_entry_t * ent)
{
	if (ent == NULL)
	{
		errno = EINVAL;
		return 0;
	}
	return ent->inode();
}

dev_t sefs_entry_get_dev(const sefs_entry_t * ent)
{
	if (ent == NULL)
	{
		errno = EINVAL;
		return 0;
	}
	return ent->dev();
}

uint32_t sefs_entry_get_object_class(const sefs_entry_t * ent)
{
	if (ent == NULL)
	{
		errno = EINVAL;
		return QPOL_CLASS_ALL;
	}
	return ent->objectClass();
}

const apol_vector_t *sefs_entry_get_paths(const sefs_entry_t * ent)
{
	if (ent == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	return ent->paths();
}

const char *sefs_entry_get_origin(const sefs_entry_t * ent)
{
	if (ent == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	return ent->origin();
}

char *sefs_entry_to_string(const sefs_entry_t * ent)
{
	if (ent == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	return ent->toString();
}

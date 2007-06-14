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

sefs_entry::sefs_entry(const sefs_entry * e)
{
	_fclist = e->_fclist;
	_context = e->_context;
	_inode = e->_inode;
	_dev = e->_dev;
	_objectClass = e->_objectClass;
	_path = e->_path;
	_origin = e->_origin;
}

sefs_entry::~sefs_entry()
{
	// do nothing
}

const apol_context_t *sefs_entry::context() const
{
	return _context->context;
}

ino64_t sefs_entry::inode() const
{
	return _inode;
}

const char *sefs_entry::dev() const
{
	return _dev;
}

uint32_t sefs_entry::objectClass() const
{
	return _objectClass;
}

const char *sefs_entry::path() const
{
	return _path;
}

const char *sefs_entry::origin() const
{
	return _origin;
}

char *sefs_entry::toString() const throw(std::bad_alloc)
{
	char *class_str;

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

	char *s = NULL;
	if (asprintf(&s, "%s\t%s\t%s", _path, class_str, _context->context_str) < 0)
	{
		_fclist->SEFS_ERR("%s", strerror(errno));
		throw std::bad_alloc();
	}
	return s;
}

/******************** private functions below ********************/

sefs_entry::sefs_entry(class sefs_fclist * fclist, const struct sefs_context_node * context, uint32_t objectClass,
		       const char *new_path, const char *origin)
{
	_fclist = fclist;
	_context = context;
	_objectClass = objectClass;
	_inode = 0;
	_dev = NULL;
	_path = new_path;
	_origin = origin;
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

const char *sefs_entry_get_dev(const sefs_entry_t * ent)
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

const char *sefs_entry_get_path(const sefs_entry_t * ent)
{
	if (ent == NULL)
	{
		errno = EINVAL;
		return NULL;
	}
	return ent->path();
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

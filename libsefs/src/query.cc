/**
 *  @file
 *  Implementation of the sefs_query class.
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

#include <sefs/query.hh>
#include <apol/util.h>
#include <qpol/genfscon_query.h>

#include <assert.h>
#include <errno.h>

/******************** public functions below ********************/

sefs_query::sefs_query()
{
	_user = _role = _type = _range = NULL;
	_path = NULL;
	_objclass = QPOL_CLASS_ALL;
	_indirect = _regex = _recursive = false;
	_inode = 0;
	_dev = 0;
	_recompiled = false;
	_reuser = _rerole = _retype = _rerange = _repath = NULL;
}

sefs_query::~sefs_query()
{
	free(_user);
	free(_role);
	free(_type);
	free(_range);
	if (_recompiled)
	{
		regfree(_reuser);
		free(_reuser);
		regfree(_rerole);
		free(_rerole);
		regfree(_retype);
		free(_retype);
		regfree(_rerange);
		free(_rerange);
		regfree(_repath);
		free(_repath);
	}
}

void sefs_query::user(const char *name) throw(std::bad_alloc)
{
	if (name != _user)
	{
		free(_user);
		_user = NULL;
		if (name != NULL && (_user = strdup(name)) == NULL)
		{
			throw std::bad_alloc();
		}
	}
}

void sefs_query::role(const char *name) throw(std::bad_alloc)
{
	if (name != _role)
	{
		free(_role);
		_role = NULL;
		if (name != NULL && (_role = strdup(name)) == NULL)
		{
			throw std::bad_alloc();
		}
	}
}

void sefs_query::type(const char *name, bool indirect) throw(std::bad_alloc)
{
	if (name != _type)
	{
		free(_type);
		_type = NULL;
		if (name != NULL)
		{
			if ((_type = strdup(name)) == NULL)
			{
				throw std::bad_alloc();
			}
			_indirect = indirect;
		}
	}
}

void sefs_query::range(const char *range, int match) throw(std::bad_alloc)
{
	if (range != _range)
	{
		free(_range);
		_range = NULL;
		if (range != NULL)
		{
			if ((_range = strdup(range)) == NULL)
			{
				throw std::bad_alloc();
			}
			_rangeMatch = match;
		}
	}
}

void sefs_query::objectClass(uint32_t objclass)
{
	_objclass = objclass;
}

void sefs_query::objectClass(const char *name)
{
	if (name == NULL || strcmp(name, "any") == 0)
	{
		_objclass = QPOL_CLASS_ALL;
	}
	else
	{
		uint32_t o = apol_str_to_objclass(name);
		if (o != QPOL_CLASS_ALL)
		{
			_objclass = o;
		}
	}
}

void sefs_query::path(const char *path) throw(std::bad_alloc)
{
	if (path != _path)
	{
		free(_path);
		_path = NULL;
		if (path != NULL && (_path = strdup(path)) == NULL)
		{
			throw std::bad_alloc();
		}
	}
}

void sefs_query::inode(ino64_t inode)
{
	_inode = inode;
}

void sefs_query::dev(dev_t dev)
{
	_dev = dev;
}

void sefs_query::regex(bool regex)
{
	_regex = regex;
}

/******************** private functions below ********************/

void sefs_query::compile() throw(std::bad_alloc)
{
	if (_recompiled)
	{
		regfree(_reuser);
		regfree(_rerole);
		regfree(_retype);
		regfree(_rerange);
		regfree(_repath);
	}
	else
	{
		if ((_reuser = static_cast < regex_t * >(malloc(sizeof(*_reuser)))) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((_rerole = static_cast < regex_t * >(malloc(sizeof(*_rerole)))) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((_retype = static_cast < regex_t * >(malloc(sizeof(*_retype)))) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((_rerange = static_cast < regex_t * >(malloc(sizeof(*_rerange)))) == NULL)
		{
			throw std::bad_alloc();
		}
		if ((_repath = static_cast < regex_t * >(malloc(sizeof(*_repath)))) == NULL)
		{
			throw std::bad_alloc();
		}
	}
	const char *s = (_user == NULL ? "" : _user);
	if (regcomp(_reuser, s, REG_EXTENDED | REG_NOSUB))
	{
		throw std::bad_alloc();
	}
	s = (_role == NULL ? "" : _role);
	if (regcomp(_rerole, s, REG_EXTENDED | REG_NOSUB))
	{
		throw std::bad_alloc();
	}
	s = (_type == NULL ? "" : _type);
	if (regcomp(_retype, s, REG_EXTENDED | REG_NOSUB))
	{
		throw std::bad_alloc();
	}
	s = (_range == NULL ? "" : _range);
	if (regcomp(_rerange, s, REG_EXTENDED | REG_NOSUB))
	{
		throw std::bad_alloc();
	}
	s = (_path == NULL ? "" : _path);
	if (regcomp(_repath, s, REG_EXTENDED | REG_NOSUB))
	{
		throw std::bad_alloc();
	}
	_recompiled = true;
}

/******************** C functions below ********************/

sefs_query_t *sefs_query_create()
{
	return new sefs_query();
}

void sefs_query_destroy(sefs_query_t ** query)
{
	if (query != NULL && *query != NULL)
	{
		delete(*query);
		*query = NULL;
	}
}

int sefs_query_set_user(sefs_query_t * query, const char *name)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	try
	{
		query->user(name);
	}
	catch(...)
	{
		return -1;
	}
	return 0;
}

int sefs_query_set_role(sefs_query_t * query, const char *name)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	try
	{
		query->role(name);
	}
	catch(...)
	{
		return -1;
	}
	return 0;
}

int sefs_query_set_type(sefs_query_t * query, const char *name, bool indirect)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	try
	{
		query->type(name, indirect);
	}
	catch(...)
	{
		return -1;
	}
	return 0;
}

int sefs_query_set_range(sefs_query_t * query, const char *range, int match)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	query->range(range, match);
	return 0;
}

int sefs_query_set_object_class(sefs_query_t * query, uint32_t objclass)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	query->objectClass(objclass);
	return 0;
}

int sefs_query_set_object_class_str(sefs_query_t * query, const char *name)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	query->objectClass(name);
	return 0;
}

int sefs_query_set_path(sefs_query_t * query, const char *path)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	try
	{
		query->path(path);
	}
	catch(...)
	{
		return -1;
	}
	return 0;
}

int sefs_query_set_inode(sefs_query_t * query, ino64_t inode)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	query->inode(inode);
	return 0;
}

int sefs_query_set_dev(sefs_query_t * query, dev_t dev)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	query->dev(dev);
	return 0;
}

int sefs_query_set_regex(sefs_query_t * query, bool regex)
{
	if (query == NULL)
	{
		errno = EINVAL;
		return -1;
	}
	query->regex(regex);
	return 0;
}

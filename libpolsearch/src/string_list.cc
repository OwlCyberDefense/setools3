/**
 * @file
 *
 * Routines to create and manipulate logically related lists of strings.
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

#include <polsearch/string_list.hh>
#include <apol/vector.h>

#include <stdexcept>

using std::bad_alloc;
using std::runtime_error;

// polsearch string list

polsearch_string_list::polsearch_string_list(const char *str, bool Xvalid) throw(std::runtime_error, std::bad_alloc)
{
	//TODO correct free callback here
	_tokens = apol_vector_create(NULL);
	_ids = apol_vector_create(NULL);
	if (!_tokens || !_ids)
		throw bad_alloc();
	//TODO parse string here
}

polsearch_string_list::polsearch_string_list(const polsearch_string_list & sl) throw(std::bad_alloc)
{
	//TODO correct free and dup callbacks here
	_tokens = apol_vector_create_from_vector(sl._tokens, NULL, NULL, NULL);
	_ids = apol_vector_create_from_vector(sl._ids, NULL, NULL, NULL);
	if (!_tokens || !_ids)
		throw bad_alloc();
}

polsearch_string_list::~polsearch_string_list()
{
	apol_vector_destroy(&_tokens);
	apol_vector_destroy(&_ids);
}

const apol_vector_t *polsearch_string_list::ids() const
{
	return _ids;
}

apol_vector_t *polsearch_string_list::match(const apol_vector_t * test_ids,
					    const apol_vector_t * Xcandidates) const throw(std::bad_alloc)
{
	//TODO
	return NULL;
}

char *polsearch_string_list::toString() const
{
	//TODO
	return NULL;
}

// internal functions

// C compatibility functions

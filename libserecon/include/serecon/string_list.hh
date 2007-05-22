/**
 * @file
 *
 * Routines to create and manipulate logically related lists of strings.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2007 Tresys Technology, LLC
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

#ifndef SERECON_STRING_LIST_H
#define SERECON_STRING_LIST_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <apol/vector.h>

#ifdef __cplusplus
}

class serecon_string_list
{
      public:
	serecon_string_list(char *str, bool Xvalid);
	 serecon_string_list(const serecon_string_list & sl);
	~serecon_string_list();

	const apol_vector_t *ids() const;
	apol_vector_t *match(apol_vector_t * test_ids, apol_vector_t * Xcandidates);
	//TODO any other methods?

      private:
	//TODO store the internal stuff here;
};

extern "C"
{
#endif

	//TODO extern C bindings

#ifdef __cplusplus
}
#endif

#endif				       /* SERECON_STRING_LIST_H */

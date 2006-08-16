/**
 *  @file class_diff.c
 *  Implementation for computing a semantic differences in classes and
 *  commons.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#include <poldiff/class_diff.h>
#include <apol/vector.h>

struct poldiff_class_summary {
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *class_diffs;
};

struct poldiff_class {
	char *name;
	poldiff_form_e form;
	apol_vector_t *added_perms;
	apol_vector_t *removed_perms;
};

const char *poldiff_class_get_name(poldiff_t *diff, poldiff_class_t *cls)
{
	//TODO
	return NULL;
}

poldiff_form_e poldiff_class_get_form(poldiff_t *diff, poldiff_class_t *cls)
{
	//TODO
	return POLDIFF_FORM_NONE;
}

apol_vector_t *poldiff_class_get_added_perms(poldiff_t *diff, poldiff_class_t *cls)
{
	//TODO
	return NULL;
}

apol_vector_t *poldiff_class_get_removed_perms(poldiff_t *diff, poldiff_class_t *cls)
{
	//TODO
	return NULL;
}

size_t poldiff_get_num_added_classes(poldiff_t *diff)
{
	//TODO
	return 0;
}

size_t poldiff_get_num_removed_classes(poldiff_t *diff)
{
	//TODO
	return 0;
}

size_t poldiff_get_num_modified_classes(poldiff_t *diff)
{
	//TODO
	return 0;
}

apol_vector_t *poldiff_get_class_diff_vector(poldiff_t *diff)
{
	//TODO
	return NULL;
}

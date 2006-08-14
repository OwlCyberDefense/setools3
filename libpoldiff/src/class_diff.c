/**
 *  @file class_diff.c
 *  Implementation for computing a semantic differences in classes.
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

struct poldiff_class_diff_summary {
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *class_diffs;
};

struct poldiff_class_diff {
	char *name;
	poldiff_diff_type_e diff_type;
	apol_vector_t *added_perms;
	apol_vector_t *removed_perms;
};

char *poldiff_class_diff_get_name(poldiff_t *diff, poldiff_class_diff_t *cls)
{
	//TODO
	return NULL;
}

poldiff_diff_type_e poldiff_class_diff_get_diff_type(poldiff_t *diff, poldiff_class_diff_t *cls)
{
	//TODO
	return DIFF_TYPE_NONE;
}

apol_vector_t *poldiff_class_diff_get_added_perms(poldiff_t *diff, poldiff_class_diff_t *cls)
{
	//TODO
	return NULL;
}

apol_vector_t *poldiff_class_diff_get_removed_perms(poldiff_t *diff, poldiff_class_diff_t *cls)
{
	//TODO
	return NULL;
}

size_t poldiff_class_diff_summary_get_num_added_classes(poldiff_t *diff, poldiff_class_diff_summary_t *cds)
{
	//TODO
	return 0;
}

size_t poldiff_class_diff_summary_get_num_removed_classes(poldiff_t *diff, poldiff_class_diff_summary_t *cds)
{
	//TODO
	return 0;
}

size_t poldiff_class_diff_summary_get_num_modified_classes(poldiff_t *diff, poldiff_class_diff_summary_t *cds)
{
	//TODO
	return 0;
}

apol_vector_t *poldiff_class_diff_summary_get_class_diff_vector(poldiff_t *diff, poldiff_class_diff_summary_t *cds)
{
	//TODO
	return NULL;
}
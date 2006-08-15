/**
 *  @file poldiff_internal.h
 *  Protected Interface for computing a semantic policy difference.
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

#ifndef POLDIFF_POLDIFF_INTERNAL_H
#define POLDIFF_POLDIFF_INTERNAL_H

#include <apol/policy.h>
#include <poldiff/poldiff.h>

/* forward declarations */
struct poldiff_class_summary;
struct poldiff_common_summary;
struct poldiff_type_summary;
struct poldiff_attrib_summary;
struct poldiff_role_summary;
struct poldiff_user_summary;
struct poldiff_bool_summary;
struct poldiff_cond_summary;
/*struct poldiff_sens_summary;*/
/*struct poldiff_cat_summary;*/
struct poldiff_avrule_summary;
struct poldiff_terule_summary;
struct poldiff_role_allow_summary;
struct poldiff_role_trans_summary;
/*struct range_trans_summary;*/
/* and so forth for ocon_summary structs */

struct poldiff {
	apol_policy_t *policy1;
	apol_policy_t *policy2;
	poldiff_handle_fn_t
	void *handle_arg;
	uint32_t diff_status;
	/* symbol maps ? */
	struct poldiff_class_summary *class_diffs;
	struct poldiff_common_summary *common_diffs;
	struct poldiff_type_summary *type_diffs;
	struct poldiff_attrib_summary *attrib_diffs;
	struct poldiff_role_summary *role_diffs;
	struct poldiff_user_summary *user_diffs;
	struct poldiff_bool_summary *bool_diffs;
	struct poldiff_cond_summary *cond_diffs;
/*	struct poldiff_sens_summary *sens_diffs;*/
/*	struct poldiff_cat_summary *cat_diffs;*/
	struct poldiff_avrule_summary *avrule_diffs;
	struct poldiff_terule_summary *terule_diffs;
	struct poldiff_role_allow_summary *role_allow_diffs;
	struct poldiff_role_trans_summary *role_trans_diffs;
/*	struct poldiff_range_trans_summary *range_trans_diffs;*/
	/* and so forth if we want ocon_diffs */
	apol_vector_t *type_renames;
};

typedef struct poldiff_type_rename poldiff_type_rename_t;


#endif /* POLDIFF_POLDIFF_INTERNAL_H */
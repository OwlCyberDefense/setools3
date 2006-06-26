/**
 * @file relabel-analysis.h
 *
 * Routines to perform a direct relabelling analysis.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2006 Tresys Technology, LLC
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

#ifndef APOL_RELABEL_ANALYSIS_H
#define APOL_RELABEL_ANALYSIS_H

#include "policy.h"
#include "vector.h"

/* defines for direction flag */
#define APOL_RELABEL_DIR_TO	0x01
#define APOL_RELABEL_DIR_FROM	0x02
#define APOL_RELABEL_DIR_BOTH	(APOL_RELABEL_DIR_TO|APOL_RELABEL_DIR_FROM)
#define APOL_RELABEL_DIR_SUBJECT 0x04

typedef struct apol_relabel_analysis apol_relabel_analysis_t;


/* data structures */
typedef struct ap_relabel_rule {
	int		rule_index;
	unsigned char	direction;
} ap_relabel_rule_t;

typedef struct ap_relabel_subject {
	int			source_type;
	ap_relabel_rule_t	*rules;
	int			num_rules;
	unsigned char		direction;
} ap_relabel_subject_t;

typedef struct ap_relabel_object {
	int			object_class;
	ap_relabel_subject_t	*subjects;
	int			num_subjects;
	unsigned char		direction;
} ap_relabel_object_t;

typedef struct ap_relabel_target {
	int			target_type;
	ap_relabel_object_t	*objects;
	int			num_objects;
	unsigned char		direction;
} ap_relabel_target_t;

typedef struct ap_relabel_result {
	int			start_type;
	unsigned char		mode;
	unsigned char		requested_direction;
	ap_relabel_target_t	*targets;
	int			num_targets;
} ap_relabel_result_t;

/* query function */
int ap_relabel_query(int start_type, unsigned char mode, unsigned char direction,
	int *excluded_types, int num_excluded_types, int *class_filter, int class_filter_sz,
	ap_relabel_result_t *res, policy_t *policy);

/* clean-up function */
void ap_relabel_result_destroy(ap_relabel_result_t *res);

#endif

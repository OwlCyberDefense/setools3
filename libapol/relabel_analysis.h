/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Jeremy A. Mowery jmowery@tresys.com
 */

#ifndef _RELABEL_ANALYSIS_H_
#define _RELABEL_ANALYSIS_H_

#include "policy.h"

/* defines for mode */
#define AP_RELABEL_MODE_OBJ	0x01
#define AP_RELABEL_MODE_SUBJ	0x02

/* defines for direction flag */
#define AP_RELABEL_DIR_NONE	0x00
#define AP_RELABEL_DIR_TO	0x01
#define AP_RELABEL_DIR_FROM	0x02
#define AP_RELABEL_DIR_BOTH	(AP_RELABEL_DIR_TO|AP_RELABEL_DIR_FROM)
#define AP_RELABEL_DIR_START	0x04


/* data structures */
typedef struct ap_relabel_rule {
	int		rule_index;
	unsigned char 	direction;
} ap_relabel_rule_t;

typedef struct ap_relabel_subject {
	int			source_type;
	ap_relabel_rule_t	*rules;
	int			num_rules;
	unsigned char 		direction;
} ap_relabel_subject_t;

typedef struct ap_relabel_object {
	int			object_class;
	ap_relabel_subject_t 	*subjects;
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
	unsigned char 		mode;
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

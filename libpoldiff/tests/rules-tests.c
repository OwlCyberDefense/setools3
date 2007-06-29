/**
 *  @file
 *
 *  Test the libpoldiff's correctness for rules.
 *
 *  @author Paul Rosenfeld prosenfeld@tresys.com
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

#include "libpoldiff-tests.h"
#include "rules-tests.h"
#include "policy-defs.h"
#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>

#include <poldiff/poldiff.h>
#include <apol/policy.h>
#include <apol/vector.h>
#include <apol/util.h>

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static apol_vector_t *added_type_rules_v;
static apol_vector_t *removed_type_rules_v;
static apol_vector_t *correct_added_type_rules_v;
static apol_vector_t *correct_removed_type_rules_v;

char *unchanged_avrules[] = {
/* 01.0 */
	"allow placeholder_t placeholder_t : file read",
	"auditallow potato_t pine_t : dir setattr",
	NULL
};
char *added_avrules[] = {
/* 01.1 */
	"allow bear_t oak_t : fifo_file write",
	"allow rock_t log_t : file getattr",
	"allow tiger_t bear_t : file execute",
	"auditallow system_t log_t : netif udp_recv",
	"neverallow lion_t bear_t : file execute",
	NULL
};
char *removed_avrules[] = {
/* 01.2 */
	"allow rock_t log_t : dir search",
	"auditallow system_t log_t : node udp_recv",
	"allow bear_t bear_t : dir search",
	"allow bear_t birch_t : fd use",
	"allow bear_t daikon_t : fd use",
	"allow bear_t glass_t : file getattr",
	"allow bear_t holly_t : fd use",
	"allow bear_t oak_t : fd use",
	"allow bear_t pine_t : fd use",
	"allow bear_t potato_t : fd use",
	NULL
};

char *modified_avrules[] = {
/*01.3.0*/
	"allow firefly_t file_t : file execute +lock",
/*01.3.1*/
	"dontaudit bass_t stone_t : dir read search -getattr",
	"dontaudit trout_t stone_t : dir read search -getattr",
/*01.3.2*/
	"allow potato_t daikon_t : file getattr ioctl setattr +write -read",
	NULL
};

char *added_type_avrules[] = {
/* 01.4.00 */
	"auditallow pipe_t bear_t : blk_file ioctl",
/* 01.4.01 */
	"auditallow dirt_t hippo_t : sock_file read",
/* 01.4.02 */
	"allow hippo_t birch_t : fd use",
	"allow hippo_t daikon_t : fd use",
	"allow hippo_t glass_t : file getattr",
	"allow hippo_t holly_t : fd use",
	"allow hippo_t oak_t : fd use",
	"allow hippo_t pine_t : fd use",
	"allow hippo_t potato_t : fd use",
/* 01.4.03 */
	"allow system_t pipe_t : file getattr ioctl read",
	"neverallow bear_t pipe_t : process transition",
	"neverallow lion_t pipe_t : process transition",
	"neverallow tiger_t pipe_t : process transition",
/* 01.4.04 */
	"allow hippo_t pipe_t : lnk_file write",
/* 01.4.05 */
	"neverallow hippo_t pipe_t : process transition",
/* 01.4.06 */
	"allow hippo_t hippo_t : file getattr",
/* 01.4.07 */
	"allow hippo_t hippo_t : dir search",
/* 01.4.08 */
	"neverallow hippo_t finch_t : dir add_name",
/*"neverallow pipe_t finch_t : dir add_name",*/
	"neverallow pipe_t potato_t : lnk_file write",
	"neverallow pipe_t system_t : lnk_file write",
	"neverallow pipe_t bass_t : lnk_file write",
	"neverallow pipe_t bear_t : lnk_file write",
	"neverallow pipe_t birch_t : lnk_file write",
	"neverallow pipe_t daikon_t : lnk_file write",
	"neverallow pipe_t dirt_t : lnk_file write",
	"neverallow pipe_t finch_t : lnk_file write",
	"neverallow pipe_t firefly_t : lnk_file write",
	"neverallow pipe_t glass_t : lnk_file write",
	"neverallow pipe_t holly_t : lnk_file write",
	"neverallow pipe_t lion_t : lnk_file write",
	"neverallow pipe_t oak_t : lnk_file write",
	"neverallow pipe_t pine_t : lnk_file write",
	"neverallow pipe_t placeholder_t : lnk_file write",
	"neverallow pipe_t rock_t : lnk_file write",
	"neverallow pipe_t stone_t : lnk_file write",
	"neverallow pipe_t tiger_t : lnk_file write",
	"neverallow pipe_t trout_t : lnk_file write",
/*01.4.09*/
	"neverallow birch_t hippo_t : lnk_file write",
	"neverallow daikon_t hippo_t : lnk_file write",
	"neverallow dirt_t hippo_t : lnk_file write",
	"neverallow file_t hippo_t : lnk_file write",
	"neverallow glass_t hippo_t : lnk_file write",
	"neverallow holly_t hippo_t : lnk_file write",
	"neverallow lion_t pipe_t : file execute",
	"neverallow log_t hippo_t : lnk_file write",
	"neverallow oak_t hippo_t : lnk_file write",
	"neverallow pine_t hippo_t : lnk_file write",
	"neverallow potato_t hippo_t : lnk_file write",
	"neverallow placeholder_t hippo_t : lnk_file write",
	"neverallow rock_t hippo_t : lnk_file write",
	"neverallow stone_t hippo_t : lnk_file write",
	"neverallow system_t hippo_t : lnk_file write",
/* 01.4.10 */
	"neverallow pipe_t hippo_t : lnk_file write",
/* 01.4.11 */
	"neverallow hippo_t log_t : file execute",
	"neverallow pipe_t log_t : file execute",
/* 01.4.12 */
	"neverallow placeholder_t hippo_t : fd use",
	"neverallow placeholder_t pipe_t : fd use",
/*********** NEED TO BE ADDED TO DOCUMENT *******/
	"neverallow bass_t pipe_t : process transition",
	"neverallow finch_t pipe_t : process transition",
	"neverallow firefly_t pipe_t : process transition",
	"neverallow hippo_t file_t : process transition",
	"neverallow hippo_t log_t : process transition",
	"neverallow trout_t pipe_t : process transition",
	NULL
};
char *removed_type_avrules[] = {
/* 01.5.00 */
	"allow koala_t oak_t : fifo_file write",
/* 01.5.01 */
	"allow tiger_t koala_t : file execute",
/* 01.5.02 */
/*"allow bear_t glass_t : file getattr",
BEAR_T IS NO LONGER MAMMAL, THIS RULES DOESN'T APPLY*/
	"allow turnip_t dirt_t : dir search",
	"neverallow koala_t file_t : process transition",
	"neverallow koala_t log_t : process transition",
/* 01.5.03 */
	"allow bear_t turnip_t : fd use",
	"allow lion_t turnip_t : fd use",
	"allow stone_t turnip_t : blk_file write",
	"allow tiger_t turnip_t : fd use",
/* 01.5.04 */
	"allow koala_t turnip_t : lnk_file read",
/* 01.5.05
"allow bear_t turnip_t : fd use",
WRONG
*/
/* 01.5.06 */
	"allow turnip_t turnip_t : fd use",
/* 01.5.07 */
/*"allow bear_t bear_t : dir search",
BEAR_T IS NO LONGER MAMMAL, THIS RULE DOESNT APPLY*/
/* 01.5.08 */
	"neverallow koala_t finch_t : dir add_name",
	"neverallow turnip_t finch_t : dir add_name",
	"neverallow turnip_t potato_t : lnk_file write",
	"neverallow turnip_t system_t : lnk_file write",
	"neverallow turnip_t bass_t : lnk_file write",
	"neverallow turnip_t bear_t : lnk_file write",
	"neverallow turnip_t birch_t : lnk_file write",
	"neverallow turnip_t daikon_t : lnk_file write",
	"neverallow turnip_t dirt_t : lnk_file write",
	"neverallow turnip_t finch_t : lnk_file write",
	"neverallow turnip_t firefly_t : lnk_file write",
	"neverallow turnip_t glass_t : lnk_file write",
	"neverallow turnip_t holly_t : lnk_file write",
	"neverallow turnip_t lion_t : lnk_file write",
	"neverallow turnip_t oak_t : lnk_file write",
	"neverallow turnip_t pine_t : lnk_file write",
	"neverallow turnip_t placeholder_t : lnk_file write",
	"neverallow turnip_t rock_t : lnk_file write",
	"neverallow turnip_t stone_t : lnk_file write",
	"neverallow turnip_t tiger_t : lnk_file write",
	"neverallow turnip_t trout_t : lnk_file write",
/* 01.5.09 */
	"neverallow birch_t koala_t : lnk_file write",
	"neverallow birch_t turnip_t : lnk_file write",
	"neverallow daikon_t koala_t : lnk_file write",
	"neverallow daikon_t turnip_t : lnk_file write",
	"neverallow dirt_t koala_t : lnk_file write",
	"neverallow dirt_t turnip_t : lnk_file write",
	"neverallow file_t koala_t : lnk_file write",
	"neverallow file_t turnip_t : lnk_file write",
	"neverallow glass_t koala_t : lnk_file write",
	"neverallow glass_t turnip_t : lnk_file write",
	"neverallow holly_t koala_t : lnk_file write",
	"neverallow holly_t turnip_t : lnk_file write",
	"neverallow lion_t koala_t : file execute",
	"neverallow log_t koala_t : lnk_file write",
	"neverallow log_t turnip_t : lnk_file write",
	"neverallow oak_t koala_t : lnk_file write",
	"neverallow oak_t turnip_t : lnk_file write",
	"neverallow placeholder_t koala_t : lnk_file write",
	"neverallow placeholder_t turnip_t : lnk_file write",
	"neverallow pine_t koala_t : lnk_file write",
	"neverallow pine_t turnip_t : lnk_file write",
	"neverallow potato_t koala_t : lnk_file write",
	"neverallow potato_t turnip_t : lnk_file write",
	"neverallow rock_t koala_t : lnk_file write",
	"neverallow rock_t turnip_t : lnk_file write",
	"neverallow stone_t koala_t : lnk_file write",
	"neverallow stone_t turnip_t : lnk_file write",
	"neverallow system_t koala_t : lnk_file write",
	"neverallow system_t turnip_t : lnk_file write",
/* 01.5.10 */
	"neverallow turnip_t koala_t : lnk_file write",
	"neverallow turnip_t turnip_t : lnk_file write",
/* 01.5.11 */
	"neverallow koala_t log_t : file execute",
	"neverallow turnip_t log_t : file execute",
/* 01.5.12 */
	"neverallow placeholder_t koala_t : fd use",
	"neverallow placeholder_t turnip_t : fd use",
	NULL
};

char *unchanged_roleallowrules[] = {
/* 09.0*/
	"allow admin_r staff_r user_r",
	"allow deity_r { admin_r aquarium_r garden_r guest_r intern_r lumberjack_r mammal_r placeholder_r staff_r user_r zoo_r }",
	"allow mammal_r intern_r user_r",
	"allow placeholder_r staff_r",
	NULL
};
char *added_roleallowrules[] = {
/* 09.1 */
	"allow intern_r user_r",
	NULL
};
char *removed_roleallowrules[] = {
/* 09.2 */
	"allow guest_r user_r",
	NULL
};
char *modified_roleallowrules[] = {
/* 09.3.0 */
	"allow aquarium_r { guest_r staff_r +admin_r }",
	"allow user_r { placeholder_r +guest_r }",
/* 09.3.1 */
	"allow garden_r { guest_r -user_r -zoo_r }",
	"allow lumberjack_r { garden_r -staff_r }",
	"allow zoo_r { aquarium_r garden_r mammal_r -admin_r }",
/* 09.3.2 */
	"allow staff_r { guest_r user_r +mammal_r -intern_r }",
	NULL
};

char *unchanged_roletrans_rules[] = {
/* 10.0*/
	"role_transition garden_r birch_t lumberjack_r",
	"role_transition garden_r oak_t lumberjack_r",
	"role_transition garden_r pine_t lumberjack_r",
	"role_transition staff_r holly_t garden_r",
	NULL
};
char *added_roletrans_rules[] = {
/* 10.1 */
	"role_transition guest_r bear_t staff_r",
	"role_transition intern_r file_t staff_r",
	NULL
};
char *removed_roletrans_rules[] = {
/* 10.2 */
	"role_transition zoo_r bass_t aquarium_r",
	"role_transition zoo_r bear_t mammal_r",
	"role_transition zoo_r trout_t aquarium_r",
	NULL
};
char *modified_roletrans_rules[] = {
/* 10.3.0 */
	"role_transition guest_r dirt_t { +admin_r -intern_r }",
	NULL
};
char *added_roletrans_type[] = {
/* 10.4.0 */
	"role_transition guest_r pipe_t staff_r",
/* 10.4.1 */
	"role_transition admin_r pipe_t staff_r",
	"role_transition staff_r hippo_t zoo_r",
	"role_transition zoo_r hippo_t mammal_r",
	NULL
};

char *removed_roletrans_type[] = {
/* 10.5.0 */
	"role_transition guest_r koala_t staff_r",
/* 10.5.1 */
	"role_transition staff_r koala_t zoo_r",
	NULL
};

char *unchanged_terules[] = {
/* 11.0 */
	"type_transition system_t dirt_t : process daikon_t",
	NULL
};
char *added_terules[] = {
/* 11.1 */
	"type_member log_t file_t : netif rock_t",
	"type_transition holly_t bear_t : dir oak_t",
	NULL
};
char *removed_terules[] = {
/* 11.2 */
	"type_transition potato_t pine_t : fd log_t",
	"type_change file_t bear_t : passwd daikon_t",
	"type_member log_t file_t : node rock_t",
	"type_change log_t bear_t : passwd daikon_t",
	NULL
};
char *added_type_terules[] = {
/*11.4.0 */
	"type_transition hippo_t log_t : file system_t",
/*11.4.1 */
	"type_transition bear_t pipe_t : chr_file birch_t",
/*11.4.2 */
	"type_transition hippo_t stone_t : netif potato_t",
/*11.4.3 */
	"type_change glass_t hippo_t : socket bass_t",
/*11.4.4 */
	"type_change hippo_t pipe_t : gc log_t",
/*11.4.5 */
	"type_change file_t hippo_t : passwd daikon_t",
	"type_change log_t hippo_t : passwd daikon_t",
	"type_change pipe_t hippo_t : passwd daikon_t",
	"type_change pipe_t lion_t : passwd daikon_t",
	"type_change pipe_t tiger_t : passwd daikon_t",
	"type_member hippo_t birch_t : chr_file file_t",
	"type_member hippo_t daikon_t : chr_file file_t",
	"type_member hippo_t holly_t : chr_file file_t",
	"type_member hippo_t oak_t : chr_file file_t",
	"type_member hippo_t pine_t : chr_file file_t",
	"type_member hippo_t potato_t : chr_file file_t",
	NULL
};
char *removed_type_terules[] = {
/* 11.5.0 */
	"type_change turnip_t glass_t : dir stone_t",
/* 11.5.1 */
	"type_change tiger_t turnip_t : file file_t",
/* 11.5.2 */
	"type_member turnip_t dirt_t : dir glass_t",
/* 11.5.3 */
	"type_member firefly_t turnip_t : file pine_t",
/* 11.5.4 */
	"type_member turnip_t turnip_t : fd lion_t",
/* 11.5.5 */
	"type_member bass_t turnip_t : chr_file file_t",
	"type_member bear_t turnip_t : chr_file file_t",
	"type_member finch_t turnip_t : chr_file file_t",
	"type_member firefly_t turnip_t : chr_file file_t",
/* these rules are incorrect because there was no hippo_t in the original policy, so it cannot be removed
"type_member hippo_t birch_t : chr_file file_t",
"type_member hippo_t daikon_t : chr_file file_t",
"type_member hippo_t holly_t : chr_file file_t",
"type_member hippo_t oak_t : chr_file file_t",
"type_member hippo_t pine_t : chr_file file_t",
"type_member hippo_t potato_t : chr_file file_t",
*/
	"type_member koala_t birch_t : chr_file file_t",
	"type_member koala_t daikon_t : chr_file file_t",
	"type_member koala_t holly_t : chr_file file_t",
	"type_member koala_t oak_t : chr_file file_t",
	"type_member koala_t pine_t : chr_file file_t",
	"type_member koala_t potato_t : chr_file file_t",
	"type_member koala_t turnip_t : chr_file file_t",
	"type_member lion_t turnip_t : chr_file file_t",
	"type_member tiger_t turnip_t : chr_file file_t",
	"type_member trout_t turnip_t : chr_file file_t",
/* koala_t is now an alias of animal, thus this rule now applies:
 type_change glass_t animal : socket bass_t;
 */
	"type_change glass_t koala_t : socket bass_t",
/* also this rule applies:
   type_transition animal stone_t : netif potato_t;
*/
	"type_transition koala_t stone_t : netif potato_t",
	NULL
};

char *modified_terules[] = {
	"type_transition lion_t tiger_t : file +bear_t -koala_t",
	NULL
};

static char *get_rule_modification_str(const apol_vector_t * unmodified, const apol_vector_t * added, const apol_vector_t * removed,
				       poldiff_form_e form, int show_changes)
{
	char *perm_add_char = "+", *perm_remove_char = "-";
	apol_vector_t *added_copy = shallow_copy_str_vec_and_sort(added);
	apol_vector_t *removed_copy = shallow_copy_str_vec_and_sort(removed);
	apol_vector_t *unmodified_copy = shallow_copy_str_vec_and_sort(unmodified);
	int error = 0;
	switch (form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:
		perm_add_char = "";
		break;
	case POLDIFF_FORM_REMOVE_TYPE:
	case POLDIFF_FORM_REMOVED:
		perm_remove_char = "";
		break;
	case POLDIFF_FORM_MODIFIED:
		// do nothing
		break;
	default:
		// should never get here
		assert(0);
	}
	size_t i, str_len;
	char *perm_name = NULL, *str = NULL;
	for (i = 0; unmodified_copy != NULL && i < apol_vector_get_size(unmodified_copy); ++i) {
		char *unmod_perm = apol_vector_get_element(unmodified_copy, i);
		apol_str_appendf(&str, &str_len, " %s", unmod_perm);
	}
	if (show_changes) {
		for (i = 0; added != NULL && i < apol_vector_get_size(added); i++) {
			perm_name = (char *)apol_vector_get_element(added_copy, i);
			if (apol_str_appendf(&str, &str_len, " %s%s", perm_add_char, perm_name) < 0) {
				error = errno;
				goto err;
			}
		}
		for (i = 0; removed != NULL && i < apol_vector_get_size(removed_copy); i++) {
			perm_name = (char *)apol_vector_get_element(removed_copy, i);
			if (apol_str_appendf(&str, &str_len, " %s%s", perm_remove_char, perm_name) < 0) {
				error = errno;
				goto err;
			}
		}
	}
	apol_vector_destroy(&added_copy);
	apol_vector_destroy(&removed_copy);
	apol_vector_destroy(&unmodified_copy);
	return str;
      err:
	free(str);
	return NULL;
}

static char *avrule_to_string(const void *arg, poldiff_form_e form, int show_changes)
{
	const poldiff_avrule_t *avr = (const poldiff_avrule_t *)arg;
	char *str = NULL;
	size_t str_len = 0;
	uint32_t rule_type = poldiff_avrule_get_rule_type(avr);
	const char *rule_type_str = apol_rule_type_to_str(rule_type);
	const char *target_type = poldiff_avrule_get_target_type(avr);
	const char *source_type = poldiff_avrule_get_source_type(avr);
	const char *object_class = poldiff_avrule_get_object_class(avr);
	apol_str_appendf(&str, &str_len, "%s %s %s : %s", rule_type_str, source_type, target_type, object_class);
	if (show_changes) {
		const apol_vector_t *unmodified_perms = poldiff_avrule_get_unmodified_perms(avr);
		const apol_vector_t *removed_perms = poldiff_avrule_get_removed_perms(avr);
		const apol_vector_t *added_perms = poldiff_avrule_get_added_perms(avr);
		char *perm_str = get_rule_modification_str(unmodified_perms, added_perms, removed_perms, form, show_changes);
		apol_str_appendf(&str, &str_len, "%s", perm_str);
		free(perm_str);
	}
	return str;
}

static char *terule_to_string(const void *arg, poldiff_form_e form, int show_changes)
{
	poldiff_terule_t *ter = (poldiff_terule_t *) arg;
	char *str = NULL;
	size_t str_len = 0;
	uint32_t rule_type = poldiff_terule_get_rule_type(ter);
	const char *rule_type_str = apol_rule_type_to_str(rule_type);
	const char *target_type = poldiff_terule_get_target_type(ter);
	const char *source_type = poldiff_terule_get_source_type(ter);
	const char *object_class = poldiff_terule_get_object_class(ter);
	const char *default_type;
	switch (form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:
		default_type = poldiff_terule_get_modified_default(ter);
		break;
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE:
	case POLDIFF_FORM_MODIFIED:
		default_type = poldiff_terule_get_original_default(ter);
		break;
	default:
		// should never get here
		assert(0);
	}
	if (form == POLDIFF_FORM_MODIFIED && show_changes) {
		const char *orig_default = poldiff_terule_get_original_default(ter);
		const char *mod_default = poldiff_terule_get_modified_default(ter);
		apol_str_appendf(&str, &str_len, "%s %s %s : %s +%s -%s", rule_type_str, source_type, target_type, object_class,
				 mod_default, orig_default);
	} else
		apol_str_appendf(&str, &str_len, "%s %s %s : %s %s", rule_type_str, source_type, target_type, object_class,
				 default_type);
	return str;
}

static char *roletrans_to_string(const void *arg, poldiff_form_e form, int show_changes)
{
	poldiff_role_trans_t *rt = (poldiff_role_trans_t *) arg;
	char *str = NULL;
	size_t str_len = 0;
	const char *source_role = poldiff_role_trans_get_source_role(rt);
	const char *target_type = poldiff_role_trans_get_target_type(rt);
	apol_str_appendf(&str, &str_len, "role_transition %s %s", source_role, target_type);
	if (show_changes) {
		const char *orig_default = poldiff_role_trans_get_original_default(rt);
		const char *mod_default = poldiff_role_trans_get_modified_default(rt);

		switch (form) {
		case POLDIFF_FORM_ADDED:
		case POLDIFF_FORM_ADD_TYPE:
			apol_str_appendf(&str, &str_len, " %s", mod_default);
			break;
		case POLDIFF_FORM_REMOVED:
		case POLDIFF_FORM_REMOVE_TYPE:
			apol_str_appendf(&str, &str_len, " %s", orig_default);
			break;
		case POLDIFF_FORM_MODIFIED:
			apol_str_appendf(&str, &str_len, " { +%s -%s }", mod_default, orig_default);
			break;
		default:
			// should never get here:
			assert(0);
		}
	}
	return str;
}

static char *roleallow_to_string(const void *arg, poldiff_form_e form, int show_changes)
{
	poldiff_role_allow_t *rat = (poldiff_role_allow_t *) arg;
	char *str = NULL, *orig_roles_str = NULL;
	size_t str_len = 0, orig_roles_str_len = 0;
	const char *name = poldiff_role_allow_get_name(rat);
	const apol_vector_t *orig_roles;
	switch (form) {
	case POLDIFF_FORM_ADDED:
		orig_roles = poldiff_role_allow_get_added_roles(rat);
		break;
	case POLDIFF_FORM_REMOVED:
		orig_roles = poldiff_role_allow_get_removed_roles(rat);
		break;
	case POLDIFF_FORM_MODIFIED:
		orig_roles = poldiff_role_allow_get_unmodified_roles(rat);
		break;
	default:
		// should never get here
		assert(0);
	}
	size_t i;
	size_t num_orig_roles = apol_vector_get_size(orig_roles);
	const char *fmt;
	if (num_orig_roles > 1 || (show_changes && form == POLDIFF_FORM_MODIFIED))
		fmt = "allow %s {%s }";
	else
		fmt = "allow %s%s";
	for (i = 0; i < num_orig_roles; ++i) {
		char *role = apol_vector_get_element(orig_roles, i);
		apol_str_appendf(&orig_roles_str, &orig_roles_str_len, " %s", role);
	}
	if (show_changes && form == POLDIFF_FORM_MODIFIED) {
		const apol_vector_t *added_role_v = poldiff_role_allow_get_added_roles(rat);
		for (i = 0; i < apol_vector_get_size(added_role_v); ++i) {
			char *added_role = apol_vector_get_element(added_role_v, i);
			apol_str_appendf(&orig_roles_str, &orig_roles_str_len, " +%s", added_role);
		}
		const apol_vector_t *removed_role_v = poldiff_role_allow_get_removed_roles(rat);
		for (i = 0; i < apol_vector_get_size(removed_role_v); ++i) {
			char *removed_role = apol_vector_get_element(removed_role_v, i);
			apol_str_appendf(&orig_roles_str, &orig_roles_str_len, " -%s", removed_role);
		}
	}
	apol_str_appendf(&str, &str_len, fmt, name, orig_roles_str);
	free(orig_roles_str);
	return str;
}

void build_roleallow_vecs()
{
	char *str = NULL, *name_only = NULL;
	size_t i;
	const void *item = NULL;
	const apol_vector_t *v = NULL;
	v = poldiff_get_role_allow_vector(diff);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		poldiff_form_e form = poldiff_role_allow_get_form(item);
		str = roleallow_to_string(item, form, 1);
		if (!str)
			break;
		switch (form) {
		case POLDIFF_FORM_ADDED:
			apol_vector_append(added_v, str);
			break;
		case POLDIFF_FORM_REMOVED:
			apol_vector_append(removed_v, str);
			break;
		case POLDIFF_FORM_MODIFIED:
			name_only = roleallow_to_string(item, form, 0);
			apol_vector_append(modified_name_only_v, name_only);
			apol_vector_append(modified_v, str);
			break;
		default:
			// should never get here
			assert(0);
		}
	}
}

void build_roletrans_vecs()
{
	added_type_rules_v = apol_vector_create(free);
	removed_type_rules_v = apol_vector_create(free);
	correct_added_type_rules_v = string_array_to_vector(added_roletrans_type);
	correct_removed_type_rules_v = string_array_to_vector(removed_roletrans_type);

	char *str = NULL, *name_only;
	size_t i;
	const void *item = NULL;
	const apol_vector_t *v = NULL;
	v = poldiff_get_role_trans_vector(diff);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		item = apol_vector_get_element(v, i);
		if (!item)
			return;
		poldiff_form_e form = poldiff_role_trans_get_form(item);
		str = roletrans_to_string(item, form, 1);
		if (!str)
			break;
		switch (form) {
		case POLDIFF_FORM_ADDED:
			apol_vector_append(added_v, str);
			break;
		case POLDIFF_FORM_REMOVED:
			apol_vector_append(removed_v, str);
			break;
		case POLDIFF_FORM_ADD_TYPE:
			apol_vector_append(added_type_rules_v, str);
			break;
		case POLDIFF_FORM_REMOVE_TYPE:
			apol_vector_append(removed_type_rules_v, str);
			break;
		case POLDIFF_FORM_MODIFIED:
			name_only = roletrans_to_string(item, form, 0);
			apol_vector_append(modified_name_only_v, name_only);
			apol_vector_append(modified_v, str);
			break;
		default:
			// should never get here
			assert(0);
		}
	}
	int test_result;
	size_t first_diff = 0;
	apol_vector_sort(added_type_rules_v, compare_str, NULL);
	apol_vector_sort(correct_added_type_rules_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(added_type_rules_v, correct_added_type_rules_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(added_type_rules_v, correct_added_type_rules_v, first_diff, "Added Rule (due to Type)");
	}
	apol_vector_sort(removed_type_rules_v, compare_str, NULL);
	apol_vector_sort(correct_removed_type_rules_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(removed_type_rules_v, correct_removed_type_rules_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(removed_type_rules_v, correct_removed_type_rules_v, first_diff, "Removed Rule (due to Type)");
	}
	apol_vector_destroy(&added_type_rules_v);
	apol_vector_destroy(&correct_added_type_rules_v);
	apol_vector_destroy(&removed_type_rules_v);
	apol_vector_destroy(&correct_removed_type_rules_v);
}

void build_terule_vecs()
{
	added_type_rules_v = apol_vector_create(free);
	removed_type_rules_v = apol_vector_create(free);
	correct_added_type_rules_v = string_array_to_vector(added_type_terules);
	correct_removed_type_rules_v = string_array_to_vector(removed_type_terules);

	size_t i;
	char *str = NULL;
	const void *item = NULL;
	const apol_vector_t *member_v = NULL, *change_v = NULL, *trans_v = NULL;
	member_v = poldiff_get_terule_vector_member(diff);
	change_v = poldiff_get_terule_vector_change(diff);
	trans_v = poldiff_get_terule_vector_trans(diff);
	apol_vector_t *all_terules = apol_vector_create(NULL);
	apol_vector_cat(all_terules, member_v);
	apol_vector_cat(all_terules, change_v);
	apol_vector_cat(all_terules, trans_v);

	for (i = 0; i < apol_vector_get_size(all_terules); i++) {
		item = apol_vector_get_element(all_terules, i);
		if (!item)
			return;
		poldiff_form_e form = poldiff_terule_get_form(item);
		str = terule_to_string(item, form, 1);
		if (!str)
			break;
		char *name_only = NULL;
		switch (form) {
		case POLDIFF_FORM_ADDED:
			apol_vector_append(added_v, str);
			break;
		case POLDIFF_FORM_REMOVED:
			apol_vector_append(removed_v, str);
			break;
		case POLDIFF_FORM_ADD_TYPE:
			apol_vector_append(added_type_rules_v, str);
			break;
		case POLDIFF_FORM_REMOVE_TYPE:
			apol_vector_append(removed_type_rules_v, str);
			break;
		case POLDIFF_FORM_MODIFIED:
			name_only = terule_to_string(item, form, 0);
			apol_vector_append(modified_name_only_v, name_only);
			apol_vector_append(modified_v, str);
			break;
		default:
			// should never get here
			assert(0);
		}
	}
	size_t first_diff = 0;
	int test_result = 0;
	apol_vector_sort(added_type_rules_v, compare_str, NULL);
	apol_vector_sort(correct_added_type_rules_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(added_type_rules_v, correct_added_type_rules_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(added_type_rules_v, correct_added_type_rules_v, first_diff, "Added Rules (due to types)");
	}

	apol_vector_sort(removed_type_rules_v, compare_str, NULL);
	apol_vector_sort(correct_removed_type_rules_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(removed_type_rules_v, correct_removed_type_rules_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(removed_type_rules_v, correct_removed_type_rules_v, first_diff, "Removed Rules (due to types)");
	}
	apol_vector_destroy(&all_terules);
	apol_vector_destroy(&added_type_rules_v);
	apol_vector_destroy(&correct_added_type_rules_v);
	apol_vector_destroy(&removed_type_rules_v);
	apol_vector_destroy(&correct_removed_type_rules_v);
}

void build_avrule_vecs()
{
	added_type_rules_v = apol_vector_create(free);
	removed_type_rules_v = apol_vector_create(free);
	correct_added_type_rules_v = string_array_to_vector(added_type_avrules);
	correct_removed_type_rules_v = string_array_to_vector(removed_type_avrules);

	size_t i;
	char *str = NULL, *name_only = NULL;
	const void *item = NULL;
	const apol_vector_t *allow_v = NULL, *neverallow_v = NULL, *auditallow_v = NULL, *dontaudit_v = NULL;
	apol_vector_t *all_avrules_v = apol_vector_create(NULL);

	allow_v = poldiff_get_avrule_vector_allow(diff);
	neverallow_v = poldiff_get_avrule_vector_neverallow(diff);
	auditallow_v = poldiff_get_avrule_vector_auditallow(diff);
	dontaudit_v = poldiff_get_avrule_vector_dontaudit(diff);

	apol_vector_cat(all_avrules_v, allow_v);
	apol_vector_cat(all_avrules_v, neverallow_v);
	apol_vector_cat(all_avrules_v, auditallow_v);
	apol_vector_cat(all_avrules_v, dontaudit_v);

	for (i = 0; i < apol_vector_get_size(all_avrules_v); i++) {
		item = apol_vector_get_element(all_avrules_v, i);
		if (!item)
			return;
		poldiff_form_e form = poldiff_avrule_get_form(item);
		str = avrule_to_string(item, form, 1);
		if (!str)
			break;
		switch (form) {
		case POLDIFF_FORM_ADDED:
			apol_vector_append(added_v, str);
			break;
		case POLDIFF_FORM_REMOVED:
			apol_vector_append(removed_v, str);
			break;
		case POLDIFF_FORM_ADD_TYPE:
			apol_vector_append(added_type_rules_v, str);
			break;
		case POLDIFF_FORM_REMOVE_TYPE:
			apol_vector_append(removed_type_rules_v, str);
			break;
		case POLDIFF_FORM_MODIFIED:
			name_only = avrule_to_string(item, form, 0);
			apol_vector_append(modified_name_only_v, name_only);
			apol_vector_append(modified_v, str);
			break;
		default:
			// should never get here
			assert(0);
		}
	}
	size_t first_diff = 0;
	apol_vector_sort(added_type_rules_v, compare_str, NULL);
	apol_vector_sort(correct_added_type_rules_v, compare_str, NULL);
	CU_ASSERT_FALSE(apol_vector_compare(added_type_rules_v, correct_added_type_rules_v, compare_str, NULL, &first_diff));

	apol_vector_sort(removed_type_rules_v, compare_str, NULL);
	apol_vector_sort(correct_removed_type_rules_v, compare_str, NULL);
	CU_ASSERT_FALSE(apol_vector_compare(removed_type_rules_v, correct_removed_type_rules_v, compare_str, NULL, &first_diff));

	apol_vector_destroy(&removed_type_rules_v);
	apol_vector_destroy(&correct_removed_type_rules_v);
	apol_vector_destroy(&added_type_rules_v);
	apol_vector_destroy(&correct_added_type_rules_v);
	apol_vector_destroy(&all_avrules_v);
}

void rules_avrules_tests()
{
	test_numbers_e test_num = RULES_AVRULE;
	poldiff_test_answers_t *answers = init_answer_vectors(added_avrules, removed_avrules, unchanged_avrules, modified_avrules);
	run_test(NULL, answers, test_num);
	cleanup_test(answers);
}

void rules_terules_tests()
{
	test_numbers_e test_num = RULES_TERULE;
	poldiff_test_answers_t *answers = init_answer_vectors(added_terules, removed_terules, unchanged_terules, modified_terules);
	run_test(NULL, answers, test_num);
	cleanup_test(answers);
}

void rules_roleallow_tests()
{
	test_numbers_e test_num = RULES_ROLEALLOW;
	poldiff_test_answers_t *answers =
		init_answer_vectors(added_roleallowrules, removed_roleallowrules, unchanged_roleallowrules,
				    modified_roleallowrules);
	run_test(NULL, answers, test_num);
	cleanup_test(answers);
}

void rules_roletrans_tests()
{
	test_numbers_e test_num = RULES_ROLETRANS;
	poldiff_test_answers_t *answers =
		init_answer_vectors(added_roletrans_rules, removed_roletrans_rules, unchanged_roletrans_rules,
				    modified_roletrans_rules);
	run_test(NULL, answers, test_num);
	cleanup_test(answers);
}

int rules_test_init()
{
	if (!(diff = init_poldiff(RULES_ORIG_POLICY, RULES_MOD_POLICY))) {
		return 1;
	} else {
		return 0;
	}
}

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
typedef struct apol_relabel_result apol_relabel_result_t;

/******************** functions to do relabel analysis ********************/

/**
 * Execute a relabel analysis against a particular policy.
 *
 * @param p Policy within which to look up constraints.
 * @param r A non-NULL structure containing parameters for analysis.
 * @param result Reference to where to store the results of the
 * analysis.  The caller must call apol_relabel_result_destroy() upon
 * this.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_relabel_analysis_do(apol_policy_t *p,
                                    apol_relabel_analysis_t *r,
                                    apol_relabel_result_t **result);

/**
 * Allocate and return a new relabel analysis structure.  All fields
 * are cleared; one must fill in the details of the query before
 * running it.  The caller must call apol_relabel_analysis_destroy()
 * upon the return value afterwards.
 *
 * @return An initialized relabel analysis structure, or NULL upon
 * error.
 */
extern apol_relabel_analysis_t *apol_relabel_analysis_create(void);

/**
 * Deallocate all memory associated with the referenced relabel
 * analysis, and then set it to NULL.  This function does nothing if
 * the analysis is already NULL.
 *
 * @param r Reference to a relabel analysis structure to destroy.
 */
extern void apol_relabel_analysis_destroy(apol_relabel_analysis_t **r);

/**
 * Set a relabel analysis to search in a specific direction.  This
 * must be one of the values APOL_RELABEL_DIR_TO,
 * APOL_RELABEL_DIR_FROM, APOL_RELABEL_DIR_BOTH, or
 * APOL_RELABEL_DIR_SUBJECT.  This function must be called prior to
 * running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param r Relabel analysis to set.
 * @param dir Direction to analyze, using one of the
 * APOL_RELABEL_DIR_* defines.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_relabel_analysis_set_dir(apol_policy_t *p,
					 apol_relabel_analysis_t *r,
					 unsigned int dir);

/**
 * Set a relabel analysis to begin searching using a given type.  This
 * function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param r Relabel anlysis to set.
 * @param name Begin searching types with this non-NULL name.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_relabel_analysis_set_type(apol_policy_t *p,
					  apol_relabel_analysis_t *r,
					  const char *name);

/**
 * Set a relabel analysis to return only types matching a regular
 * expression.  Note that if regexp will also match types' aliases.
 *
 * @param p Policy handler, to report errors.
 * @param r Relabel anlysis to set.
 * @param result Only return types matching this regular expression, or
 * NULL to return all types
 *
 * @return 0 on success, negative on error.
 */
extern int apol_relabel_analysis_set_result_regexp(apol_policy_t *p,
						   apol_relabel_analysis_t *r,
						   const char *result);

/******************** functions to access relabel results ********************/

/**
 * Free all memory associated with a relabel result, including the
 * pointer itself.  This function does nothing if the result is
 * already NULL.
 *
 * @param result Reference to a relabel result structure to destroy.  The
 * pointer will be set to NULL afterwards.
 */
extern void apol_relabel_result_destroy(apol_relabel_result_t **result);


/**
 * Return the relabelto vector embedded within an apol_relabel_result
 * node.  This is a vector qpol_rule_t pointers.  The caller shall not
 * call apol_vector_destroy() upon this pointer.
 *
 * @param r Relabel result node.
 *
 * @return Pointer to a vector of rules, relative to the policy
 * originally used to generate the relabelling result.
 */
extern apol_vector_t *apol_relabel_result_get_to(apol_relabel_result_t *r);

/**
 * Return the relabelfrom vector embedded within an
 * apol_relabel_result node.  This is a vector qpol_rule_t pointers.
 * The caller shall not call apol_vector_destroy() upon this pointer.
 *
 * @param r Relabel result node.
 *
 * @return Pointer to a vector of rules, relative to the policy
 * originally used to generate the relabelling result.
 */
extern apol_vector_t *apol_relabel_result_get_from(apol_relabel_result_t *r);

/**
 * Return the relabelboth vector embedded within an
 * apol_relabel_result node.  This is a vector qpol_rule_t pointers.
 * The caller shall not call apol_vector_destroy() upon this pointer.
 *
 * @param r Relabel result node.
 *
 * @return Pointer to a vector of rules, relative to the policy
 * originally used to generate the relabelling result.
 */
extern apol_vector_t *apol_relabel_result_get_both(apol_relabel_result_t *r);

#endif

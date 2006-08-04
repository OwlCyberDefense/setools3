/**
 *  @file apol_tcl_rules.h
 *  Apol interface to perform rule searches.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2006 Tresys Technology, LLC
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

#ifndef APOL_TCL_RULES_H
#define APOL_TCL_RULES_H

#include <tcl.h>

/**
 * Convert an apol vector of qpol_avrule_t pointers to a Tcl
 * representation.
 *
 * @param interp Tcl interpreter object.
 * @param v Apol vector to convert.
 * @param obj Destination to create Tcl list.
 *
 * @return 0 on success, < 0 on error.
 */
extern int apol_vector_avrule_to_tcl_list(Tcl_Interp *interp,
					  apol_vector_t *v,
					  Tcl_Obj **obj);

/**
 * Convert an apol vector of qpol_terule_t pointers to a Tcl
 * representation.
 *
 * @param interp Tcl interpreter object.
 * @param v Apol vector to convert.
 * @param obj Destination to create Tcl list.
 *
 * @return 0 on success, < 0 on error.
 */
extern int apol_vector_terule_to_tcl_list(Tcl_Interp *interp,
					  apol_vector_t *v,
					  Tcl_Obj **obj);

/**
 * Given a Tcl object, retrieve the qpol_avrule_t stored within.  If
 * the object is not already a qpol_avrule_tcl_obj_type, shimmer it to
 * a qpol_avrule_tcl_obj_type before returning the rule.
 *
 * @param interp Tcl interpreter object.
 * @param o Tcl object from which to get qpol_avrule_t.
 * @param rule Reference to where to write result.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 */
extern int tcl_obj_to_qpol_avrule(Tcl_Interp *interp, Tcl_Obj *o, qpol_avrule_t **rule);

/**
 * Given a Tcl object, retrieve the qpol_terule_t stored within.  If
 * the object is not already a qpol_terule_tcl_obj_type, shimmer it to
 * a qpol_terule_tcl_obj_type before returning the rule.
 *
 * @param interp Tcl interpreter object.
 * @param o Tcl object from which to get qpol_terule_t.
 * @param rule Reference to where to write result.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 */
extern int tcl_obj_to_qpol_terule(Tcl_Interp *interp, Tcl_Obj *o, qpol_terule_t **rule);

/**
 * Given a Tcl object, retrieve the qpol_syn_avrule_t stored within.
 * If the object is not already a qpol_syn_avrule_tcl_obj_type,
 * shimmer it to a qpol_syn_avrule_tcl_obj_type before returning the
 * rule.
 *
 * @param interp Tcl interpreter object.
 * @param o Tcl object from which to get qpol_syn_avrule_t.
 * @param rule Reference to where to write result.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 */
extern int tcl_obj_to_qpol_syn_avrule(Tcl_Interp *interp, Tcl_Obj *o, qpol_syn_avrule_t **rule);

/**
 * Given a Tcl object, retrieve the qpol_syn_terule_t stored within.
 * If the object is not already a qpol_syn_terule_tcl_obj_type,
 * shimmer it to a qpol_syn_terule_tcl_obj_type before returning the
 * rule.
 *
 * @param interp Tcl interpreter object.
 * @param o Tcl object from which to get qpol_syn_terule_t.
 * @param rule Reference to where to write result.
 *
 * @return TCL_OK on success, TCL_ERROR on error.
 */
extern int tcl_obj_to_qpol_syn_terule(Tcl_Interp *interp, Tcl_Obj *o, qpol_syn_terule_t **rule);

int apol_tcl_rules_init(Tcl_Interp *interp);

#endif

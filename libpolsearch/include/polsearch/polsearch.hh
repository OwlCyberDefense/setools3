/**
 * @file
 *
 * Top level library routines.
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

#ifndef POLSEARCH_H
#define POLSEARCH_H

#ifdef __cplusplus
extern "C"
{
#endif

	/** Values to indicate the type of symbol for which to search */
	typedef enum polsearch_symbol
	{
		POLSEARCH_SYMBOL_NONE = 0,	/*!< only used for error conditions */
		POLSEARCH_SYMBOL_TYPE, /*!< query returns qpol_type_t */
		POLSEARCH_SYMBOL_ATTRIBUTE,	/*!< query returns qpol_type_t */
		POLSEARCH_SYMBOL_ROLE, /*!< query returns qpol_role_t */
		POLSEARCH_SYMBOL_USER, /*!< query returns qpol_user_t */
		POLSEARCH_SYMBOL_CLASS,	/*!< query returns qpol_class_t */
		POLSEARCH_SYMBOL_COMMON,	/*!< query returns qpol_common_t */
		POLSEARCH_SYMBOL_CATEGORY,	/*!< query returns qpol_cat_t */
		POLSEARCH_SYMBOL_LEVEL,	/*!< query returns qpol_level_t */
		POLSEARCH_SYMBOL_BOOL  /*!< query returns qpol_bool_t */
	} polsearch_symbol_e;

	/** Values to indicate the type of policy element. This is a superset of polsearch_symbol_e */
	typedef enum polsearch_element
	{
		POLSEARCH_ELEMENT_NONE = POLSEARCH_SYMBOL_NONE,	/*!< only used for error conditions */
		POLSEARCH_ELEMENT_TYPE = POLSEARCH_SYMBOL_TYPE,	/*!< qpol_type_t */
		POLSEARCH_ELEMENT_ATTRIBUTE = POLSEARCH_SYMBOL_ATTRIBUTE,	/*!< qpol_type_t */
		POLSEARCH_ELEMENT_ROLE = POLSEARCH_SYMBOL_ROLE,	/*!< qpol_role_t */
		POLSEARCH_ELEMENT_USER = POLSEARCH_SYMBOL_USER,	/*!< qpol_user_t */
		POLSEARCH_ELEMENT_CLASS = POLSEARCH_SYMBOL_CLASS,	/*!< qpol_class_t */
		POLSEARCH_ELEMENT_COMMON = POLSEARCH_SYMBOL_COMMON,	/*!< qpol_common_t */
		POLSEARCH_ELEMENT_CATEGORY = POLSEARCH_SYMBOL_CATEGORY,	/*!< qpol_cat_t */
		POLSEARCH_ELEMENT_LEVEL = POLSEARCH_SYMBOL_LEVEL,	/*!< qpol_level_t */
		POLSEARCH_ELEMENT_BOOL = POLSEARCH_SYMBOL_BOOL,	/*!< qpol_bool_t */
		POLSEARCH_ELEMENT_STRING,	/*!< char * */
		POLSEARCH_ELEMENT_AVRULE,	/*!< qpol_avrule_t */
		POLSEARCH_ELEMENT_TERULE,	/*!< qpol_terule_t */
		POLSEARCH_ELEMENT_ROLE_ALLOW,	/*!< qpol_role_allow_t */
		POLSEARCH_ELEMENT_ROLE_TRANS,	/*!< qpol_role_trans_t */
		POLSEARCH_ELEMENT_RANGE_TRANS,	/*!< qpol_range_trans_t */
		POLSEARCH_ELEMENT_FC_ENTRY,	/*!< sefs_entry_t */
		POLSEARCH_ELEMENT_MLS_RANGE,	/*!< apol_mls_range_t */
		POLSEARCH_ELEMENT_PERMISSION,	/*!< char * */
		POLSEARCH_ELEMENT_BOOL_STATE,	/*!< bool */
	} polsearch_element_e;

#ifdef __cplusplus
}

/* Include the other headers so that only this one needs to be included. */
#include "query.hh"
#include "test.hh"
#include "criterion.hh"
#include "string_list.hh"
#include "util.hh"
#include "symbol_query.hh"
#include "util.h"

#endif				       /* POLSEARCH_H */

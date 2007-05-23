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

#ifndef SERECON_H
#define SERECON_H

#ifdef __cplusplus
extern "C"
{
#endif

	/** Values to indicate the type of symbol for which to search */
	typedef enum serecon_symbol
	{
		SERECON_SYMBOL_NONE = 0,	/*!< only used for error conditions */
		SERECON_SYMBOL_TYPE,   /*!< query returns qpol_type_t */
		SERECON_SYMBOL_ATTRIBUTE,	/*!< query returns qpol_type_t */
		SERECON_SYMBOL_ROLE,   /*!< query returns qpol_role_t */
		SERECON_SYMBOL_USER,   /*!< query returns qpol_user_t */
		SERECON_SYMBOL_CLASS,  /*!< query returns qpol_class_t */
		SERECON_SYMBOL_COMMON, /*!< query returns qpol_common_t */
		SERECON_SYMBOL_CATEGORY,	/*!< query returns qpol_cat_t */
		SERECON_SYMBOL_LEVEL,  /*!< query returns qpol_level_t */
		SERECON_SYMBOL_BOOL    /*!< query returns qpol_bool_t */
	} serecon_symbol_e;

#ifdef __cplusplus
}
#endif

#endif				       /* SERECON_H */

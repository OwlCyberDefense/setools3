/**
 *  @file
 *  Headers for a dialog that allows users to explicitly remap/remap
 *  types.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
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

#ifndef REMAP_TYPES_DIALOG_H
#define REMAP_TYPES_DIALOG_H

#include "toplevel.h"

/**
 * Display and run a dialog that allows the user to add and remove
 * type remappings.
 *
 * @param top Toplevel containing poldiff structure.
 *
 * @return Non-zero if any mapping was added or removed, zero if there
 * were no changes.
 */
int remap_types_run(toplevel_t * top);

/**
 * Notify the remap types dialog that the currently loaded policies
 * have changed.  This function updates its lists of types from the
 * policies.  This function must be called at least once prior to
 * remap_types_run().
 *
 * @param orig_policy Newly loaded original policy.
 * @param mod_policy Newly loaded modified policy.
 *
 * @return 0 on success, < 0 on error.
 */
int remap_types_update(apol_policy_t * orig_policy, apol_policy_t * mod_policy);

#endif

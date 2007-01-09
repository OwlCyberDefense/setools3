/**
 *  @file
 *  Dialog that allows the user to select either a monolithic policy
 *  or a base policy + list of modules.  The dialog may also actually
 *  open the policy or it may be used simply as a file chooser.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2004-2007 Tresys Technology, LLC
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

#ifndef OPEN_POLICY_WINDOW_H
#define OPEN_POLICY_WINDOW_H

#include "toplevel.h"
#include <apol/policy-path.h>

/**
 * Display and run a dialog that allows the user open a policy, either
 * a monolithic or a modular policy.
 *
 * @param top Toplevel for the application.
 * @param path If not NULL, the default path for the policy.
 * @param selection If non-NULL, then allocate and set this reference
 * pointer to the path selected; caller must call
 * apol_policy_path_destroy() afterwards.  Otherwise if NULL then
 * actually load the policy and set the path tloplvel_open_policy().
 */
void open_policy_window_run(toplevel_t * top, const apol_policy_path_t * path, apol_policy_path_t ** selection);

#endif

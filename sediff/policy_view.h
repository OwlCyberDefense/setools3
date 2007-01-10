/**
 *  @file
 *  Header for routines related to showing the parts of a policy --
 *  its statistics and its source, if available.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
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
#ifndef POLICY_VIEW_H
#define POLICY_VIEW_H

#include "sediffx.h"
#include "toplevel.h"

typedef struct policy_view policy_view_t;

/**
 * Allocate and return an instance of a policy view object.  This
 * object is responsible for showing the statistics and policy source
 * (if available) for a particular policy.
 *
 * @param top Toplevel object containing view's widgets.
 * @param which Which policy to show.
 *
 * @return An initialized policy_view object, or NULL upon error.  The
 * caller must call policy_view_destroy() afterwards.
 */
policy_view_t *policy_view_create(toplevel_t * top, sediffx_policy_e which);

/**
 * Deallocate all space associated with the referenced view.  This
 * does nothing if the pointer is already NULL.
 *
 * @param view Reference to a policy_view to destroy.  Afterwards the
 * pointer will be set to NULL.
 */
void policy_view_destroy(policy_view_t ** view);

#endif

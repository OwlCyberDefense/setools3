/**
 *  @file policy_view.h
 *  Declaration of viewer for the currently loaded policy.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "toplevel.h"

#include <seaudit/message.h>

typedef struct policy_view policy_view_t;

/**
 * Create a new policy view object.  This is used to display the
 * policy's content and to search for TE rules.
 *
 * @param top Toplevel object that will control the newly opened
 * policy view.
 *
 * @return An initialized policy view object, or NULL upon error.  The
 * caller must call policy_view_destroy() upon the returned value.
 */
policy_view_t *policy_view_create(toplevel_t * top);

/**
 * Destroy the policy view object.  This does nothing if the pointer
 * is set to NULL.
 *
 * @param pv Reference to a policy view object.  Afterwards the
 * pointer will be set to NULL.
 */
void policy_view_destroy(policy_view_t ** pv);

/**
 * (Re)synchronize the policy displayed in the viewer with the one
 * actually loaded.  If there is no policy loaded then clear the
 * viewer's contents.
 *
 * @param pv Policy view to update.
 * @param path Path to the policy, or NULL if no policy is loaded.
 */
void policy_view_update(policy_view_t * pv, const char *path);

/**
 * (Re)open the policy view window to allow the user to search for TE
 * rules in the currently opened policy.  If message is not NULL then
 * set the query's initial parameters to the message's source type,
 * target type, and object class.
 *
 * @param pv Policy view object.  Note that a policy must already
 * exist and policy_view_update() must be first called.
 * @param message If non-NULL, the initial parameters for query.
 */
void policy_view_find_terules(policy_view_t * pv, seaudit_message_t * message);

#endif

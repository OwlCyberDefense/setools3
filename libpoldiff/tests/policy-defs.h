/**
 *  @file
 *
 *  Header file defining location of test policies.
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

#ifndef POLICY_DEFS
#define POLICY_DEFS

#include <config.h>

#define POLICY_ROOT TEST_POLICIES "/setools-3.2/sediff"

#define COMPONENTS_ORIG_POLICY (POLICY_ROOT "/testing-component-orig.conf")
#define COMPONENTS_MOD_POLICY (POLICY_ROOT "/testing-component-mod.conf")

#define RULES_ORIG_POLICY (POLICY_ROOT "/testing-rules-orig.conf")
#define RULES_MOD_POLICY (POLICY_ROOT "/testing-rules-mod.conf")

#define MLS_ORIG_POLICY (POLICY_ROOT "/testing-mls-orig.conf")
#define MLS_MOD_POLICY (POLICY_ROOT "/testing-mls-mod.conf")

#define NOMLS_ORIG_POLICY (POLICY_ROOT "/testing-mls-orig.conf")
#define NOMLS_MOD_POLICY (POLICY_ROOT "/testing-mls-mod-nomls.conf")

#endif

/**
 * SWIG declarations for libapol.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

%module apol

#define __attribute__(x)

%{
#include "../include/apol/avl-util.h"
#include "../include/apol/avrule-query.h"
#include "../include/apol/bool-query.h"
#include "../include/apol/bst.h"
#include "../include/apol/class-perm-query.h"
#include "../include/apol/condrule-query.h"
#include "../include/apol/constraint-query.h"
#include "../include/apol/context-query.h"
#include "../include/apol/domain-trans-analysis.h"
#include "../include/apol/fscon-query.h"
#include "../include/apol/infoflow-analysis.h"
#include "../include/apol/isid-query.h"
#include "../include/apol/mls-query.h"
#include "../include/apol/netcon-query.h"
#include "../include/apol/perm-map.h"
#include "../include/apol/policy.h"
#include "../include/apol/policy-path.h"
#include "../include/apol/policy-query.h"
#include "../include/apol/rangetrans-query.h"
#include "../include/apol/rbacrule-query.h"
#include "../include/apol/relabel-analysis.h"
#include "../include/apol/render.h"
#include "../include/apol/role-query.h"
#include "../include/apol/terule-query.h"
#include "../include/apol/type-query.h"
#include "../include/apol/types-relation-analysis.h"
#include "../include/apol/user-query.h"
#include "../include/apol/util.h"
#include "../include/apol/vector.h"
%}

%include "../include/apol/avl-util.h"
%include "../include/apol/avrule-query.h"
%include "../include/apol/bool-query.h"
%include "../include/apol/bst.h"
%include "../include/apol/class-perm-query.h"
%include "../include/apol/condrule-query.h"
%include "../include/apol/constraint-query.h"
%include "../include/apol/context-query.h"
%include "../include/apol/domain-trans-analysis.h"
%include "../include/apol/fscon-query.h"
%include "../include/apol/infoflow-analysis.h"
%include "../include/apol/isid-query.h"
%include "../include/apol/mls-query.h"
%include "../include/apol/netcon-query.h"
%include "../include/apol/perm-map.h"
%include "../include/apol/policy.h"
%include "../include/apol/policy-path.h"
%include "../include/apol/policy-query.h"
%include "../include/apol/rangetrans-query.h"
%include "../include/apol/rbacrule-query.h"
%include "../include/apol/relabel-analysis.h"
%include "../include/apol/render.h"
%include "../include/apol/role-query.h"
%include "../include/apol/terule-query.h"
%include "../include/apol/type-query.h"
%include "../include/apol/types-relation-analysis.h"
%include "../include/apol/user-query.h"
%include "../include/apol/util.h"
%include "../include/apol/vector.h"

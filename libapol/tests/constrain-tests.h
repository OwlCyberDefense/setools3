/**
 *  @file
 *
 *  Declarations for libapol constraint tests.
 *
 *
 *  Copyright (C) 2010 Tresys Technology, LLC
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

#ifndef CONSTRAIN_TESTS_H
#define CONSTRAIN_TESTS_H

#include <CUnit/CUnit.h>

extern CU_TestInfo constrain_tests[];
extern int constrain_init();
extern int constrain_cleanup();

#endif

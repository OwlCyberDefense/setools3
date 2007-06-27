/**
 *  @file
 *
 *  Header file for libpoldiff's correctness of rules.
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

#ifndef RULES_TEST
#define RULES_TEST
int rules_test_init();
int rules_test_cleanup();

void rules_avrules_tests();
void rules_roleallow_tests();
void rules_roletrans_tests();
void rules_terules_tests();

void build_avrule_vecs();
void build_terule_vecs();
void build_roletrans_vecs();
void build_roleallow_vecs();

#endif

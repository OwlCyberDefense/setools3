/**
 *  @file
 *
 *  Header file for libpoldiff's correctness of MLS.
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

#ifndef MLS_TEST
#define MLS_TEST
int mls_test_init();
int mls_test_cleanup();

void mls_category_tests();
void mls_user_tests();
void mls_rangetrans_tests();
void mls_level_tests();
void build_category_vecs();
void build_rangetrans_vecs();
void build_level_vecs();
void build_user_vecs();

#endif

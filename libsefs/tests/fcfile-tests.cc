/**
 *  @file
 *
 *  Test the fcfile parsing and querying, introduced in SETools 3.3.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
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

#include <config.h>

#include <CUnit/CUnit.h>
#include <sefs/fcfile.hh>
#include <string.h>

#define FC_CONFED SRCDIR "/file_contexts.confed"
#define FC_UNION SRCDIR "/file_contexts.union"
#define FC_BROKEN SRCDIR "/file_contexts.broken"

static void fcfile_open()
{
	sefs_fcfile *fc1 = NULL, *fc2 = NULL;
	bool open_failed = false;
	apol_vector_t *files = apol_vector_create(NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(files);
	apol_vector_append(files, (void *)(FC_CONFED));

	try
	{
		fc1 = new sefs_fcfile(NULL, NULL);
		fc2 = new sefs_fcfile(files, NULL, NULL);
	}
	catch(...)
	{
		CU_ASSERT(0);
		open_failed = true;
	}
	delete fc1;
	fc1 = NULL;
	if (open_failed)
	{
		delete fc2;
		return;
	}

	apol_vector_destroy(&files);
	files = apol_vector_create(NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(files);
	apol_vector_append(files, (void *)(FC_UNION));
	apol_vector_append(files, (void *)(FC_BROKEN));
	size_t num_matches = 0;
	try
	{
		num_matches = fc2->appendFileList(files);
		CU_ASSERT(num_matches == 1);
	}
	catch(...)
	{
		CU_ASSERT(0);
	}
	apol_vector_destroy(&files);

	CU_ASSERT_FALSE(fc2->isMLS());
	CU_ASSERT(fc2->fclist_type() == SEFS_FCLIST_TYPE_FCFILE);

	const apol_vector_t *fileList = fc2->fileList();
	CU_ASSERT(apol_vector_get_size(fileList) == 2);
	if (apol_vector_get_size(fileList) >= 1)
	{
		CU_ASSERT_STRING_EQUAL(apol_vector_get_element(fileList, 0), FC_CONFED);
	}
	if (apol_vector_get_size(fileList) >= 2)
	{
		CU_ASSERT_STRING_EQUAL(apol_vector_get_element(fileList, 1), FC_UNION);
	}

	delete fc2;
}

int fcfile_query_map_user_lee(sefs_fclist * fc __attribute__ ((unused)), const sefs_entry * e, void *data)
{
	const apol_context_t *con = e->context();
	if (strcmp(apol_context_get_user(con), "lee_u") == 0)
	{
		CU_ASSERT(1);
		int *num_matches = static_cast < int *>(data);
		(*num_matches)++;
		CU_ASSERT_STRING_EQUAL(e->origin(), FC_CONFED);
		return 0;
	}
	else
	{
		CU_ASSERT(0);
		return -1;
	}
}

static void fcfile_query()
{
	sefs_fcfile *fc = NULL;
	int retval;
	try
	{
		fc = new sefs_fcfile(FC_CONFED, NULL, NULL);
		retval = fc->appendFile(FC_UNION);
		CU_ASSERT(retval == 0);
	}
	catch(...)
	{
		CU_ASSERT_FATAL(0);
	}

	sefs_query *q = new sefs_query();
	q->user("lee_u");
	int num_matches = 0;
	retval = fc->runQueryMap(q, fcfile_query_map_user_lee, &num_matches);
	CU_ASSERT(retval == 0 && num_matches == 2);

	q->user(NULL);
	q->role("location_r");
	apol_vector_t *entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 11);
	for (size_t i = 0; i < apol_vector_get_size(entries); i++)
	{
		sefs_entry *e = static_cast < sefs_entry * >(apol_vector_get_element(entries, i));
		const apol_context_t *con = e->context();
		const char *t = apol_context_get_type(con);
		CU_ASSERT(strcmp(t, "city_t") == 0 || strcmp(t, "state_t") == 0 || strcmp(t, "terrain_t") == 0);
		char *s = e->toString();
		printf("%s\n", s);
		CU_ASSERT_PTR_NOT_NULL(s);
		free(s);
	}
	apol_vector_destroy(&entries);

	q->type("city_t", false);
	entries = fc->runQuery(q);     // both role and type are set
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 3);
	bool found_boonsboro = false, found_sharpsburg = false, found_harpers_ferry = false;
	for (size_t i = 0; i < apol_vector_get_size(entries); i++)
	{
		sefs_entry *e = static_cast < sefs_entry * >(apol_vector_get_element(entries, i));
		const char *p = e->path();
		if (strcmp(p, "/antietam/boonsboro") == 0)
		{
			found_boonsboro = true;
		}
		else if (strcmp(p, "/sharpsburg") == 0)
		{
			found_sharpsburg = true;
		}
		else if (strcmp(p, "/harpers_ferry") == 0)
		{
			found_harpers_ferry = true;
		}
		else
		{
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_boonsboro && found_sharpsburg && found_harpers_ferry);
	apol_vector_destroy(&entries);

	q->role(NULL);
	q->type(NULL, false);
	q->objectClass(QPOL_CLASS_LNK_FILE);
	entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 6);	// 2 link files, 4 entries without explicit class
	for (size_t i = 0; i < apol_vector_get_size(entries); i++)
	{
		sefs_entry *e = static_cast < sefs_entry * >(apol_vector_get_element(entries, i));
		uint32_t objclass = e->objectClass();
		CU_ASSERT(objclass == QPOL_CLASS_LNK_FILE || objclass == QPOL_CLASS_ALL);
	}
	apol_vector_destroy(&entries);

	q->objectClass("file");
	entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 8);	// 4 files, 4 entries without explicit class
	size_t num_files = 0, num_alls = 0;
	for (size_t i = 0; i < apol_vector_get_size(entries); i++)
	{
		sefs_entry *e = static_cast < sefs_entry * >(apol_vector_get_element(entries, i));
		uint32_t objclass = e->objectClass();
		if (objclass == QPOL_CLASS_FILE)
		{
			num_files++;
		}
		else if (objclass == QPOL_CLASS_ALL)
		{
			num_alls++;
		}
		else
		{
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(num_files == 4 && num_alls == 4);
	apol_vector_destroy(&entries);

	// setting any of these should have no effect upon results
	q->range("s0", APOL_QUERY_EXACT);
	q->inode(42);
	q->dev("first_maryland_campaign");
	entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 8);
	num_files = 0, num_alls = 0;
	for (size_t i = 0; i < apol_vector_get_size(entries); i++)
	{
		sefs_entry *e = static_cast < sefs_entry * >(apol_vector_get_element(entries, i));
		uint32_t objclass = e->objectClass();
		if (objclass == QPOL_CLASS_FILE)
		{
			num_files++;
		}
		else if (objclass == QPOL_CLASS_ALL)
		{
			num_alls++;
		}
		else
		{
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(num_files == 4 && num_alls == 4);
	apol_vector_destroy(&entries);

	q->objectClass((const char *)NULL);
	q->path("/sharpsburg/main_street");
	entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 0);
	apol_vector_destroy(&entries);

	q->path("/sharpsburg/east_woods/hooker");
	entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 2);
	bool found_east_woods = false, found_hooker = false;
	for (size_t i = 0; i < apol_vector_get_size(entries); i++)
	{
		sefs_entry *e = static_cast < sefs_entry * >(apol_vector_get_element(entries, i));
		const char *path = e->path();
		if (strcmp(path, "/sharpsburg/east_woods(/.*)?") == 0)
		{
			found_east_woods = true;
		}
		else if (strcmp(path, "/sharpsburg/east_woods/hooker") == 0)
		{
			found_hooker = true;
		}
		else
		{
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_east_woods && found_hooker);
	apol_vector_destroy(&entries);

	q->path(NULL);
	q->user("hill");
	q->regex(true);
	entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 2);
	apol_vector_destroy(&entries);

	q->user("hilly");
	entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 0);
	apol_vector_destroy(&entries);

	q->user(NULL);
	q->path("/sharpsburg/dunker");
	entries = fc->runQuery(q);
	CU_ASSERT_PTR_NOT_NULL(entries);
	CU_ASSERT(apol_vector_get_size(entries) == 1);
	for (size_t i = 0; i < apol_vector_get_size(entries); i++)
	{
		sefs_entry *e = static_cast < sefs_entry * >(apol_vector_get_element(entries, i));
		const apol_context_t *con = e->context();
		CU_ASSERT_PTR_NOT_NULL(con);
		CU_ASSERT_STRING_EQUAL(apol_context_get_user(con), "");
		CU_ASSERT_STRING_EQUAL(apol_context_get_role(con), "");
		CU_ASSERT_STRING_EQUAL(apol_context_get_type(con), "");
	}
	apol_vector_destroy(&entries);

	delete q;
	delete fc;
}

// alse test: load MLS in non-MLS; load non-MLS in MLS; MLS in MLS

CU_TestInfo fcfile_tests[] = {
	{"fcfile opening files", fcfile_open}
	,
	{"fcfile queries", fcfile_query}
	,
	CU_TEST_INFO_NULL
};

int fcfile_init()
{
	return 0;
}

int fcfile_cleanup()
{
	return 0;
}

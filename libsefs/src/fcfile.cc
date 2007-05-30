/**
 *  @file
 *  Implementation of the sefs_fcfile class.
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

#include <sefs/fcfile.hh>
#include <errno.h>

/******************** public functions below ********************/

sefs_fcfile::sefs_fcfile(sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc):sefs_fclist(msg_callback, varg)
{
	_files = _entries = NULL;
	try {
		if ((_files = apol_vector_create(free)) == NULL) {
			throw new std::bad_alloc;
		}
		if ((_entries = apol_vector_create(free)) == NULL) {
			throw new std::bad_alloc;
		}
	}
	catch(...) {
		apol_vector_destroy(&_files);
		apol_vector_destroy(&_entries);
		throw;
	}
}

const apol_vector_t *sefs_fcfile::fileList() const
{
	return _files;
}

/******************** private functions below ********************/

/******************** C functions below ********************/

sefs_fclist_t *sefs_fcfile_create(sefs_callback_fn_t msg_callback, void *varg)
{
	sefs_fclist *fclist;
	try {
		fclist = new sefs_fcfile(msg_callback, varg);
	}
	catch(...) {
		errno = ENOMEM;
		return NULL;
	}
	return fclist;
}

sefs_fclist_t *sefs_fcfile_create_from_file(const char *file, sefs_callback_fn_t msg_callback, void *varg)
{
	sefs_fclist *fclist;
	try {
		fclist = new sefs_fcfile(file, msg_callback, varg);
	}
	catch(...) {
		errno = ENOMEM;
		return NULL;
	}
	return fclist;
}

sefs_fclist_t *sefs_fcfile_create_from_file_list(const apol_vector_t * files, sefs_callback_fn_t msg_callback, void *varg)
{
	sefs_fclist *fclist;
	try {
		fclist = new sefs_fcfile(files, msg_callback, varg);
	}
	catch(...) {
		errno = ENOMEM;
		return NULL;
	}
	return fclist;
}

int sefs_fcfile_append_file(sefs_fcfile_t * fcfile, const char *file)
{
	if (fcfile == NULL) {
		errno = EINVAL;
		return -1;
	}
	return fcfile->appendFile(file);
}

size_t sefs_fcfile_append_file_list(sefs_fcfile_t * fcfile, const apol_vector_t * files)
{
	if (fcfile == NULL) {
		errno = EINVAL;
		return 0;
	}
	return fcfile->appendFileList(files);
}

const apol_vector_t *sefs_fcfile_get_file_list(sefs_fcfile_t * fcfile)
{
	if (fcfile == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return fcfile->fileList();
}

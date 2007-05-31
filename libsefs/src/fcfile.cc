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

#include "sefs_internal.hh"

#include <sefs/entry.hh>
#include <sefs/fcfile.hh>
#include <apol/util.h>
#include <qpol/genfscon_query.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>

/******************** public functions below ********************/

static void fcfile_entry_free(void *elem)
{
	if (elem != NULL) {
		sefs_entry *entry = static_cast < sefs_entry * >(elem);
		delete entry;
	}
}

sefs_fcfile::sefs_fcfile(sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc):sefs_fclist(SEFS_FCLIST_TYPE_FCFILE,
													msg_callback, varg)
{
	_files = _entries = NULL;
	_mls_set = false;
	try {
		if ((_files = apol_vector_create(free)) == NULL) {
			throw new std::bad_alloc;
		}
		if ((_entries = apol_vector_create(fcfile_entry_free)) == NULL) {
			throw new std::bad_alloc;
		}
	}
	catch(...) {
		apol_vector_destroy(&_files);
		apol_vector_destroy(&_entries);
		throw;
	}
}

sefs_fcfile::sefs_fcfile(const char *file, sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc,
											      std::
											      runtime_error):sefs_fclist
	(SEFS_FCLIST_TYPE_FCFILE, msg_callback, varg)
{
	_files = _entries = NULL;
	_mls_set = false;
	try {
		if ((_files = apol_vector_create_with_capacity(1, free)) == NULL) {
			throw new std::bad_alloc;
		}
		if ((_entries = apol_vector_create(fcfile_entry_free)) == NULL) {
			throw new std::bad_alloc;
		}
		if (appendFile(file) < 0) {
			throw new std::runtime_error("Could not construct fcfile with the given file.");
		}
	}
	catch(...) {
		apol_vector_destroy(&_files);
		apol_vector_destroy(&_entries);
		throw;
	}
}

sefs_fcfile::sefs_fcfile(const apol_vector_t * files, sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc,
													 std::
													 runtime_error):sefs_fclist
	(SEFS_FCLIST_TYPE_FCFILE, msg_callback, varg)
{
	_files = _entries = NULL;
	_mls_set = false;
	try {
		if (files == NULL) {
			throw new std::runtime_error(strerror(EINVAL));
		}
		if ((_files = apol_vector_create_with_capacity(apol_vector_get_size(files), free)) == NULL) {
			throw new std::bad_alloc;
		}
		if ((_entries = apol_vector_create(fcfile_entry_free)) == NULL) {
			throw new std::bad_alloc;
		}
		if (appendFileList(files) != apol_vector_get_size(files)) {
			throw new std::runtime_error("Could not construct fcfile with the given vector.");
		}
	}
	catch(...) {
		apol_vector_destroy(&_files);
		apol_vector_destroy(&_entries);
		throw;
	}
}

sefs_fcfile::~sefs_fcfile()
{
	apol_vector_destroy(&_files);
	apol_vector_destroy(&_entries);
}

int sefs_fcfile::appendFile(const char *file)
{
	FILE *fc_file = NULL;
	char *line = NULL;
	size_t line_len = 0;
	int retval, error = 0;

	try {
		if (file == NULL) {
			error = EINVAL;
			SEFS_ERR("%s", strerror(EINVAL));
			throw new std::runtime_error(strerror(EINVAL));
		}

		fc_file = fopen(file, "r");
		if (!fc_file) {
			error = errno;
			SEFS_ERR("Unable to open file %s", file);
			throw new std::runtime_error(strerror(error));
		}

		char *s = strdup(file);
		if (s == NULL) {
			error = errno;
			SEFS_ERR("%s", strerror(error));
			throw new std::bad_alloc;
		}
		if (apol_vector_append(_files, s) < 0) {
			error = errno;
			SEFS_ERR("%s", strerror(error));
			free(s);
			throw new std::bad_alloc;
		}

		while (!feof(fc_file)) {
			if (getline(&line, &line_len, fc_file) == -1) {
				if (feof(fc_file)) {
					break;
				} else {
					error = errno;
					SEFS_ERR("%s", strerror(error));
					throw new std::bad_alloc;
				}
			}
			parse_line(line);
		}

		retval = 0;
	}
	catch(...) {
		retval = -1;
	}

	if (fc_file != NULL) {
		fclose(fc_file);
	}
	free(line);
	errno = error;
	return retval;
}

size_t sefs_fcfile::appendFileList(const apol_vector_t * files)
{
	size_t i;
	for (i = 0; i < apol_vector_get_size(files); i++) {
		if (appendFile(static_cast < char *>(apol_vector_get_element(files, i))) < 0)
		{
			return i;
		}
	}
	return i;
}

const apol_vector_t *sefs_fcfile::fileList() const
{
	return _files;
}

bool sefs_fcfile::isMLS() const
{
	if (_mls_set) {
		return _mls;
	}
	return false;
}

/******************** private functions below ********************/

void sefs_fcfile::parse_line(const char *line)
{
	int error = 0;
	char *s = strdup(line);
        apol_context_t *context = NULL;
        apol_mls_range_t *range = NULL;
        apol_mls_level_t *level = NULL;
        char *origin = "";        
	if (s == NULL) {
		error = errno;
		SEFS_ERR("%s", strerror(error));
		throw new std::bad_alloc;
	}

	apol_str_trim(s);
	if (s[0] == '#' || s[0] == '\0') {
		free(s);
		return;
	}

	try {
		size_t line_len = strlen(s);
		size_t j;
                bool found_dash = false;
                bool found_high = false;

		// extract the path
		for (j = 0; j < line_len; j++) {
			if (isspace(s[j]) || s[j] == ':') {
				// split the line
				s[j] = '\0';
			}
		}
		char *tmp = s;
		j = strlen(tmp) + 1;

		char *path = strdup(tmp);
		if (path == NULL) {
			error = errno;
			SEFS_ERR("%s", strerror(error));
			throw new std::bad_alloc;
		}
		if (apol_bst_insert_and_get(path_tree, (void **)&path, NULL) < 0) {
			error = errno;
			SEFS_ERR("%s", strerror(error));
			throw new std::bad_alloc;
		}

		while (j < line_len && s[j] == '\0') {
			j++;
		}
		if (j >= line_len) {
			// walked off the end
			error = EIO;
			SEFS_ERR("%s", "Not enough fields in line");
			throw new std::runtime_error(strerror(error));
		}

		tmp = s + j;
		uint32_t objclass;
		if (tmp[0] == '-') {
			switch (tmp[1]) {
			case '-':
				objclass = QPOL_CLASS_FILE;
				break;
			case 'd':
				objclass = QPOL_CLASS_DIR;
				break;
			case 'c':
				objclass = QPOL_CLASS_CHR_FILE;
				break;
			case 'b':
				objclass = QPOL_CLASS_BLK_FILE;
				break;
			case 'p':
				objclass = QPOL_CLASS_FIFO_FILE;
				break;
			case 'l':
				objclass = QPOL_CLASS_LNK_FILE;
				break;
			case 's':
				objclass = QPOL_CLASS_SOCK_FILE;
				break;
			default:
				error = EIO;
				SEFS_ERR("%s", "Invalid file context object class.");
				throw new std::runtime_error(strerror(error));
			}

			// advance to context
			j += 2;
			while (j < line_len && s[j] == '\0') {
				j++;
			}

			if (j >= line_len) {
				// walked off the end
				error = EIO;
				SEFS_ERR("%s", "Not enough fields in line");
				throw new std::runtime_error(strerror(error));
			}
		} else {
			// no object class explicitly given; j is pointing to context
			objclass = QPOL_CLASS_ALL;
		}

		tmp = s + j;
                    if ((context = apol_context_create()) == NULL) {
                        error = errno;
                        SEFS_ERR("%s", strerror(error));
                        throw new std::bad_alloc;
                    }
		if (strcmp(tmp, "<<none>>") == 0) {
                    goto finish_context;
                }
                // get user
                if (apol_context_set_user(NULL, context, tmp) < 0) {
                    error = errno;
                    SEFS_ERR("%s", strerror(error));
                    throw new std::bad_alloc;
                }
                j += strlen(tmp) + 2;
                if (j >= line_len) {
                    // walked off the end
                    error = EIO;
                    SEFS_ERR("%s", "Not enough fields in line");
			throw new std::runtime_error(strerror(error));
                }
                
                // get role
		tmp = s + j;
                if (apol_context_set_role(NULL, context, tmp) < 0) {
                    error = errno;
                    SEFS_ERR("%s", strerror(error));
                    throw new std::bad_alloc;
                }
                j += strlen(tmp) + 2;
		if (j >= line_len) {
			// walked off the end
                    error = EIO;
			SEFS_ERR("%s", "Not enough fields in line");
			throw new std::runtime_error(strerror(error));
		}
                
                // get type
		tmp = s + j;
                    if (apol_context_set_type(NULL, context, tmp) < 0) {
                        error = errno;
                        SEFS_ERR("%s", strerror(error));
                        throw new std::bad_alloc;
                    }
                    j += strlen(tmp) + 2;
		if (j >= line_len) {
			// at end of line -- check if MLS range is needed
                    if (_mls_set && _mls) {
			error = EIO;
			SEFS_ERR("%s", "Not enough fields in line");
			throw new std::runtime_error(strerror(error));
                    }
                    _mls_set = true;
                    _mls = false;
                    goto finish_context;
		}

                // check if MLS range is not expected
                if (_mls_set && !_mls) {
                    error = EIO;
                    SEFS_ERR("%s", "Too many fields in line");
                    throw new std::runtime_error(strerror(error));
                }
                _mls_set = true;
                _mls = true;
                tmp = s + j;

                // add low level to range being constructed
                if ((range = apol_mls_range_create()) == NULL) {
                        error = errno;
                        SEFS_ERR("%s", strerror(error));
                        throw new std::bad_alloc;
                }
                if ((level = apol_mls_level_create_from_literal(tmp)) == NULL ||
                    (apol_mls_range_set_low(NULL, range, level) < 0)) {
                    error = errno;
                    SEFS_ERR("%s", strerror(error));
                    throw new std::bad_alloc;
                }
                level = NULL;

                // check if there is a high level for the range
                j += strlen(tmp) + 2;
                for ( ; j < line_len; j++) {
                    if (s[j] == '-') {
                        if (found_dash) {
                            error = EIO;
                            SEFS_ERR("%s", "Too many dashes in context");
                            throw new std::runtime_error(strerror(error));
                        }
                        found_dash = true;
                    }
                    else if (s[j] != '\0') {
                        if (found_high) {
                            error = EIO;
                            SEFS_ERR("%s", "Too many fields in line");
                            throw new std::runtime_error(strerror(error));
                        }
                        if (!found_dash) {
                            error = EIO;
                            SEFS_ERR("%s", "Not enough dashes in context");
                            throw new std::runtime_error(strerror(error));
                        }
                        
                        tmp = s + j;
                        if ((level = apol_mls_level_create_from_literal(tmp)) == NULL ||
                            (apol_mls_range_set_high(NULL, range, level) < 0)) {
                            error = errno;
                            SEFS_ERR("%s", strerror(error));
                            throw new std::bad_alloc;
                        }
                        level = NULL;
                        j += strlen(tmp) + 1; // for loop increments j again
                        found_high = true;
                    }
                }

                if (apol_context_set_range(NULL, context, range) < 0) {
                        error = errno;
                        SEFS_ERR("%s", strerror(error));
                        throw new std::bad_alloc;
                }
                range = NULL;
                
        finish_context:
                sefs_entry *entry = new sefs_entry(context, objclass, path, origin);
                if (apol_vector_append(_entries, static_cast<void *>(entry)) < 0) {
                    error = errno;
                    delete entry;
                    SEFS_ERR("%s", strerror(error));
                    throw new std::bad_alloc;
                }
	}
	catch(...) {
		free(s);
                apol_context_destroy(&context);
                apol_mls_range_destroy(&range);
                apol_mls_level_destroy(&level);
		errno = error;
		throw;
	}
	free(s);
}

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
	try {
		fcfile->appendFile(file);
	}
	catch(...) {
		return -1;
	}
	return 0;
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

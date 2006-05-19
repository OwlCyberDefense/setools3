 /**
 *  @file policy.h
 *  Defines the public interface the QPol policy.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#include "debug.h"
#include <qpol/policy.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sepol/policydb/policydb.h>
#include <fcntl.h>

int qpol_load_policy_from_file(qpol_policy_t **policy, const char *file)
{
	int fd, rt;
	void *map = NULL;
	struct stat sb;
	struct policy_file f, *fp;

	if (policy == NULL || file == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	/* create the policy structure */
	*policy = NULL;
	if (sepol_policy_db_create(policy) < 0) {
                ERR("error initializing policy");
                return STATUS_ERR;
        } 
	/* open the file */
	if (fd = open(file, O_RDONLY) < 0) {
		ERR("can't open %s:", file, strerror(errno));
		return STATUS_ERR;
	}
	if (fstat(fd, &sb) < 0) {
		ERR("can't stat %s", file);
		goto err;
	}
	/* read the file into the policy structure */
	if (is_binary_policy_file(fd)) {
		map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (map == MAP_FAILED) {
			ERR("can not map %s", filename);
			goto err;
		}
		f.type = PF_USE_MEMORY;
		f.data = map;
		f.len = sb.st_size;
		fp = &f;
		if (policydb_read((policydb_t*)*policy, fp, 1)) {
			ERR("could not load %s", filename);
			goto err;
		}
	} else {
		ERR("source parsing is not supported yet");
		goto err;
	}
	rt = STATUS_SUCCESS;
exit: 
	if (map) {
		munmap(map, sb.st_size);
	}
	close(fd);
	return rt;
err: 
	rt = STATUS_ERR;
	goto exit;
}

int qpol_close_policy(qpol_policy_t **policy)
{
	if (policy == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	policydb_destroy((policydb_t*)*policy);
	*policy = NULL;
	return STATUS_SUCCESS;
}

/**
 *  @file class_perm_query.h
 *  Defines the public interface for searching and iterating over
 *  classes, commons, and permissions.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
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

#ifndef QPOL_CLASS_PERM_QUERY_H
#define QPOL_CLASS_PERM_QUERY_H

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

typedef struct qpol_class qpol_class_t;
typedef struct qpol_common qpol_common_t;
 
/* perms */
/**
 *  Get an iterator over the set of classes which contain a permission
 *  with the name perm.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy from which to query the classes.
 *  @param perm The name of the permission to be matched. Must be non-NULL.
 *  @param classes The iterator of type qpol_class_t returned;
 *  the user is responsible for calling qpol_iterator_destroy
 *  to free memory used. It is also important to note
 *  that an iterator is only valid as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *classes will be NULL;
 */
extern int qpol_perm_get_class_iter(qpol_handle_t *handle, qpol_policy_t *policy, const char *perm, qpol_iterator_t **classes);

/**
 *  Get an iterator over the set of commons which contain a permission
 *  with the name perm.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy from which to query the commons.
 *  @param perm The name of the permission to be matched. Must be non-NULL.
 *  @param commons The iterator of type qpol_common_t returned; 
 *  the user is responsible for calling qpol_iterator_destroy 
 *  to free memory used. It is also important to note
 *  that an iterator is only valid as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *commons will be NULL;
 */
extern int qpol_perm_get_common_iter(qpol_handle_t *handle, qpol_policy_t *policy, const char *perm, qpol_iterator_t **commons);

/* classes */
/**
 *  Get the datum for an object class by name.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy from which to get the class datum.
 *  @param name The name of the class; searching is case sensitive.
 *  @param datum Pointer in which to store the class datum. 
 *  Caller should not free this pointer.
 *  @return Returns 0 for success and < 0 for failure; if the call fails,
 *  errno will be set and *datum will be NULL;
 */
extern int qpol_policy_get_class_by_name(qpol_handle_t *handle, qpol_policy_t *policy, const char *name, qpol_class_t **datum);

/**
 *  Get an iterator for object classes in the policy.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy database from which to create the iterator.
 *  @param iter Iterator of type qpol_class_t* returned; the user 
 *  is responsible for calling qpol_iterator_destroy to free memory used. 
 *  It is also important to note that an iterator is only valid as long 
 *  as the policy is unchanged.
 *  @return Returns 0 for success and < 0 for failure; if the call fails,
 *  errno will be set and *iter will be NULL.
*/
extern int qpol_policy_get_class_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter);

/** 
 *  Get the integer value associated with a class. Values range from 1 to 
 *  the number of object classes declared in the policy.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy with which the class datum is associated. 
 *  @param datum Class datum from which to get the value. Must be non-NULL.
 *  @param value Pointer to the integer to be set to value. Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *value will be 0.
 */
extern int qpol_class_get_value(qpol_handle_t *handle, qpol_policy_t *policy, qpol_class_t *datum, uint32_t *value);

/** 
 *  Get the common used by a class.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy with which the class datum is associated. 
 *  @param datum Class datum from which to get the value. Must be non-NULL.
 *  @param common Pointer to the datum of the common associated with this
 *  class; the caller should not free this pointer. Not all classes have an
 *  associated common so it is possible for *common to be NULL on success.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *common will be NULL. 
 */
extern int qpol_class_get_common(qpol_handle_t *handle, qpol_policy_t *policy, qpol_class_t *datum, qpol_common_t **common);

/**
 *  Get an iterator for the set of (unique) permissions for a class.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy with which the class is associated.
 *  @param datum The class from which to get the permissions.
 *  @param perms Iterator of type char* returned for the list of
 *  permissions for this class. The list only contains permissions unique
 *  to the class not those included from a common. The iterator is only
 *  valid as long as the policy is unchanged; the caller is responsible
 *  for calling qpol_iterator_destroy to free memory used.
 *  @return Returns 0 for success and < 0 for failure; if the call fails,
 *  errno will be set and *perms will be NULL.
 */
extern int qpol_class_get_perm_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_class_t *datum, qpol_iterator_t **perms);

/**
 *  Get the name which identifies a class from its datum.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy with which the boolean datum is associated.
 *  @param datum Class datum for which to get the name. Must be non-NULL.
 *  @param name Pointer to the string in which to store the name.
 *  Must be non-NULL. Caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL. 
 */
extern int qpol_class_get_name(qpol_handle_t *handle, qpol_policy_t *policy, qpol_class_t *datum, char **name);

/* commons */
/**
 *  Get the datum for a common by name
 *  @param handle Error handler for the policy database.
 *  @param policy from which to get the common.
 *  @param name The name of the common; searching is case sensitive.
 *  @param datum Pointer in which to store the common datum.
 *  Caller should not free this pointer.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *datum will be NULL.
 */
extern int qpol_policy_get_common_by_name(qpol_handle_t *handle, qpol_policy_t *policy, const char *name, qpol_common_t **datum);

/**
 *  Get an iterator for commons in the policy
 *  @param handle Error handler for the policy database.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator of type qpol_common_t* returned; 
 *  the user is responsible for calling qpol_iterator_destroy to
 *  free memory used. It is also important to note that an iterator is
 *  only valid as long as the policy is unchanged.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
extern int qpol_policy_get_common_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter);

/**
 *  Get the integer value associated with a common. Values range from 1 to
 *  the number of commons declared in the policy.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy associated with the common.
 *  @param datum The common from which to get the value.
 *  @param value Pointer to the integer to be set to value. Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *value will be 0.
 */
extern int qpol_common_get_value(qpol_handle_t *handle, qpol_policy_t *policy, qpol_common_t *datum, uint32_t *value);

/**
 *  Get an iterator for the permissions included in a common.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy associated with the common.
 *  @param datum The common from which to get permissions.
 *  @param perms Iterator of type char* returned for the list of 
 *  permissions for this common. The iterator is only valid as long 
 *  as the policy is unchanged; the caller is responsible for calling 
 *  qpol_iterator_destroy to free memory used.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *perms will be NULL.
 */
extern int qpol_common_get_perm_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_common_t *datum, qpol_iterator_t **perms);

/**
 *  Get the name which identifies a common from its datum.
 *  @param handle Error handler for the policy database.
 *  @param policy associated with the common.
 *  @param datum The common from which to get the name.
 *  @param name Pointer in which to store the name. Must be non-NULL;
 *  the caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
extern int qpol_common_get_name(qpol_handle_t *handle, qpol_policy_t *policy, qpol_common_t *datum, char **name);

#endif /* QPOL_CLASS_PERM_QUERY_H */

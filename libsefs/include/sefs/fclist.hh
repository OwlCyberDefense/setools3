/**
 *  @file
 *  Defines the public interface for the file context list abstract
 *  object.  A user must call a constructor for one of sefs_fcfile_t,
 *  sefs_db_t, or sefs_filesystem_t to create a sefs_fclist_t object.
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

#ifndef SEFS_FCLIST_H
#define SEFS_FCLIST_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <stdarg.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <apol/policy.h>

#define SEFS_MSG_ERR  1		       /*!< Message describes a fatal error. */
#define SEFS_MSG_WARN 2		       /*!< Message is issued as a warning but does not represent a fatal error. */
#define SEFS_MSG_INFO 3		       /*!< Message is issued for inormational reasons and does not represent an atypical state. */

	typedef void (*sefs_callback_fn_t) (void *varg, struct sefs_fclist * fclist, int level, const char *fmt, va_list argp);

/**
 * Possible types of fclist for use with sefs_fclist_get_data().
 */
	typedef enum sefs_fclist_type
	{
		SEFS_FCLIST_TYPE_NONE = 0,	/*!< Not an actual type, used for error conditions */
		SEFS_FCLIST_TYPE_FILESYSTEM,	/*!< get_data returns sefs_filesystem_t, a representation of a file system */
		SEFS_FCLIST_TYPE_FCFILE,	/*!< get_data returns sefs_fcfile_t, a representation of a collection of file_context files */
		SEFS_FCLIST_TYPE_DB    /*!< get_data returns sefs_db_t, a representation of a database of file system contexts */
	} sefs_fclist_type_e;

#ifdef __cplusplus
}

#include <stdexcept>

struct apol_bst;
class sefs_entry;

class sefs_fclist
{
	friend class sefs_entry;

      public:
	 virtual ~sefs_fclist();

	/**
	 * Determine if the contexts in the fclist contain MLS fields.
	 * @return \a true if MLS fields are present, \a false if not
	 * or undeterminable.
	 */
	virtual bool isMLS() const = 0;

	/**
	 * Associate a policy with the fclist.  This is needed to
	 * resolve attributes and MLS ranges in queries.  If a policy
	 * is already associated, then calling this function removes
	 * that previous association.
	 * @param policy Policy to associate with \a fclist.  If NULL,
	 * remove any policy association. While \a policy is
	 * associated with \a fclist the caller should not destroy \a
	 * policy.
	 * @see sefs_query_set_type()
	 * @see sefs_query_set_range()
	 */
	void associatePolicy(apol_policy_t * new_policy);

	/**
	 * Return the policy currently associated with this fclist.
	 * Do not destroy the policy without first unassociating it
	 * (via call to sefs_fclist::associatePolicy(NULL)).
	 * @return Currently associated policy, or NULL if none is
	 * set.
	 */
	apol_policy_t *associatePolicy() const;

	/**
	 * Get the type of fclist object represented by \a fclist.
	 * @return The type of fclist object or SEFS_FCLIST_TYPE_NONE
	 * on error.
	 */
	sefs_fclist_type_e type() const;

      protected:
	 sefs_fclist(sefs_fclist_type_e type, sefs_callback_fn_t callback, void *varg) throw(std::bad_alloc);

	sefs_fclist_type_e fclist_type;
	apol_policy_t *policy;
	struct apol_bst *user_tree, *role_tree, *type_tree, *range_tree, *path_tree;

	/**
	 * Write a message to the callback stored within a fclist
	 * error handler.  If the msg_callback field is empty, then
	 * the default message callback will be used.
	 * @param level Severity of message, one of SEFS_MSG_*.
	 * @param fmt Format string to print, using syntax of
	 * printf(3).
	 */
	__attribute__ ((format(printf, 3, 4))) void handleMsg(int level, const char *fmt, ...);

      private:
	 sefs_callback_fn_t _callback;
	void *_varg;
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore
//the compatibility section.
#ifndef SWIG

	typedef struct sefs_fclist sefs_fclist_t;

/**
 * Deallocate all memory associated with the referenced fclist object,
 * and then set it to NULL.  This function does nothing if the fclist
 * object is already NULL.
 * @param Reference to a fclist object to destroy.
 */
	extern void sefs_fclist_destroy(sefs_fclist_t ** fclist);

/**
 * Get the type of fclist object represented by \a fclist.
 * @see sefs_fclist::type()
 */
	extern sefs_fclist_type_e sefs_fclist_get_type(sefs_fclist_t * fclist);

/**
 * Determine if the contexts in the fclist contain MLS fields.
 * @see sefs_fclist::isMLS()
 */
	extern bool sefs_fclist_get_is_mls(const sefs_fclist_t * fclist);

/**
 * Associate a policy with the fclist.
 * @see sefs_fclist::associatePolicy()
 * @see sefs_query_set_type()
 * @see sefs_query_set_range()
 */
	extern void sefs_fclist_associate_policy(sefs_fclist_t * fclist, apol_policy_t * policy);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_FCLIST_H */

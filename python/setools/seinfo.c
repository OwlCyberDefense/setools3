/**
 *  @file
 *  Command line tool to search TE rules.
 *
 *  @author Frank Mayer  mayerf@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Paul Rosenfeld  prosenfeld@tresys.com
 *  @author Thomas Liu  <tliu@redhat.com>
 *  @author Dan Walsh  <dwalsh@redhat.com>
 *
 *  Copyright (C) 2003-2008 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * This is a modified version of seinfo to be used as part of a library for
 * Python bindings.
 */

#include "Python.h"

/* libapol */
#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>
#include <apol/vector.h>

/* libqpol */
#include <qpol/policy.h>
#include <qpol/util.h>

/* other */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2007 Tresys Technology, LLC"
static char *policy_file = NULL;

enum input
{
	TYPE, ATTRIBUTE, ROLE, USER, PORT,
};

/**
 * Gets a textual representation of an attribute, and 
 * all of that attribute's types.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 */
static PyObject* get_attr(const qpol_type_t * type_datum, const apol_policy_t * policydb)
{
	int retval = -1;
	PyObject *dict = PyDict_New(); 
	const qpol_type_t *attr_datum = NULL;
	qpol_iterator_t *iter = NULL;
	const char *attr_name = NULL, *type_name = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	unsigned char isattr;

	if (qpol_type_get_name(q, type_datum, &attr_name))
		goto cleanup;
	PyObject *obj = PyString_FromString(attr_name);
	PyDict_SetItemString(dict, "name", obj);
	Py_DECREF(obj);

	/* get an iterator over all types this attribute has */
	if (qpol_type_get_isattr(q, type_datum, &isattr))
		goto cleanup;
	if (isattr) {	       /* sanity check */
		if (qpol_type_get_type_iter(q, type_datum, &iter))
			goto cleanup;
		PyObject *list = PyList_New(0);
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&attr_datum))
				goto cleanup;
			if (qpol_type_get_name(q, attr_datum, &type_name))
				goto cleanup;
			PyObject *obj = PyString_FromString(type_name);
			PyList_Append(list, obj);
			Py_DECREF(obj);
		}
		qpol_iterator_destroy(&iter);
		PyDict_SetItemString(dict, "types", list);
		Py_DECREF(list);
	} else		       /* this should never happen */
		goto cleanup;
	
	retval = 0;
cleanup:
	qpol_iterator_destroy(&iter);
	if (retval) {
		Py_DECREF(dict);
		return NULL;
	}
	return dict;
}

/**
 * Gets statistics regarding a policy's attributes.
 * If this function is given a name, it will attempt to
 * get statistics about a particular attribute; otherwise
 * the function gets statistics about all of the policy's
 * attributes.
 *
 * @param name Reference to an attribute's name; if NULL,
 * all object classes will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject* get_attribs(const char *name, const apol_policy_t * policydb)
{
	int retval = -1;
	PyObject *list = PyList_New(0);
	apol_attr_query_t *attr_query = NULL;
	apol_vector_t *v = NULL;
	const qpol_type_t *type_datum = NULL;
	size_t n_attrs, i;

	/* we are only getting information about 1 attribute */
	if (name != NULL) {
		attr_query = apol_attr_query_create();
		if (!attr_query)
			goto cleanup;
		if (apol_attr_query_set_attr(policydb, attr_query, name))
			goto cleanup;
		if (apol_attr_get_by_query(policydb, attr_query, &v))
			goto cleanup;
		apol_attr_query_destroy(&attr_query);
		if (apol_vector_get_size(v) == 0) {
			apol_vector_destroy(&v);
			errno = EINVAL;
			goto cleanup;
		}

		type_datum = apol_vector_get_element(v, (size_t) 0);
		PyObject *obj = get_attr(type_datum, policydb);
		PyList_Append(list, obj);
		Py_DECREF(obj);
	} else {
		attr_query = apol_attr_query_create();
		if (!attr_query)
			goto cleanup;
		if (apol_attr_get_by_query(policydb, attr_query, &v))
			goto cleanup;
		apol_attr_query_destroy(&attr_query);
		n_attrs = apol_vector_get_size(v);

		for (i = 0; i < n_attrs; i++) {
			/* get qpol_type_t* item from vector */
			type_datum = (qpol_type_t *) apol_vector_get_element(v, (size_t) i);
			if (!type_datum)
				goto cleanup;
			PyObject *obj = get_attr(type_datum, policydb);
			PyList_Append(list, obj);
			Py_DECREF(obj);
		}
	}
	apol_vector_destroy(&v);

	retval = 0;
      cleanup:
	apol_attr_query_destroy(&attr_query);
	apol_vector_destroy(&v);
	if (retval) {
		Py_DECREF(list);
		PyErr_SetString(PyExc_RuntimeError,strerror(errno));
		return NULL;
	}
	return list;
}

/**
 * Get a textual representation of a type, and
 * all of that type's attributes.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 */
static PyObject* get_type_attrs(const qpol_type_t * type_datum, const apol_policy_t * policydb)
{
	qpol_iterator_t *iter = NULL;
	const char *attr_name = NULL;
	const qpol_type_t *attr_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	if (qpol_type_get_attr_iter(q, type_datum, &iter))
		goto cleanup;
	PyObject *list = PyList_New(0);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&attr_datum))
			goto cleanup;
		if (qpol_type_get_name(q, attr_datum, &attr_name))
			goto cleanup;
		PyObject *obj = PyString_FromString(attr_name);
		PyList_Append(list, obj);
		Py_DECREF(obj);
	}

      cleanup:
	qpol_iterator_destroy(&iter);
	return list;
}

static PyObject* get_type( const qpol_type_t * type_datum, const apol_policy_t * policydb) {

	PyObject *dict = PyDict_New(); 
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	const char *type_name = NULL;

	unsigned char isalias, ispermissive, isattr;

	if (qpol_type_get_name(q, type_datum, &type_name))
		goto cleanup;
	if (qpol_type_get_isalias(q, type_datum, &isalias))
		goto cleanup;
	if (qpol_type_get_isattr(q, type_datum, &isattr))
		goto cleanup;
	if (qpol_type_get_ispermissive(q, type_datum, &ispermissive))
		goto cleanup;

	PyObject *obj = PyString_FromString(type_name);
	PyDict_SetItemString(dict, "name", obj);
	Py_DECREF(obj);
	obj = PyBool_FromLong(ispermissive);
	PyDict_SetItemString(dict, "permissive", obj);
	Py_DECREF(obj);
	if (!isattr && !isalias) {
		obj = get_type_attrs(type_datum, policydb);
		PyDict_SetItemString(dict, "attributes", obj);
		Py_DECREF(obj);
	}
	return dict;
cleanup:
	Py_DECREF(dict);
	return NULL;
}

/**
 * Gets a textual representation of a user, and
 * all of that user's roles.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * roles
 */
static PyObject* get_user(const qpol_user_t * user_datum, const apol_policy_t * policydb)
{
	PyObject *dict = NULL;
	const qpol_role_t *role_datum = NULL;
	qpol_iterator_t *iter = NULL;
	const qpol_mls_range_t *range = NULL;
	const qpol_mls_level_t *dflt_level = NULL;
	apol_mls_level_t *ap_lvl = NULL;
	apol_mls_range_t *ap_range = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	char *tmp;
	const char *user_name, *role_name;

	if (qpol_user_get_name(q, user_datum, &user_name))
		goto cleanup;

	dict = PyDict_New(); 
	PyObject *obj = PyString_FromString(user_name);
	PyDict_SetItemString(dict, "name", obj);
	Py_DECREF(obj);

	if (qpol_policy_has_capability(q, QPOL_CAP_MLS)) {
		if (qpol_user_get_dfltlevel(q, user_datum, &dflt_level))
			goto cleanup;
		ap_lvl = apol_mls_level_create_from_qpol_mls_level(policydb, dflt_level);
		tmp = apol_mls_level_render(policydb, ap_lvl);
		if (!tmp)
			goto cleanup;
		obj = PyString_FromString(tmp);
		PyDict_SetItemString(dict, "level", obj);
		Py_DECREF(obj);
		free(tmp);
		/* print default range */
		if (qpol_user_get_range(q, user_datum, &range))
			goto cleanup;
		ap_range = apol_mls_range_create_from_qpol_mls_range(policydb, range);
		tmp = apol_mls_range_render(policydb, ap_range);
		if (!tmp)
			goto cleanup;
		obj = PyString_FromString(tmp);
		PyDict_SetItemString(dict, "range", obj);
		Py_DECREF(obj);
		free(tmp);
	}
	
	if (qpol_user_get_role_iter(q, user_datum, &iter))
		goto cleanup;
	PyObject *list = PyList_New(0);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&role_datum)) {
			Py_DECREF(list);
			goto cleanup;
		}
		if (qpol_role_get_name(q, role_datum, &role_name)) {
			Py_DECREF(list);
			goto cleanup;
		}
		PyObject *obj = PyString_FromString(role_name);
		PyList_Append(list, obj);
		Py_DECREF(obj);
	}
	PyDict_SetItemString(dict, "roles", list);
	Py_DECREF(list);

cleanup:
	qpol_iterator_destroy(&iter);
	apol_mls_level_destroy(&ap_lvl);
	apol_mls_range_destroy(&ap_range);
	return dict;
}

/**
 * Gets statistics regarding a policy's users.
 * If this function is given a name, it will attempt to
 * get statistics about a particular user; otherwise
 * the function gets statistics about all of the policy's
 * users.
 *
 * @param name Reference to a user's name; if NULL,
 * all users will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject*  get_users(const char *name, const apol_policy_t * policydb)
{
	int retval = -1;
	PyObject *list = PyList_New(0);
	qpol_iterator_t *iter = NULL;
	const qpol_user_t *user_datum = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	if (name != NULL) {
		if (qpol_policy_get_user_by_name(q, name, &user_datum)) {
			errno = EINVAL;
			goto cleanup;
		}
		PyObject *obj = get_user(user_datum, policydb);
		PyList_Append(list, obj);
		Py_DECREF(obj);
	} else {
		if (qpol_policy_get_user_iter(q, &iter))
			goto cleanup;

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&user_datum))
				goto cleanup;
			PyObject *obj = get_user(user_datum, policydb);
			PyList_Append(list, obj);
			Py_DECREF(obj);
		}
		qpol_iterator_destroy(&iter);
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	if (retval) {
		Py_DECREF(list);
		PyErr_SetString(PyExc_RuntimeError,strerror(errno));
		return NULL;
	}
	return list;
}

/**
 * get a textual representation of a role, and 
 * all of that role's types.
 *
 * @param type_datum Reference to sepol type_datum
 * @param policydb Reference to a policy
 * types
 */
static PyObject* get_role(const qpol_role_t * role_datum, const apol_policy_t * policydb)
{
	int retval = -1;
	PyObject *dict = PyDict_New();
	const char *role_name = NULL, *type_name = NULL;
	const qpol_role_t *dom_datum = NULL;
	const qpol_type_t *type_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	size_t n_dom = 0, n_types = 0;

	if (qpol_role_get_name(q, role_datum, &role_name))
		goto cleanup;

	PyObject *obj = PyString_FromString(role_name);
	PyDict_SetItemString(dict, "name", obj);
	Py_DECREF(obj);

	if (qpol_role_get_dominate_iter(q, role_datum, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_dom))
		goto cleanup;
	if ((int)n_dom > 0) {
		PyObject *list = PyList_New(0);
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&dom_datum))
				goto cleanup;
			if (qpol_role_get_name(q, dom_datum, &role_name))
				goto cleanup;
			PyObject *obj = PyString_FromString(role_name);
			PyList_Append(list, obj);
			Py_DECREF(obj);
		}
		PyDict_SetItemString(dict, "dominate", list);
		Py_DECREF(list);
	}
	qpol_iterator_destroy(&iter);
	
	if (qpol_role_get_type_iter(q, role_datum, &iter))
		goto cleanup;
	if (qpol_iterator_get_size(iter, &n_types))
		goto cleanup;
	if ((int)n_types > 0) {
		PyObject *list = PyList_New(0);
		/* print types */
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type_datum))
				goto cleanup;
			if (qpol_type_get_name(q, type_datum, &type_name))
				goto cleanup;
			PyObject *obj = PyString_FromString(type_name);
			PyList_Append(list, obj);
			Py_DECREF(obj);
		}
		PyDict_SetItemString(dict, "types", list);
		Py_DECREF(list);
	}

	retval = 0;
cleanup:
	qpol_iterator_destroy(&iter);
	if (retval) {
		Py_DECREF(dict);
		PyErr_SetString(PyExc_RuntimeError,strerror(errno));
		return NULL;
	}
	return dict;
}

/**
 * Get statistics regarding a policy's ports.
 * If this function is given a name, it will attempt to
 * get statistics about a particular port; otherwise
 * the function get statistics about all of the policy's ports.
 *
 * @param name Reference to an port's name; if NULL,
 * all ports will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject*  get_ports(const char *num, const apol_policy_t * policydb)
{
	PyObject *list = PyList_New(0);
	int retval = -1;
	const qpol_portcon_t *portcon = NULL;
	qpol_iterator_t *iter = NULL;
	uint16_t low_port, high_port;
	uint8_t ocon_proto;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);
	const qpol_context_t *ctxt = NULL;
	const char *proto_str;
	PyObject *dict;
	const char *type = NULL;
	const apol_mls_range_t *range = NULL;
	char *range_str = NULL;
	PyObject *obj = NULL;
	apol_context_t *c = NULL;

	if (qpol_policy_get_portcon_iter(q, &iter))
		goto cleanup;

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&portcon))
			goto cleanup;
		if (qpol_portcon_get_low_port(q, portcon, &low_port))
			goto cleanup;
		if (qpol_portcon_get_high_port(q, portcon, &high_port))
			goto cleanup;
		if (qpol_portcon_get_protocol(q, portcon, &ocon_proto))
			goto cleanup;
		if (num) {
			if (atoi(num) < low_port || atoi(num) > high_port)
				continue;
		}

		if ((ocon_proto != IPPROTO_TCP) &&
		    (ocon_proto != IPPROTO_UDP)) 
			goto cleanup;

		if (qpol_portcon_get_context(q, portcon, &ctxt)) {
			PyErr_SetString(PyExc_RuntimeError, "Could not get for port context.");
			goto cleanup;
		}

		if ((proto_str = apol_protocol_to_str(ocon_proto)) == NULL) {
			PyErr_SetString(PyExc_RuntimeError, "Invalid protocol for port");
			goto cleanup;
		}

		if ((c = apol_context_create_from_qpol_context(policydb, ctxt)) == NULL) {
			goto cleanup;
		}
		
		if((type = apol_context_get_type(c)) == NULL) {
			apol_context_destroy(&c);
			goto cleanup;
		}
			
		dict = PyDict_New(); 
		obj = PyString_FromString(type);
		PyDict_SetItemString(dict, "type", obj);
		Py_DECREF(obj);

		if((range = apol_context_get_range(c)) == NULL) {
			goto cleanup;
		}
			
		range_str = apol_mls_range_render(policydb, range);
		if (range_str == NULL) {
			goto cleanup;
		}
		obj = PyString_FromString(range_str);
		PyDict_SetItemString(dict, "range", obj);
		Py_DECREF(obj);

		obj = PyString_FromString(proto_str);
		PyDict_SetItemString(dict, "protocol", obj);
		Py_DECREF(obj);

		obj = PyInt_FromLong(high_port);
		PyDict_SetItemString(dict, "high", obj);
		Py_DECREF(obj);

		obj = PyInt_FromLong(low_port);
		PyDict_SetItemString(dict, "low", obj);
		Py_DECREF(obj);

		PyList_Append(list, dict);
		Py_DECREF(dict);
	}
	retval = 0;
      cleanup:
	free(range_str);
	apol_context_destroy(&c);
	qpol_iterator_destroy(&iter);

	if (retval) {
		Py_DECREF(list);
		PyErr_SetString(PyExc_RuntimeError,strerror(errno));
		return NULL;
	}
	return list;
}

/**
 * Get statistics regarding a policy's roles.
 * If this function is given a name, it will attempt to
 * get statistics about a particular role; otherwise
 * the function get statistics about all of the policy's roles.
 *
 * @param name Reference to an role's name; if NULL,
 * all roles will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject*  get_roles(const char *name, const apol_policy_t * policydb)
{
	int retval = -1;
	PyObject *list = PyList_New(0);
	const qpol_role_t *role_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	if (name != NULL) {
		if (qpol_policy_get_role_by_name(q, name, &role_datum)) {
			errno = EINVAL;
			goto cleanup;
		}
		PyObject *obj = get_role(role_datum, policydb);
		PyList_Append(list, obj);
		Py_DECREF(obj);
	} else {
		if (qpol_policy_get_role_iter(q, &iter))
			goto cleanup;

		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&role_datum))
				goto cleanup;
			PyObject *obj = get_role(role_datum, policydb);
			PyList_Append(list, obj);
			Py_DECREF(obj);
		}
		qpol_iterator_destroy(&iter);
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	if (retval) {
		Py_DECREF(list);
		PyErr_SetString(PyExc_RuntimeError,strerror(errno));
		return NULL;
	}
	return list;
}

/**
 * Get statistics regarding a policy's types.
 * If this function is given a name, it will attempt to
 * print statistics about a particular type; otherwise
 * the function prints statistics about all of the policy's types.
 *
 * @param name Reference to a type's name; if NULL,
 * all object classes will be considered
 * @param policydb Reference to a policy
 *
 * @return 0 on success, < 0 on error.
 */
static PyObject* get_types(const char *name, const apol_policy_t * policydb)
{
	int retval = -1;
	PyObject *list = PyList_New(0);
	const qpol_type_t *type_datum = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policydb);

	/* if name was provided, only print that name */
	if (name != NULL) {
		if (qpol_policy_get_type_by_name(q, name, &type_datum)) {
			errno = EINVAL;
			goto cleanup;
		}
		PyObject *obj = get_type(type_datum, policydb);
		PyList_Append(list, obj);
		Py_DECREF(obj);
	} else {
		if (qpol_policy_get_type_iter(q, &iter))
			goto cleanup;
		/* Print all type names */
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			if (qpol_iterator_get_item(iter, (void **)&type_datum))
				goto cleanup;
			PyObject *obj = get_type(type_datum, policydb);
			PyList_Append(list, obj);
			Py_DECREF(obj);
		}
	}
	retval = 0;
cleanup:
	qpol_iterator_destroy(&iter);
	if (retval) {
		Py_DECREF(list);
		PyErr_SetString(PyExc_RuntimeError,strerror(errno));
		return NULL;
	}
	return list;
}

PyObject* seinfo(int type, const char *name)
{
	int rt = -1;

	apol_policy_t *policydb = NULL;
	apol_policy_path_t *pol_path = NULL;
	apol_vector_t *mod_paths = NULL;
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;
	PyObject* output = NULL;

	rt = qpol_default_policy_find(&policy_file);
	if (rt != 0) {
		PyErr_SetString(PyExc_RuntimeError,"No default policy found.");
		return NULL;
	}

	pol_path = apol_policy_path_create(path_type, policy_file, mod_paths);
	if (!pol_path) {
		free(policy_file);
		apol_vector_destroy(&mod_paths);
		PyErr_SetString(PyExc_RuntimeError,strerror(ENOMEM));
		return NULL;
	}
	apol_vector_destroy(&mod_paths);

	int policy_load_options = 0;
	policy_load_options |= QPOL_POLICY_OPTION_MATCH_SYSTEM;
	policydb = apol_policy_create_from_policy_path(pol_path, policy_load_options, NULL, NULL);
	if (!policydb) {
		free(policy_file);
		apol_policy_path_destroy(&pol_path);
		PyErr_SetString(PyExc_RuntimeError,strerror(errno));
		return NULL;
	}
	free(policy_file);

	/* display requested info */
	if (type == TYPE)
		output = get_types(name, policydb);

	if (type == ATTRIBUTE)
		output = get_attribs(name, policydb);

	if (type == ROLE)
		output = get_roles(name, policydb);

	if (type == USER)
		output = get_users(name, policydb);

	if (type == PORT)
		output = get_ports(name, policydb);

	apol_policy_destroy(&policydb);
	apol_policy_path_destroy(&pol_path);
	return output;
}

PyObject *wrap_seinfo(PyObject *self, PyObject *args){
    unsigned int type;
    char *name;
    
    if (!PyArg_ParseTuple(args, "iz", &type, &name))
        return NULL;

    return Py_BuildValue("O",seinfo(type, name));

}

static PyMethodDef methods[] = {
    {"seinfo", (PyCFunction) wrap_seinfo, METH_VARARGS},
    {NULL, NULL, 0, NULL}
};

void init_seinfo(){
    PyObject *m;
    m = Py_InitModule("_seinfo", methods);
    PyModule_AddIntConstant(m, "ATTRIBUTE", ATTRIBUTE);
    PyModule_AddIntConstant(m, "PORT", PORT);
    PyModule_AddIntConstant(m, "ROLE", ROLE);
    PyModule_AddIntConstant(m, "TYPE", TYPE);
    PyModule_AddIntConstant(m, "USER", USER);
}

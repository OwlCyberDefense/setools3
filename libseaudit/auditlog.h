/* Copyright (C) 2003-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr kcarr@tresys.com
 *         Karl MacMillan <kmacmillan@tresys.com>
 *         Jeremy Stitz <jstitz@tresys.com>
 *
 * Date: October 1, 2003
 *
 * This file contains the data structure definitions for storing
 * audit logs.
 *
 * auditlog.h
 */

#ifndef LIBAUDIT_AUDITLOG_H
#define LIBAUDIT_AUDITLOG_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <config.h>
#include <time.h>
#include <apol/util.h>
#include <apol/policy.h>
#include <apol/vector.h>
#include <errno.h>

/* The following should be defined in the make environment */
#ifndef LIBSEAUDIT_VERSION_STRING
#define LIBSEAUDIT_VERSION_STRING "UNKNOWN"
#endif

/* define the types of logs that we understand here, this will
   be assigned to the logtype of the audit_log_t */
#define AUDITLOG_SYSLOG 0
#define AUDITLOG_AUDITD 1

/*
 * msg_type_t defines the different types of audit messages this library will
 * handle.  AVC_MSG is a standard 'allowed' or 'denied' type message.
 * LOAD_POLICY_MSG is the message that results when a policy is loaded into the
 * system  BOOLEAN_MSG is the message that results when changing booleans in a
 * conditional policy. Message types are put in alphabetical order to make
 * msg_field_compare() in sort.c easier.
 */
#define BOOLEAN_MSG     0x00000001
#define AVC_MSG		0x00000002
#define	LOAD_POLICY_MSG 0x00000004

/* defines for the fields in the message types */
#define AVC_MSG_FIELD		0
#define AVC_EXE_FIELD		1
#define AVC_PATH_FIELD		2
#define AVC_DEV_FIELD		3
#define AVC_SRC_USER_FIELD	4
#define AVC_SRC_ROLE_FIELD	5
#define AVC_SRC_TYPE_FIELD	6
#define AVC_TGT_USER_FIELD	7
#define AVC_TGT_ROLE_FIELD	8
#define AVC_TGT_TYPE_FIELD	9
#define AVC_OBJ_CLASS_FIELD	10
#define AVC_PERM_FIELD		11
#define AVC_INODE_FIELD		12
#define AVC_IPADDR_FIELD        13
#define AVC_AUDIT_HEADER_FIELD  14
#define AVC_PID_FIELD		15
#define AVC_SRC_SID_FIELD       16
#define AVC_TGT_SID_FIELD       17
#define AVC_COMM_FIELD          18
#define AVC_NETIF_FIELD         19
#define AVC_KEY_FIELD           20
#define AVC_CAPABILITY_FIELD    21
#define AVC_PORT_FIELD          22
#define AVC_LPORT_FIELD         23
#define AVC_FPORT_FIELD         24
#define AVC_DEST_FIELD          25
#define AVC_SOURCE_FIELD        26
#define AVC_LADDR_FIELD         27
#define AVC_FADDR_FIELD         28
#define AVC_DADDR_FIELD         29
#define AVC_SADDR_FIELD         30
#define AVC_SRC_CONTEXT         31
#define AVC_TGT_CONTEXT         32
#define AVC_NAME_FIELD          33
#define AVC_MISC_FIELD          34
#define AVC_NUM_FIELDS		35

#define LOAD_POLICY_USERS_FIELD   35
#define LOAD_POLICY_ROLES_FIELD   36
#define LOAD_POLICY_TYPES_FIELD   37
#define LOAD_POLICY_CLASSES_FIELD 38
#define LOAD_POLICY_RULES_FIELD   39
#define LOAD_POLICY_BINARY_FIELD  40
#define LOAD_POLICY_NUM_FIELDS    6

#define BOOLEAN_NUM_BOOLS         41
#define BOOLEAN_BOOLS             42
#define BOOLEAN_VALUES            43

#define DATE_FIELD		44
#define HOST_FIELD              45
#define TIME_STAMP_SEC		46
#define TIME_STAMP_NANO		47
#define TIME_STAMP_SERIAL	48

#define MSG_MAX_NFIELDS AVC_NUM_FIELDS
#define NUM_FIELDS		49

	extern const char *audit_log_field_strs[NUM_FIELDS];
	int audit_log_field_strs_get_index(const char *str);

	enum avc_msg_class_t
	{
		AVC_AUDIT_DATA_NO_VALUE,
		AVC_AUDIT_DATA_IPC,
		AVC_AUDIT_DATA_CAP,
		AVC_AUDIT_DATA_FS,
		AVC_AUDIT_DATA_NET,
		AVC_AUDIT_DATA_MALFORMED
	};
/*
 * avc_msg contains all fields unique to an AVC message.
 */
#define AVC_DENIED  0
#define AVC_GRANTED 1
	typedef struct avc_msg
	{
		enum avc_msg_class_t avc_type;
		char *exe;	       /* executable and path */
		char *comm;
		char *path;	       /* path of the OBJECT */
		char *dev;	       /* device for the object */
		char *netif;
		char *laddr;
		char *faddr;
		char *daddr;
		char *saddr;
		char *name;
		char *ipaddr;
		time_t tm_stmp_sec;    /* audit header timestamp (seconds) */
		long tm_stmp_nano;     /* audit header timestamp (nanoseconds) */
		unsigned int serial;   /* audit header serial number */
		apol_vector_t *perms;  /* vector of pointers into audit_log->perms (hence char *) */
		int msg;	       /* message ie. AVC_DENIED or AVC_GRANTED */
		int key;
		bool_t is_key;
		int capability;
		bool_t is_capability;
		int lport;
		int fport;
		int dest;
		int port;
		int source;
		int src_user;
		int src_role;
		int src_type;
		bool_t is_src_con;
		int tgt_user;
		int tgt_role;
		int tgt_type;
		bool_t is_tgt_con;
		int obj_class;
		bool_t is_obj_class;
		unsigned int src_sid;  /* source sid */
		bool_t is_src_sid;
		unsigned int tgt_sid;  /* target sid */
		bool_t is_tgt_sid;
		unsigned int pid;      /* process ID of the subject */
		bool_t is_pid;
		unsigned long inode;   /* inode of the object */
		bool_t is_inode;
	} avc_msg_t;

/*
 * load_policy_msg contains all fields unique to the loaded policy message.
 */
	typedef struct load_policy_msg
	{
		unsigned int users;    /* number of users */
		unsigned int roles;    /* number of roles */
		unsigned int types;    /* number of types */
		unsigned int classes;  /* number of classes */
		unsigned int rules;    /* number of rules */
		unsigned int bools;    /* number of bools */
		char *binary;	       /* path for binary that was loaded */
	} load_policy_msg_t;

/*
 * boolean_msg contains all fields unique to a conditional boolean message.
 */
	typedef struct boolean_msg
	{
		int num_bools;	       /* number of booleans */
		int *booleans;	       /* ordered array of ints refering to boolean name */
		bool_t *values;	       /* ordered array 0 or 1 depending on boolean value */
	} boolean_msg_t;

/*
 * msg_t is the type for all audit log messages.  It will contain either
 * avc_msg_t OR load_policy_msg_t OR boolean_msg_t.
 */
	typedef struct msg
	{
		struct tm *date_stamp; /* audit message datestamp */
		unsigned int msg_type; /* audit message type..AVC_MSG, LOAD_POLICY_MSG or BOOLEAN_MSG */
		int host;	       /* key for the hostname that generated the message */
		union
		{
			avc_msg_t *avc_msg;	/* if msg_type = AVC_MSG */
			load_policy_msg_t *load_policy_msg;	/* if msg_type = LOAD_POLICY_MSG */
			boolean_msg_t *boolean_msg;	/* if msg_type = BOOLEAN_MSG */
		} msg_data;
	} msg_t;

/*
 * strs_t is a type for storing dynamically allocated arrays of strings.
 */
	typedef struct strs
	{
		char **strs;	       /* strings */
		int strs_sz;	       /* size of array */
		int num_strs;	       /* number of strings */
	} strs_t;

/* Set the initial size of the strings array to 100 and increment by that
 * amount as needed */
#define ARRAY_SZ 100

#define TYPE_VECTOR 0
#define USER_VECTOR 1
#define ROLE_VECTOR 2
#define OBJ_VECTOR 3
#define PERM_VECTOR 4
#define HOST_VECTOR 5
#define BOOL_VECTOR 6
#define NUM_VECTORS 7

	typedef struct audit_log
	{
		apol_vector_t *msg_list;	/* the array of messages */
		int num_bool_msgs;
		int num_load_msgs;
		int num_allow_msgs;
		int num_deny_msgs;
		apol_vector_t *malformed_msgs;
		apol_vector_t *types;
		apol_vector_t *classes;
		apol_vector_t *roles;
		apol_vector_t *users;
		apol_vector_t *perms;
		apol_vector_t *hosts;
		apol_vector_t *bools;
		int logtype;	       /* the type of log, syslog or auditlog */
	} audit_log_t;

	audit_log_t *audit_log_create(void);
	msg_t *avc_msg_create(void);
	msg_t *load_policy_msg_create(void);
	msg_t *boolean_msg_create(void);
	void audit_log_destroy(audit_log_t * tmp);
	void msg_print(msg_t * msg, FILE * file);
	void msg_destroy(msg_t * tmp); /* Free all memory associated with a message */
	int audit_log_add_msg(audit_log_t *, msg_t *);	/* add msg_t pointer to audit log database */
	int audit_log_add_str(audit_log_t * log, char *string, int *id, int which);
	int audit_log_get_str_idx(audit_log_t * log, const char *str, int which);
	const char *audit_log_get_str(audit_log_t * log, int idx, int which);
	int audit_log_add_malformed_msg(char *line, audit_log_t ** log);

	void audit_log_set_log_type(audit_log_t * log, int logtype);
	int audit_log_get_log_type(audit_log_t * log);
	bool_t audit_log_has_valid_years(audit_log_t * log);	/* does the log have valid years in the dates */

	enum avc_msg_class_t which_avc_msg_class(msg_t * msg);

#define msg_get_avc_data(msg) msg->msg_data.avc_msg
#define msg_get_load_policy_data(msg) msg->msg_data.load_policy_msg
#define msg_get_boolean_data(msg) msg->msg_data.boolean_msg

#define audit_log_add_type(log, str, id) audit_log_add_str(log, str, id, TYPE_VECTOR)
#define audit_log_add_user(log, str, id) audit_log_add_str(log, str, id, USER_VECTOR)
#define audit_log_add_role(log, str, id) audit_log_add_str(log, str, id, ROLE_VECTOR)
#define audit_log_add_obj(log, str, id)  audit_log_add_str(log, str, id, OBJ_VECTOR)
#define audit_log_add_perm(log, str, id) audit_log_add_str(log, str, id, PERM_VECTOR)
#define audit_log_add_host(log, str, id) audit_log_add_str(log, str, id, HOST_VECTOR)
#define audit_log_add_bool(log, str, id) audit_log_add_str(log, str, id, BOOL_VECTOR)

#define audit_log_get_type_idx(log, str) audit_log_get_str_idx(log, str, TYPE_VECTOR)
#define audit_log_get_user_idx(log, str) audit_log_get_str_idx(log, str, USER_VECTOR)
#define audit_log_get_role_idx(log, str) audit_log_get_str_idx(log, str, ROLE_VECTOR)
#define audit_log_get_obj_idx(log, str)  audit_log_get_str_idx(log, str, OBJ_VECTOR)
#define audit_log_get_host_idx(log, str) audit_log_get_str_idx(log, str, HOST_VECTOR)
#define audit_log_get_bool_idx(log, str) audit_log_get_str_idx(log, str, BOOL_VECTOR)

#define audit_log_get_type(log, idx) audit_log_get_str(log, idx, TYPE_VECTOR)
#define audit_log_get_user(log, idx) audit_log_get_str(log, idx, USER_VECTOR)
#define audit_log_get_role(log, idx) audit_log_get_str(log, idx, ROLE_VECTOR)
#define audit_log_get_obj(log, idx)  audit_log_get_str(log, idx, OBJ_VECTOR)
#define audit_log_get_host(log, idx) audit_log_get_str(log, idx, HOST_VECTOR)
#define audit_log_get_bool(log, idx) audit_log_get_str(log, idx, BOOL_VECTOR)

	const char *libseaudit_get_version(void);

#ifdef	__cplusplus
}
#endif

#endif

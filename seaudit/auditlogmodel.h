/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 */

#ifndef _AUDIT_LOG_MODEL_H
#define _AUDIT_LOG_MODEL_H

#include <gtk/gtktreemodel.h>
#include <gtk/gtktreesortable.h>
#include "auditlog.h"

#define SEAUDIT_TYPE_LOG_STORE	       (seaudit_log_store_get_type())
#define SEAUDIT_LOG_STORE(obj)	       (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAUDIT_TYPE_LOG_STORE, GtkListStore))
#define SEAUDIT_LOG_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SEAUDIT_TYPE_LOG_STORE, GtkListStoreClass))
#define SEAUDIT_IS_LOG_STORE(obj)	       (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAUDIT_TYPE_LOG_STORE))
#define SEAUDIT_IS_LOG_STORE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAUDIT_TYPE_LOG_STORE))
#define SEAUDIT_LOG_STORE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAUDIT_TYPE_LOG_STORE, GtkListStoreClass))

typedef struct _SEAuditLogStore
{
	GObject parent;
	audit_log_t *log;
	gint stamp;
	gint sort_column_id;
	GtkSortType order;
} SEAuditLogStore;

typedef struct _SEAuditLogStoreClass
{
	GObjectClass parent_class;
} SEAuditLogStoreClass;

GType seaudit_log_store_get_type(void);
SEAuditLogStore *seaudit_log_store_create(void);
int seaudit_log_store_open_log(SEAuditLogStore *store, FILE *file);
void seaudit_log_store_close_log(SEAuditLogStore *store);
int seaudit_log_store_iter_to_idx(SEAuditLogStore *store, GtkTreeIter *iter);
void seaudit_log_store_do_filter(SEAuditLogStore *store);
void seaudit_log_store_refresh(SEAuditLogStore *store, FILE *file);

#endif

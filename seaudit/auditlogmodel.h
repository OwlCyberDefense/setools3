/* Copyright (C) 2003-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author:  Karl MacMillan <kmacmillan@tresys.com>
 * Updated: Kevin Carr <kcarr@tresys.com>
 * Date: January 14, 2004
 */

#ifndef _AUDIT_LOG_VIEW_MODEL_H
#define _AUDIT_LOG_VIEW_MODEL_H

#include <gtk/gtktreemodel.h>
#include <gtk/gtktreesortable.h>
#include "auditlog_view.h"
#include <apol/util.h>

#define SEAUDIT_TYPE_LOG_VIEW_STORE	       (seaudit_log_view_store_get_type())
#define SEAUDIT_LOG_VIEW_STORE(obj)	       (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAUDIT_TYPE_LOG_VIEW_STORE, GtkListStore))
#define SEAUDIT_LOG_VIEW_STORE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SEAUDIT_TYPE_LOG_VIEW_STORE, GtkListStoreClass))
#define SEAUDIT_IS_LOG_VIEW_STORE(obj)	       (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAUDIT_TYPE_LOG_VIEW_STORE))
#define SEAUDIT_IS_LOG_VIEW_STORE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAUDIT_TYPE_LOG_VIEW_STORE))
#define SEAUDIT_LOG_VIEW_STORE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAUDIT_TYPE_LOG_VIEW_STORE, GtkListStoreClass))

typedef struct _SEAuditLogViewStore
{
	GObject parent;
	audit_log_view_t *log_view;
	gint stamp;
	gint sort_column_id;
	GtkSortType order;
} SEAuditLogViewStore;

typedef struct _SEAuditLogViewStoreClass
{
	GObjectClass parent_class;
} SEAuditLogViewStoreClass;

SEAuditLogViewStore *seaudit_log_view_store_create(void);
int seaudit_log_view_store_open_log(SEAuditLogViewStore *store, audit_log_t *new_log);
void seaudit_log_view_store_close_log(SEAuditLogViewStore *store);
void seaudit_log_view_store_do_filter(SEAuditLogViewStore *store);
void seaudit_log_view_store_refresh(SEAuditLogViewStore *store);
int seaudit_log_view_store_iter_to_idx(SEAuditLogViewStore *store, GtkTreeIter *iter);
GType seaudit_log_view_store_get_type(void);

#endif

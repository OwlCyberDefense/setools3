/* Copyright (C) 2003-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Kevin Carr <kcarr@tresys.com>
 * Date: October 23, 2003
 *
 * Modified by Don Patterson <don.patterson@tresys.com>
 * Comment(s): Changed to a more object-oriented design.
 *
 * Karl MacMillan <kmacmillan@tresys.com>
 *
 */

#include <config.h>

#include "filter_window.h"
#include "seaudit.h"
#include "utilgui.h"
#include "filters.h"
#include "seaudit_callback.h"
#include "../libseaudit/filters.h"
#include "../libseaudit/auditlog.h"
#include <apol/policy.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>

#define TM_YEAR_ZERO 1900

enum {
	ITEMS_LIST_COLUMN,
	NUMBER_ITEMS_LIST_COLUMNS
};

enum items_list_types_t {
	SEAUDIT_SRC_TYPES,
	SEAUDIT_SRC_USERS,
	SEAUDIT_SRC_ROLES,
	SEAUDIT_TGT_TYPES,
	SEAUDIT_TGT_USERS,
	SEAUDIT_TGT_ROLES,
	SEAUDIT_OBJECTS
};

enum select_values_source_t {
	SEAUDIT_FROM_LOG,
	SEAUDIT_FROM_POLICY,
	SEAUDIT_FROM_UNION
};

enum message_types {
	SEAUDIT_MSG_NONE,
	SEAUDIT_MSG_AVC_DENIED,
	SEAUDIT_MSG_AVC_GRANTED
};

/* define the date time options */
#define SEAUDIT_DT_OPTION_NONE 0
#define SEAUDIT_DT_OPTION_BEFORE 1
#define SEAUDIT_DT_OPTION_AFTER 2
#define SEAUDIT_DT_OPTION_BETWEEN 3

#define SEAUDIT_MAX_U16_STRLEN 5 /* the max # of chars that can be in a string representing a 16 bit digit */

const char *msg_type_strs[] = { "none", "denied", "granted" };

typedef struct  seaudit_filter_list {
	char **list;
	int size;
} seaudit_filter_list_t;

struct filter_window;

typedef struct filters_select_items {
	GtkListStore *selected_items;
	GtkListStore *unselected_items;
	enum items_list_types_t items_list_type;
        enum select_values_source_t items_source;
	GtkWindow *window;
	GladeXML *xml;
	struct filter_window *parent;
} filters_select_items_t;

typedef struct filters_date_item {
	struct tm *start;
	struct tm *end;
	unsigned int option;
} filters_date_item_t;

extern seaudit_t *seaudit_app;

/* Given the year and the month set the spin button to have the correct number of
   days for that month */
static void filter_window_date_set_number_days(int month, GtkSpinButton *button)
{
	int days[] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int cur_day;
	if (!button || month < 0)
		return;
	/* we have to get the current day because set_range moves the current day
	   by the difference minus 1 day, i.e. going from jan 20 to february
	   the day would automatically become 18 */
	cur_day = gtk_spin_button_get_value_as_int(button);
	gtk_spin_button_set_range(button, 1, days[month]);
	/* return to current day, or to the max value allowed in range*/
	gtk_spin_button_set_value(button, cur_day);
	return;
}

/* this is called whenever the month or year is changed in the date filter*/
static void filter_window_date_update_days(GladeXML *xml)
{
	int month;
	GtkWidget *widget;

	if (!xml)
		return;

	widget = glade_xml_get_widget(xml, "DateStartMonth");
	/* remember that months start with 0 in this widget */
	month = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
	widget = glade_xml_get_widget(xml, "DateStartDay");
	filter_window_date_set_number_days(month, GTK_SPIN_BUTTON(widget));

	widget = glade_xml_get_widget(xml, "DateEndMonth");
	/* remember that months start with 0 in this widget */
	month = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
	widget = glade_xml_get_widget(xml, "DateEndDay");
	filter_window_date_set_number_days(month, GTK_SPIN_BUTTON(widget));

}

/* set the frames sorrounding date options sensitive based on toggle selections */
static void filter_window_date_set_sensitive(GtkToggleButton *tb, gpointer user_data)
{
	GtkWidget *startframe;
	GtkWidget *endframe;
	filter_window_t *fw = (filter_window_t *)user_data;
	const char *name;
	/* if this toggle button is the deselected one just return */
	if (!gtk_toggle_button_get_active(tb))
		return;
	startframe = glade_xml_get_widget(fw->xml, "DateStartFrame");
	endframe = glade_xml_get_widget(fw->xml, "DateEndFrame");
	if (!startframe || !endframe)
		return;
	name =  gtk_widget_get_name(GTK_WIDGET(tb));
	if (strcmp(name, "MatchNoneRadio") == 0) {
		gtk_widget_set_sensitive(startframe, FALSE);
		gtk_widget_set_sensitive(endframe, FALSE);
	} else if (strcmp(name, "MatchBetweenRadio") == 0) {
		gtk_widget_set_sensitive(startframe, TRUE);
		gtk_widget_set_sensitive(endframe, TRUE);
	} else {
		gtk_widget_set_sensitive(startframe, TRUE);
		gtk_widget_set_sensitive(endframe, FALSE);
	}
}

/* get the option from the date filter gui */
int filters_window_get_tm_option(GladeXML *xml)
{
	GtkWidget *widget;
	widget = glade_xml_get_widget(xml, "MatchNoneRadio");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
		return SEAUDIT_DT_OPTION_NONE;
	widget = glade_xml_get_widget(xml, "MatchBeforeRadio");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
		return SEAUDIT_DT_OPTION_BEFORE;
	widget = glade_xml_get_widget(xml, "MatchAfterRadio");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
		return SEAUDIT_DT_OPTION_AFTER;
	return SEAUDIT_DT_OPTION_BETWEEN;
}

/*
   get the current time stored in the window and place in parameter tm
   unless the year is not valid, then do not overwrite the year
*/
static int filters_window_update_tm(filter_window_t *fw, bool_t start, struct tm *tm)
{
	GladeXML *xml;
	GtkWidget *widget = NULL;

	if (!fw || !tm)
		return -1;
	xml = fw->xml;
	if (start) {
		/* get the date */
		widget = glade_xml_get_widget(xml, "DateStartMonth");
		tm->tm_mon = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
		widget = glade_xml_get_widget(xml, "DateStartDay");
		tm->tm_mday = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		tm->tm_year = 0;
		/* get the hour min sec */
		widget = glade_xml_get_widget(xml, "DateStartHour");
		tm->tm_hour = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		widget = glade_xml_get_widget(xml, "DateStartMinute");
		tm->tm_min = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		widget = glade_xml_get_widget(xml, "DateStartSecond");
		tm->tm_sec = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
	} else {
		/* get the date */
		widget = glade_xml_get_widget(xml, "DateEndMonth");
		tm->tm_mon = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
		widget = glade_xml_get_widget(xml, "DateEndDay");
		tm->tm_mday = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		tm->tm_year = 0;
		/* get the hour min sec */
		widget = glade_xml_get_widget(xml, "DateEndHour");
		tm->tm_hour = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		widget = glade_xml_get_widget(xml, "DateEndMinute");
		tm->tm_min = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
		widget = glade_xml_get_widget(xml, "DateEndSecond");
		tm->tm_sec = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widget));
	}
	return 0;
}


/******************************************************************
 * The following are private methods for the filters_select_items *
 * object. This object is encapsulated by the filters object.	  *
 ******************************************************************/
static GtkEntry* filters_select_items_get_entry(filters_select_items_t *s)
{
	GtkEntry *entry;
	GtkWidget *widget;

	switch (s->items_list_type) {
	case SEAUDIT_SRC_TYPES:
		widget = glade_xml_get_widget(s->parent->xml, "SrcTypesEntry");
		break;
	case SEAUDIT_TGT_TYPES:
		widget = glade_xml_get_widget(s->parent->xml, "TgtTypesEntry");
		break;

	case SEAUDIT_SRC_USERS:
		widget = glade_xml_get_widget(s->parent->xml, "SrcUsersEntry");
		break;
	case SEAUDIT_TGT_USERS:
		widget = glade_xml_get_widget(s->parent->xml, "TgtUsersEntry");
		break;

	case SEAUDIT_SRC_ROLES:
		widget = glade_xml_get_widget(s->parent->xml, "SrcRolesEntry");
		break;
	case SEAUDIT_TGT_ROLES:
		widget = glade_xml_get_widget(s->parent->xml, "TgtRolesEntry");
		break;

	case SEAUDIT_OBJECTS:
		widget = glade_xml_get_widget(s->parent->xml, "ObjClassEntry");
		break;
	default:
		fprintf(stderr, "Bad type specified!!\n");
		return NULL;
	};
	assert(widget);
	entry = GTK_ENTRY(widget);

	return entry;
}

/* Note: the caller must free the string */
static void filters_select_items_add_item_to_list_model(GtkTreeModel *model, const gchar *item)
{
	GtkTreeIter iter;
	gchar *str_data = NULL;
	gint row = 0;
	gboolean valid;

	/* As a defensive programming technique, we first make sure the string is */
	/* a valid size before adding it to the list store. If not, then ignore.  */
/*
	if (!is_valid_str_sz(item)) {
		fprintf(stderr, "Item string too large....Ignoring");
		return;
	}
*/

	valid = gtk_tree_model_get_iter_first(model, &iter);
	while (valid) {
		gtk_tree_model_get(model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		if (strcmp(item, str_data) < 0)
			break;
		valid = gtk_tree_model_iter_next (model, &iter);
		row++;
	}
	/* now insert it into the specified list model */
	gtk_list_store_insert(GTK_LIST_STORE(model), &iter, row);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter, ITEMS_LIST_COLUMN, item, -1);
}

static gboolean filters_select_items_is_value_selected(filters_select_items_t *filter_items_list, const gchar *item)
{
	gboolean valid;
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL(filter_items_list->selected_items);
	gchar *str_data;

	valid = gtk_tree_model_get_iter_first(model, &iter);
	while (valid) {
		gtk_tree_model_get(model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		if (strcmp(item, str_data) == 0)
			return TRUE;
		valid = gtk_tree_model_iter_next (model, &iter);
	}
	return FALSE;
}

static gboolean filters_select_items_is_value_unselected(filters_select_items_t *filter_items_list, const gchar *item)
{
	gboolean valid;
	GtkTreeIter iter;
	GtkTreeModel *model = GTK_TREE_MODEL(filter_items_list->unselected_items);
	gchar *str_data;

	valid = gtk_tree_model_get_iter_first(model, &iter);
	while (valid) {
		gtk_tree_model_get(model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		if (strcmp(item, str_data) == 0)
			return TRUE;
		valid = gtk_tree_model_iter_next (model, &iter);
	}
	return FALSE;
}

static gboolean is_value_from_current_items_source(filters_select_items_t *filter_items_list, const gchar *item_str)
{
	qpol_type_t *type;
	qpol_user_t *user;
	qpol_role_t *role;
	qpol_class_t *class;

	if (filter_items_list->items_list_type == SEAUDIT_SRC_TYPES ||
	    filter_items_list->items_list_type == SEAUDIT_TGT_TYPES)
		switch (filter_items_list->items_source) {
		case SEAUDIT_FROM_LOG:
			return (audit_log_get_type_idx(seaudit_app->cur_log, item_str) != -1);
		case SEAUDIT_FROM_POLICY:
			return (qpol_policy_get_type_by_name(seaudit_app->cur_policy->p, item_str, &type) == 0);
		case SEAUDIT_FROM_UNION:
			if (audit_log_get_type_idx(seaudit_app->cur_log, item_str) != -1)
				return TRUE;
			if (qpol_policy_get_type_by_name(seaudit_app->cur_policy->p, item_str, &type) == 0)
				return TRUE;
			return FALSE;
		default:
			break;
		}

	else if (filter_items_list->items_list_type == SEAUDIT_SRC_USERS ||
	    filter_items_list->items_list_type == SEAUDIT_TGT_USERS)
		switch (filter_items_list->items_source) {
		case SEAUDIT_FROM_LOG:
			return (audit_log_get_user_idx(seaudit_app->cur_log, item_str) != -1);
		case SEAUDIT_FROM_POLICY:
			return (qpol_policy_get_user_by_name(seaudit_app->cur_policy->p, item_str, &user) == 0);
		case SEAUDIT_FROM_UNION:
			if (audit_log_get_user_idx(seaudit_app->cur_log, item_str) != -1)
				return TRUE;
			if (qpol_policy_get_user_by_name(seaudit_app->cur_policy->p, item_str, &user) == 0)
				return TRUE;
			return FALSE;
		default:
			break;
		}

	else if (filter_items_list->items_list_type == SEAUDIT_SRC_ROLES ||
	    filter_items_list->items_list_type == SEAUDIT_TGT_ROLES)
		switch (filter_items_list->items_source) {
		case SEAUDIT_FROM_LOG:
			return (audit_log_get_role_idx(seaudit_app->cur_log, item_str) != -1);
		case SEAUDIT_FROM_POLICY:
			return (qpol_policy_get_role_by_name(seaudit_app->cur_policy->p, item_str, &role) == 0);
		case SEAUDIT_FROM_UNION:
			if (audit_log_get_role_idx(seaudit_app->cur_log, item_str) != -1)
				return TRUE;
			if (qpol_policy_get_role_by_name(seaudit_app->cur_policy->p, item_str, &role) == 0)
				return TRUE;
			return FALSE;
		default:
			break;
		}
	else if (filter_items_list->items_list_type == SEAUDIT_OBJECTS)
		switch (filter_items_list->items_source) {
		case SEAUDIT_FROM_LOG:
			return (audit_log_get_obj_idx(seaudit_app->cur_log, item_str) != -1);
		case SEAUDIT_FROM_POLICY:
			return (qpol_policy_get_class_by_name(seaudit_app->cur_policy->p, item_str, &class) == 0);
		case SEAUDIT_FROM_UNION:
			if (audit_log_get_obj_idx(seaudit_app->cur_log, item_str) != -1)
				return TRUE;
			if (qpol_policy_get_class_by_name(seaudit_app->cur_policy->p, item_str, &class) == 0)
				return TRUE;
			return FALSE;
		default:
			break;
		}
	return FALSE;
}

/* add an unselected item */
static void filters_select_items_add_unselected_value(filters_select_items_t *filter_items_list, const gchar *item)
{
	if (filters_select_items_is_value_selected(filter_items_list, item))
		return;
	if (filters_select_items_is_value_unselected(filter_items_list, item))
		return;
	filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(filter_items_list->unselected_items), item);
}

static void filters_select_items_add_selected_value(filters_select_items_t *filter_items_list, const gchar *item)
{
	if (filters_select_items_is_value_selected(filter_items_list, item))
		return;
	if (filters_select_items_is_value_unselected(filter_items_list, item))
		return;
	filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(filter_items_list->selected_items), item);
}

static void filters_select_items_set_objects_list_stores_default_values(filters_select_items_t *filter_items_list)
{
	int i;
	const char *object;
	char *class_name;
	apol_vector_t *class_vector;
	qpol_class_t *class = NULL;

	apol_get_class_by_query(seaudit_app->cur_policy, NULL, &class_vector);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		for (i = 0; (object = audit_log_get_obj(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(object, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list,
									  object);
		break;
	case SEAUDIT_FROM_POLICY:
		for (i = 0; i < apol_vector_get_size(class_vector); i++) {
			/* Add to excluded objects list store */
			class = apol_vector_get_element(class_vector, i);
			qpol_class_get_name(seaudit_app->cur_policy->p, class, &class_name);
			filters_select_items_add_unselected_value(filter_items_list, class_name);
		}
		break;
	case SEAUDIT_FROM_UNION:
		for (i = 0; (object = audit_log_get_obj(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(object, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list,
									  object);
		for (i = 0; i < apol_vector_get_size(class_vector); i++)
			/* Add to excluded objects list store */
			class = apol_vector_get_element(class_vector, i);
			qpol_class_get_name(seaudit_app->cur_policy->p, class, &class_name);
			filters_select_items_add_unselected_value(filter_items_list, class_name);
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
		break;
	}
	apol_vector_destroy(&class_vector, NULL);
}

static void filters_select_items_set_roles_list_stores_default_values(filters_select_items_t *filter_items_list)
{
	int i;
	const char *role;
	char *role_name;
	apol_vector_t *role_vector;
	qpol_role_t *role_type;

	apol_get_role_by_query (seaudit_app->cur_policy, NULL, &role_vector);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		for (i = 0; (role = audit_log_get_role(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(role, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list,
									  role);
		break;
	case SEAUDIT_FROM_POLICY:
		for (i = 0; i < apol_vector_get_size(role_vector); i++) {
			role_type = apol_vector_get_element(role_vector, i);
			qpol_role_get_name(seaudit_app->cur_policy->p, role_type, &role_name);
			filters_select_items_add_unselected_value(filter_items_list, role_name);
		}
		break;
	case SEAUDIT_FROM_UNION:
		for (i = 0; (role = audit_log_get_role(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(role, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list,
									  role);
		for (i = 0; i < apol_vector_get_size(role_vector); i++) {
                        role_type = apol_vector_get_element(role_vector, i);
                        qpol_role_get_name(seaudit_app->cur_policy->p, role_type, &role_name);
                        filters_select_items_add_unselected_value(filter_items_list, role_name);
		}
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
		break;
	}
	apol_vector_destroy(&role_vector, NULL);
}

static void filters_select_items_set_users_list_stores_default_values(filters_select_items_t *filter_items_list)
{
	const char *user_str;
	int i;
	apol_vector_t *user_vector;
	qpol_user_t *user;
	char *user_name;

	apol_get_user_by_query(seaudit_app->cur_policy, NULL, &user_vector);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		for (i = 0; (user_str = audit_log_get_user(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(user_str, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list,
									  user_str);
		break;
	case SEAUDIT_FROM_POLICY:
		for (i = 0; apol_vector_get_size(user_vector); i++) {
			user = apol_vector_get_element(user_vector, i);
			qpol_user_get_name(seaudit_app->cur_policy->p, user, &user_name);
			filters_select_items_add_unselected_value(filter_items_list, user_name);
		}
		break;
	case SEAUDIT_FROM_UNION:
		for (i = 0; (user_str = audit_log_get_user(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(user_str, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list,
									  user_str);
		for (i = 0; apol_vector_get_size(user_vector); i++) {
			user = apol_vector_get_element(user_vector, i);
			qpol_user_get_name(seaudit_app->cur_policy->p, user, &user_name);
			filters_select_items_add_unselected_value(filter_items_list, user_name);
		}
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
		break;
	}
	apol_vector_destroy(&user_vector, NULL);
}

static void filters_select_items_set_types_list_stores_default_values(filters_select_items_t *filter_items_list)
{
	int i;
	const char *type_str;
	apol_vector_t *type_vector;
	qpol_type_t *type;
	char *type_name;

	apol_get_type_by_query(seaudit_app->cur_policy, NULL, &type_vector);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		for (i = 0; (type_str = audit_log_get_type(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(type_str, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list,
									  type_str);
		break;
	case SEAUDIT_FROM_POLICY:
		/* start iteration of types at index 1 in order to skip 'self' type */
		for (i = 1; i < apol_vector_get_size(type_vector); i++) {
                        type = apol_vector_get_element(type_vector, i);
                        qpol_type_get_name(seaudit_app->cur_policy->p, type, &type_name);
                        filters_select_items_add_unselected_value(filter_items_list, type_name);
		}
		break;
	case SEAUDIT_FROM_UNION:
		for (i = 0; (type_str = audit_log_get_type(seaudit_app->cur_log, i)) != NULL; i++)
			if (g_utf8_validate(type_str, -1, NULL))
				filters_select_items_add_unselected_value(filter_items_list,
									  type_str);
                for (i = 1; i < apol_vector_get_size(type_vector); i++) {
                        type = apol_vector_get_element(type_vector, i);
                        qpol_type_get_name(seaudit_app->cur_policy->p, type, &type_name);
                        filters_select_items_add_unselected_value(filter_items_list, type_name);
                }
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
	}
	apol_vector_destroy(&type_vector, NULL);
}

static void filters_select_items_set_list_stores_default_values(filters_select_items_t* filter_items_list)
{
	if (filter_items_list->items_list_type == SEAUDIT_SRC_TYPES
	    || filter_items_list->items_list_type == SEAUDIT_TGT_TYPES)
		/* types */
		filters_select_items_set_types_list_stores_default_values(filter_items_list);

	else if (filter_items_list->items_list_type == SEAUDIT_SRC_USERS
		   || filter_items_list->items_list_type == SEAUDIT_TGT_USERS)
		/* users */
		filters_select_items_set_users_list_stores_default_values(filter_items_list);

	else if (filter_items_list->items_list_type == SEAUDIT_SRC_ROLES
		   || filter_items_list->items_list_type == SEAUDIT_TGT_ROLES)
		/* roles */
		filters_select_items_set_roles_list_stores_default_values(filter_items_list);

	else if (filter_items_list->items_list_type == SEAUDIT_OBJECTS )
		/* objects */
		filters_select_items_set_objects_list_stores_default_values(filter_items_list);

	else
		fprintf(stderr, "Wrong filter parameter specified.\n");
}

static void filters_select_items_refresh_unselected_list_store(filters_select_items_t *filters_select)
{
	show_wait_cursor(GTK_WIDGET(filters_select->window));
	gtk_list_store_clear(filters_select->unselected_items);
	filters_select_items_set_list_stores_default_values(filters_select);
	clear_wait_cursor(GTK_WIDGET(filters_select->window));
}

static void filters_select_items_on_radio_button_toggled(GtkToggleButton *button, gpointer user_data)
{
	filters_select_items_t *filters_select = (filters_select_items_t*)user_data;

	if (gtk_toggle_button_get_active(button)) {
		if (strcmp("LogRadioButton", gtk_widget_get_name(GTK_WIDGET(button))) == 0)
			filters_select->items_source = SEAUDIT_FROM_LOG;
		if (strcmp("PolicyRadioButton", gtk_widget_get_name(GTK_WIDGET(button))) ==0)
			filters_select->items_source = SEAUDIT_FROM_POLICY;
		if (strcmp("UnionRadioButton", gtk_widget_get_name(GTK_WIDGET(button))) == 0)
			filters_select->items_source = SEAUDIT_FROM_UNION;
		filters_select_items_refresh_unselected_list_store(filters_select);
	}
}

static void filters_select_items_fill_entry(filters_select_items_t *s)
{
	GtkTreeIter iter;
	gboolean valid, first = TRUE;
	GString *string;
	gchar *item;
	GtkEntry *entry;

	string = g_string_new("");

	valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->selected_items), &iter);
	while (valid) {
		if (first)
			first = FALSE;
		else
			g_string_append(string, ", ");
		gtk_tree_model_get(GTK_TREE_MODEL(s->selected_items), &iter, ITEMS_LIST_COLUMN, &item, -1);
		g_string_append(string, item);
		valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(s->selected_items), &iter);
	}
	entry = filters_select_items_get_entry(s);
	if (!entry) {
		fprintf(stderr, "Could not get entry widget!");
		return;
	}
	gtk_entry_set_text(entry, string->str);
	g_string_free(string, TRUE);
}

static void filters_select_items_move_to_selected_items_list(filters_select_items_t *filter_items_list)
{
	GtkTreeView *include_tree, *exclude_tree;
	GtkTreeModel *incl_model, *excl_model;
        GtkTreeIter iter;
	GList *sel_rows = NULL;
	GtkTreePath *path;
	gchar *item_str = NULL;

	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "IncludeTreeView"));
	g_assert(include_tree);
	exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "ExcludeTreeView"));
	g_assert(exclude_tree);

	incl_model = GTK_TREE_MODEL(filter_items_list->selected_items);
	excl_model = GTK_TREE_MODEL(filter_items_list->unselected_items);
	sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(exclude_tree), &excl_model);

	if(sel_rows == NULL)
		return;

	while(sel_rows != NULL) {
		path = g_list_nth_data(sel_rows, 0);
		assert(path != NULL);
		if(gtk_tree_model_get_iter(excl_model, &iter, path) == 0) {
			fprintf(stderr, "Could not get valid iterator for the selected path.\n");
			return;
		}
		gtk_tree_model_get(excl_model, &iter, ITEMS_LIST_COLUMN, &item_str, -1);
		gtk_list_store_remove(GTK_LIST_STORE(excl_model), &iter);
		filters_select_items_add_item_to_list_model(incl_model, item_str);
		g_free(item_str);

		/* Free the list of selected tree paths; we have to get the list of selected items again since the list has now changed */
		g_list_foreach(sel_rows, (GFunc) gtk_tree_path_free, NULL);
		g_list_free (sel_rows);
		sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(exclude_tree), &excl_model);
	}
	filters_select_items_fill_entry(filter_items_list);
}

static void filters_select_items_remove_selected_items(filters_select_items_t *filter_items_list)
{
	GtkTreeModel *incl_model;
	GtkTreeView *include_tree;
        GtkTreeIter iter;
	GList *sel_rows = NULL;
	GtkTreePath *path;
	gchar *item_str = NULL;

	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "IncludeTreeView"));
	g_assert(include_tree);

	incl_model = GTK_TREE_MODEL(filter_items_list->selected_items);
	sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(include_tree), &incl_model);

	if(sel_rows == NULL)
		return;

	while(sel_rows != NULL) {
		path = g_list_nth_data(sel_rows, 0);
		assert(path != NULL);
		if(gtk_tree_model_get_iter(incl_model, &iter, path) == 0) {
			fprintf(stderr, "Could not get valid iterator for the selected path.\n");
			return;
		}
		gtk_tree_model_get(incl_model, &iter, ITEMS_LIST_COLUMN, &item_str, -1);
		gtk_list_store_remove(GTK_LIST_STORE(incl_model), &iter);
		if (is_value_from_current_items_source(filter_items_list, item_str))
			filters_select_items_add_unselected_value(filter_items_list, item_str);
		g_free(item_str);

		/* Free the list of selected tree paths; we have to get the list of selected items again since the list has now changed */
		g_list_foreach(sel_rows, (GFunc) gtk_tree_path_free, NULL);
		g_list_free (sel_rows);
		sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(include_tree), &incl_model);
	}
	filters_select_items_fill_entry(filter_items_list);
}

/* filters_select_items events */
static void filters_select_items_on_add_button_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	filters_select_items_move_to_selected_items_list(filter_items_list);
}

static void filters_select_items_on_remove_button_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	filters_select_items_remove_selected_items(filter_items_list);
}

static void filters_select_on_policy_opened(void *filter_items_list)
{
	filters_select_items_t *s = (filters_select_items_t*)filter_items_list;
	GtkWidget *widget;

	widget = glade_xml_get_widget(s->xml, "PolicyRadioButton");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, TRUE);
	widget = glade_xml_get_widget(s->xml, "UnionRadioButton");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, TRUE);

	if (s->items_source == SEAUDIT_FROM_LOG)
		return;
	else
		filters_select_items_refresh_unselected_list_store(s);
}

static void filters_select_on_log_opened(void *filter_items_list)
{
	filters_select_items_t *s = (filters_select_items_t*)filter_items_list;

	if (s->items_source == SEAUDIT_FROM_POLICY)
		return;
	else
		filters_select_items_refresh_unselected_list_store(s);
}

static void filters_select_items_on_close_button_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	if (filter_items_list->window != NULL) {
		/* if there is an idle function for this window
		 * then we must remove it to avoid that function
		 * being executed after we delete the window.  This
		 * may happen if the window is closed during a search. */
		while(g_idle_remove_by_data(filter_items_list->window));

		gtk_widget_destroy(GTK_WIDGET(filter_items_list->window));
		filter_items_list->window = NULL;
		filters_select_items_fill_entry(filter_items_list);
		log_load_callback_remove(&filters_select_on_log_opened, filter_items_list);
		policy_load_callback_remove(&filters_select_on_policy_opened, filter_items_list);
	}
}

static gboolean filters_select_items_on_window_destroy(GtkWidget *widget, GdkEvent *event, filters_select_items_t *filter_items_list)
{

	filters_select_items_on_close_button_clicked(NULL, filter_items_list);
	return FALSE;
}

static void filters_select_items_on_Selected_SelectAllButton_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	GtkTreeView *include_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "IncludeTreeView"));
	g_assert(include_tree);
	gtk_tree_selection_select_all(gtk_tree_view_get_selection(include_tree));
}

static void filters_select_items_on_Selected_ClearButton_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	GtkTreeView *include_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "IncludeTreeView"));
	g_assert(include_tree);
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(include_tree));
}

static void filters_select_items_on_Unselected_SelectAllButton_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	GtkTreeView *exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "ExcludeTreeView"));
	g_assert(exclude_tree);
	gtk_tree_selection_select_all(gtk_tree_view_get_selection(exclude_tree));
}

static void filters_select_items_on_Unselected_ClearButton_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	GtkTreeView *exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(filter_items_list->xml, "ExcludeTreeView"));
	g_assert(exclude_tree);
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(exclude_tree));
}

/********************************************************************************
 * The following are public methods and callbacks for the filters_select_items
 * object only in the sense that they are exposed to the encapsulating filters
 * object.
 ********************************************************************************/
static void filters_select_items_reset_list_store(filters_select_items_t* item)
{
	/* Remove all rows from the both list stores */
	gtk_list_store_clear(item->selected_items);
	gtk_list_store_clear(item->unselected_items);

	filters_select_items_set_list_stores_default_values(item);
}

static void filters_select_items_destroy(filters_select_items_t* item)
{
	if (item == NULL)
		return;
	if (item->selected_items != NULL)
		g_object_unref(G_OBJECT(item->selected_items));
	if (item->unselected_items != NULL)
		g_object_unref(G_OBJECT(item->unselected_items));
	if (item->window != NULL)
		gtk_widget_destroy(GTK_WIDGET(item->window));
	if (item->xml != NULL)
		g_object_unref(G_OBJECT(item->xml));
	free(item);
	item = NULL;
}

static void filters_select_items_parse_entry(filters_select_items_t *s)
{
	GtkTreeIter iter;
	gboolean valid;
	const gchar *entry_text;
	gchar **items, *cur, *item;
	int cur_index;
	GtkEntry *entry;

	entry = filters_select_items_get_entry(s);
	if (!entry) {
		fprintf(stderr, "Could not get entry widget!");
		return;
	}
	entry_text = gtk_entry_get_text(entry);

	filters_select_items_reset_list_store(s);

	if (strcmp(entry_text, "") != 0) {
		items = g_strsplit(entry_text, ",", -1);
		cur = items[0];
		cur_index = 0;
		while (cur) {
			/* remove whitespace from the beginning and end */
			g_strchug(cur);
			g_strchomp(cur);
			/* See if item exists in unselected list store; if so, remove */
			if (filters_select_items_is_value_unselected(s, cur)) {
				valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->unselected_items), &iter);
				while (valid) {
					gtk_tree_model_get(GTK_TREE_MODEL(s->unselected_items), &iter, ITEMS_LIST_COLUMN, &item, -1);
					if (strcmp(cur, item) == 0) {
						gtk_list_store_remove(s->unselected_items, &iter);
						break;
					}
					valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(s->unselected_items), &iter);
					g_free(item);
				}
			}
			filters_select_items_add_selected_value(s, cur);
			cur_index++;
			cur = items[cur_index];
		}
		g_strfreev(items);
	}
}

static filters_select_items_t* filters_select_items_create(filter_window_t *parent, enum items_list_types_t items_type)
{
	filters_select_items_t *item = NULL;

	/* Create and initialize the object */
	item = (filters_select_items_t *)malloc(sizeof(filters_select_items_t));
	if (item == NULL) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	memset (item, 0, sizeof(filters_select_items_t));
	item->selected_items = gtk_list_store_new(NUMBER_ITEMS_LIST_COLUMNS, G_TYPE_STRING);
	item->unselected_items = gtk_list_store_new(NUMBER_ITEMS_LIST_COLUMNS, G_TYPE_STRING);
	item->items_list_type = items_type;
	item->parent = parent;

	return item;
}

static void filters_select_items_display(filters_select_items_t *filter_items_list, GtkWindow *parent)
{
	GladeXML *xml;
	GtkTreeView *include_tree, *exclude_tree;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *excl_column, *incl_column;
	GtkWindow *window;
	GtkWidget *widget;
	GString *path;
	char *dir;
	GtkLabel *lbl;
	GtkLabel *incl_lbl;
	GtkLabel *excl_lbl;

	/* Load the glade interface specifications */
	dir = apol_file_find("customize_filter_window.glade");
	if (!dir){
		fprintf(stderr, "could not find customize_filter_window.glade\n");
		return;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/customize_filter_window.glade");
	xml = glade_xml_new(path->str, NULL, NULL);
	g_string_free(path, TRUE);
	filter_items_list->xml = xml;
	window = GTK_WINDOW(glade_xml_get_widget(xml, "CreateFilterWindow"));
	g_assert(window);
	filter_items_list->window = window;



	/* Set this new dialog transient for the parent filters dialog so that
	 * it will be destroyed when the parent filters dialog is destroyed */
	/* set this window to be transient on the parent window, so that when it pops up it gets centered on it */
	/* however to have it "appear" to be centered we have to hide and then show */
	gtk_window_set_transient_for(window, parent);
	gtk_window_set_position(window, GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_window_set_destroy_with_parent(window, FALSE);

	if (!seaudit_app->cur_policy) {
		widget = glade_xml_get_widget(xml, "PolicyRadioButton");
		g_assert(widget);
		gtk_widget_set_sensitive(widget, FALSE);
		widget = glade_xml_get_widget(xml, "UnionRadioButton");
		g_assert(widget);
		gtk_widget_set_sensitive(widget, FALSE);
	}

	/* Connect all signals to callback functions */
	g_signal_connect(G_OBJECT(window), "delete_event",
			 G_CALLBACK(filters_select_items_on_window_destroy),
			 filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_radio_button_toggled",
				      G_CALLBACK(filters_select_items_on_radio_button_toggled),
				      filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_close_button_clicked",
				      G_CALLBACK(filters_select_items_on_close_button_clicked),
				      filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_add_button_clicked",
				      G_CALLBACK(filters_select_items_on_add_button_clicked),
				      filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_remove_button_clicked",
				      G_CALLBACK(filters_select_items_on_remove_button_clicked),
				      filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_Selected_SelectAllButton_clicked",
				      G_CALLBACK(filters_select_items_on_Selected_SelectAllButton_clicked),
				      filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_Selected_ClearButton_clicked",
				      G_CALLBACK(filters_select_items_on_Selected_ClearButton_clicked),
				      filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_Unselected_SelectAllButton_clicked",
				      G_CALLBACK(filters_select_items_on_Unselected_SelectAllButton_clicked),
				      filter_items_list);
	glade_xml_signal_connect_data(xml, "filters_select_items_on_Unselected_ClearButton_clicked",
				      G_CALLBACK(filters_select_items_on_Unselected_ClearButton_clicked),
				      filter_items_list);

	/* Set labeling */
	lbl = GTK_LABEL(glade_xml_get_widget(xml, "TitleFrameLabel"));
	incl_lbl = GTK_LABEL(glade_xml_get_widget(xml, "IncludeLabel"));
	excl_lbl = GTK_LABEL(glade_xml_get_widget(xml, "ExcludeLabel"));

	if (filter_items_list->items_list_type == SEAUDIT_SRC_TYPES) {
		gtk_window_set_title(window, "Select Source Types");
		gtk_label_set_text(lbl, "Source types:");
	} else if (filter_items_list->items_list_type == SEAUDIT_SRC_ROLES) {
		gtk_window_set_title(window, "Select Source Roles");
		gtk_label_set_text(lbl, "Source roles:");
	} else if (filter_items_list->items_list_type == SEAUDIT_SRC_USERS) {
		gtk_window_set_title(window, "Select Source Users");
		gtk_label_set_text(lbl, "Source users:");
	} else if (filter_items_list->items_list_type == SEAUDIT_TGT_TYPES) {
		gtk_window_set_title(window, "Select Target Types");
		gtk_label_set_text(lbl, "Target types:");
	} else if (filter_items_list->items_list_type == SEAUDIT_TGT_USERS) {
		gtk_window_set_title(window, "Select Target Users");
		gtk_label_set_text(lbl, "Target users:");
	} else if (filter_items_list->items_list_type == SEAUDIT_TGT_ROLES) {
		gtk_window_set_title(window, "Select Target Roles");
		gtk_label_set_text(lbl, "Target roles:");
	} else if (filter_items_list->items_list_type == SEAUDIT_OBJECTS) {
		gtk_window_set_title(window, "Select Object Classes");
		gtk_label_set_text(lbl, "Object classes:");
	} else {
		g_assert(window);
		message_display(window, GTK_MESSAGE_ERROR, "Wrong filter parameter specified.\n");
		return;
	}
	gtk_label_set_text(incl_lbl, "Selected:");
	gtk_label_set_text(excl_lbl, "Unselected:");

	/* Create the views */
	include_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "IncludeTreeView"));
	g_assert(include_tree);
	exclude_tree = GTK_TREE_VIEW(glade_xml_get_widget(xml, "ExcludeTreeView"));
	g_assert(exclude_tree);

	switch (filter_items_list->items_source) {
	case SEAUDIT_FROM_LOG:
		widget = glade_xml_get_widget(xml, "LogRadioButton");
		g_assert(widget);
		/* emits the toggled signal */
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		break;
	case SEAUDIT_FROM_POLICY:
		widget = glade_xml_get_widget(xml, "PolicyRadioButton");
		g_assert(widget);
		/* emits the toggled signal */
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		break;
	case SEAUDIT_FROM_UNION:
		widget = glade_xml_get_widget(xml, "UnionRadioButton");
		g_assert(widget);
		/* emits the toggled signal */
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		break;
	default:
		break;
	}

	gtk_tree_view_set_model(include_tree, GTK_TREE_MODEL(filter_items_list->selected_items));
	gtk_tree_view_set_model(exclude_tree, GTK_TREE_MODEL(filter_items_list->unselected_items));

	/* Display the model with cell render; specify what column to use (ITEMS_LIST_COLUMN). */
	renderer = gtk_cell_renderer_text_new();
	incl_column = gtk_tree_view_column_new_with_attributes("", renderer, "text", ITEMS_LIST_COLUMN, NULL);
	excl_column = gtk_tree_view_column_new_with_attributes("", renderer, "text", ITEMS_LIST_COLUMN, NULL);

	/* Add the column to the view. */
	gtk_tree_view_append_column(include_tree, incl_column);
	gtk_tree_view_append_column(exclude_tree, excl_column);
	gtk_tree_view_column_set_clickable(incl_column, TRUE);
	gtk_tree_view_column_set_clickable(excl_column, TRUE);

	/* Set selection mode */
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(include_tree), GTK_SELECTION_MULTIPLE);
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(exclude_tree), GTK_SELECTION_MULTIPLE);

	policy_load_callback_register(&filters_select_on_policy_opened, filter_items_list);
	log_load_callback_register(&filters_select_on_log_opened, filter_items_list);
}

/********************************************************
 * Private methods and callbacks for the filters object *
 ********************************************************/
static int filter_window_verify_filter_values(filter_window_t *filter_window)
{
	char *text = NULL;
	GtkWidget *widget = NULL;
	int i, j;
	struct tm *t1 = NULL, *t2 = NULL;

	/* check for network port filter */
	/* since we do not know if this is an ipv4 or ipv6 port we check against
	   ipv6 sizes since that is the larger of the two */
	widget = glade_xml_get_widget(filter_window->xml, "PortEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	/* check to see if the strlen of this number is larger than
	   the strlen of a __16 which is the
	   maximum size a ipv6 port can be as defined in in6.h*/
	if (strlen(text) > SEAUDIT_MAX_U16_STRLEN) {
		message_display(filter_window->window, GTK_MESSAGE_ERROR, "Invalid Port Filter.\n");
		return -1;
	}
	if (strcmp(text, "") != 0) {
		for (i = 0 ; i < strlen(text); i++) {
			if (isdigit(text[i]) == 0) {
				message_display(filter_window->window, GTK_MESSAGE_ERROR, "Invalid Port Filter.\n");
				return -1;
			}
		}
		j = atoi(text);
		/* now check that the number returned is within the range
		   of #'s allowed for a ipv6 port */
		if (j < 0 || j > (1 << 16)) {
			message_display(filter_window->window, GTK_MESSAGE_ERROR, "Invalid Port Filter.\n");
			return -1;
		}
	}

	/*check the date and time */
	if (filters_window_get_tm_option(filter_window->xml) == SEAUDIT_DT_OPTION_BETWEEN) {
		t1 = (struct tm *)calloc(1, sizeof(struct tm));
		t2 = (struct tm *)calloc(1, sizeof(struct tm));
		filters_window_update_tm(filter_window, TRUE, t1);
		filters_window_update_tm(filter_window, FALSE, t2);
		if (date_time_compare(t1, t2) > 0) {
			free(t1);
			free(t2);
			message_display(filter_window->window, GTK_MESSAGE_ERROR, "Invalid Date Filter.\n");
			return -1;
		}
		free(t1);
		free(t2);
	}
	return 0;
}

static void filter_window_set_title(filter_window_t *filter_window)
{
	GString *title;

	if (!filter_window || !filter_window->window)
		return;
	title = g_string_new("Edit filter - ");
	g_string_append(title, filter_window->name->str);
	gtk_window_set_title(filter_window->window, title->str);
	g_string_free(title, TRUE);
}

static void filter_window_set_values(filter_window_t *filter_window)
{
	GtkWidget *widget;
	GtkTextBuffer *buffer;

	filters_select_items_fill_entry(filter_window->src_types_items);
	filters_select_items_fill_entry(filter_window->src_users_items);
	filters_select_items_fill_entry(filter_window->src_roles_items);
	filters_select_items_fill_entry(filter_window->tgt_types_items);
	filters_select_items_fill_entry(filter_window->tgt_users_items);
	filters_select_items_fill_entry(filter_window->tgt_roles_items);
	filters_select_items_fill_entry(filter_window->obj_class_items);

	/* set network address */
	widget = glade_xml_get_widget(filter_window->xml, "IPAddressEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->ip_address->str);

	/* set network port */
	widget = glade_xml_get_widget(filter_window->xml, "PortEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->port->str);

	/* set network interface */
	widget = glade_xml_get_widget(filter_window->xml, "InterfaceEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->interface->str);

	/* set executable */
	widget = glade_xml_get_widget(filter_window->xml, "ExeEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->executable->str);

	/* set command */
	widget = glade_xml_get_widget(filter_window->xml, "CommEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->comm->str);

	/* set path */
	widget = glade_xml_get_widget(filter_window->xml, "PathEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->path->str);

	widget = glade_xml_get_widget(filter_window->xml, "NameEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->name->str);
	filter_window_set_title(filter_window);

	widget = glade_xml_get_widget(filter_window->xml, "MatchEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->match->str);

	widget = glade_xml_get_widget(filter_window->xml, "NotesTextView");
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
	gtk_text_buffer_set_text(buffer, filter_window->notes->str, strlen(filter_window->notes->str));

	widget = glade_xml_get_widget(filter_window->xml, "HostEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filter_window->host->str);

	/* next set the time*/
	if (filter_window->dates) {
		widget = glade_xml_get_widget(filter_window->xml, "DateStartMonth");
		gtk_combo_box_set_active(GTK_COMBO_BOX(widget), filter_window->dates->start->tm_mon);
		widget = glade_xml_get_widget(filter_window->xml, "DateStartDay");
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), filter_window->dates->start->tm_mday);
		widget = glade_xml_get_widget(filter_window->xml, "DateStartHour");
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), filter_window->dates->start->tm_hour);
		widget = glade_xml_get_widget(filter_window->xml, "DateStartMinute");
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), filter_window->dates->start->tm_min);
		widget = glade_xml_get_widget(filter_window->xml, "DateStartSecond");
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), filter_window->dates->start->tm_sec);

		widget = glade_xml_get_widget(filter_window->xml, "DateEndMonth");
		gtk_combo_box_set_active(GTK_COMBO_BOX(widget), filter_window->dates->end->tm_mon);
		widget = glade_xml_get_widget(filter_window->xml, "DateEndDay");
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), filter_window->dates->end->tm_mday);
		widget = glade_xml_get_widget(filter_window->xml, "DateEndHour");
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), filter_window->dates->end->tm_hour);
		widget = glade_xml_get_widget(filter_window->xml, "DateEndMinute");
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), filter_window->dates->end->tm_min);
		widget = glade_xml_get_widget(filter_window->xml, "DateEndSecond");
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), filter_window->dates->end->tm_sec);

		switch (filter_window->dates->option) {
		case SEAUDIT_DT_OPTION_NONE:
			widget = glade_xml_get_widget(filter_window->xml, "MatchNoneRadio");
			break;
		case SEAUDIT_DT_OPTION_BEFORE:
			widget = glade_xml_get_widget(filter_window->xml, "MatchBeforeRadio");
			break;
		case SEAUDIT_DT_OPTION_AFTER:
			widget = glade_xml_get_widget(filter_window->xml, "MatchAfterRadio");
			break;
		default :
			widget = glade_xml_get_widget(filter_window->xml, "MatchBetweenRadio");
			break;
		}
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	}
	widget = glade_xml_get_widget(filter_window->xml, "MsgCombo");
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget), filter_window->msg);

}

static void filter_window_update_values(filter_window_t *filter_window)
{
	GtkWidget *widget;
	GtkTextBuffer *buffer;
	GtkTextIter start, end;
	int rt;

	/* First parse all selection enabled entry boxes, because the user may have typed in the value */
	filters_select_items_parse_entry(filter_window->src_types_items);
	filters_select_items_parse_entry(filter_window->src_users_items);
	filters_select_items_parse_entry(filter_window->src_roles_items);
	filters_select_items_parse_entry(filter_window->tgt_types_items);
	filters_select_items_parse_entry(filter_window->tgt_users_items);
	filters_select_items_parse_entry(filter_window->tgt_roles_items);
	filters_select_items_parse_entry(filter_window->obj_class_items);

	/* update network address value */
	widget = glade_xml_get_widget(filter_window->xml, "IPAddressEntry");
	filter_window->ip_address = g_string_assign(filter_window->ip_address, gtk_entry_get_text(GTK_ENTRY(widget)));

	/* update network port value */
	widget = glade_xml_get_widget(filter_window->xml, "PortEntry");
	filter_window->port = g_string_assign(filter_window->port, gtk_entry_get_text(GTK_ENTRY(widget)));

	/* update network interface value */
	widget = glade_xml_get_widget(filter_window->xml, "InterfaceEntry");
	filter_window->interface = g_string_assign(filter_window->interface, gtk_entry_get_text(GTK_ENTRY(widget)));

	/* update executable value */
	widget = glade_xml_get_widget(filter_window->xml, "ExeEntry");
	filter_window->executable = g_string_assign(filter_window->executable, gtk_entry_get_text(GTK_ENTRY(widget)));

	/* update command value */
	widget = glade_xml_get_widget(filter_window->xml, "CommEntry");
	filter_window->comm = g_string_assign(filter_window->comm, gtk_entry_get_text(GTK_ENTRY(widget)));

	/* update path value */
	widget = glade_xml_get_widget(filter_window->xml, "PathEntry");
	filter_window->path = g_string_assign(filter_window->path, gtk_entry_get_text(GTK_ENTRY(widget)));

	widget = glade_xml_get_widget(filter_window->xml, "NameEntry");
	filter_window->name = g_string_assign(filter_window->name, gtk_entry_get_text(GTK_ENTRY(widget)));

	widget = glade_xml_get_widget(filter_window->xml, "MatchEntry");
	filter_window->match = g_string_assign(filter_window->match, gtk_entry_get_text(GTK_ENTRY(widget)));

	widget = glade_xml_get_widget(filter_window->xml, "HostEntry");
	filter_window->host = g_string_assign(filter_window->host, gtk_entry_get_text(GTK_ENTRY(widget)));

	/* update message value */
	widget = glade_xml_get_widget(filter_window->xml, "MsgCombo");
	filter_window->msg = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));

	widget = glade_xml_get_widget(filter_window->xml, "NotesTextView");
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
	gtk_text_buffer_get_start_iter(buffer, &start);
	gtk_text_buffer_get_end_iter(buffer, &end);
	filter_window->notes = g_string_assign(filter_window->notes, gtk_text_buffer_get_text(buffer, &start, &end, FALSE));

	if (filter_window->dates) {
		rt = filters_window_update_tm(filter_window, TRUE, filter_window->dates->start);
		if (rt < 0)
			return;
		rt = filters_window_update_tm(filter_window, FALSE, filter_window->dates->end);
		if (rt < 0)
			return;
		filter_window->dates->option = filters_window_get_tm_option(filter_window->xml);
	}

}

static void filter_window_seaudit_filter_list_free(seaudit_filter_list_t *list)
{
	int i;

	if (!list->list)
		return;
	for (i = 0; i < list->size; i++)
		if (list->list[i])
			free(list->list[i]);
	if (list->list)
		free(list->list);
	return;
}

/* Note: the caller must free the returned list */
static seaudit_filter_list_t* filter_window_seaudit_filter_list_get(filters_select_items_t *filters_select_item)
{
	GtkTreeModel *incl_model;
	GtkTreeIter iter;
	gchar *str_data;
	int count = 0;
	seaudit_filter_list_t *flist;
	gboolean valid;

	flist = (seaudit_filter_list_t *)malloc(sizeof(seaudit_filter_list_t));
	if (flist == NULL) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	memset (flist, 0, sizeof(seaudit_filter_list_t));
	flist->list = NULL;
	flist->size = 0;

	/* Get the model and the create the array of strings to return */
	incl_model = GTK_TREE_MODEL(filters_select_item->selected_items);
	valid = gtk_tree_model_get_iter_first(incl_model, &iter);
	while(valid) {
		gtk_tree_model_get(incl_model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		count++;
		if (flist->list == NULL) {
			flist->list = (char **)malloc(sizeof(char*));
			if(flist->list == NULL) {
				fprintf(stderr, "out of memory\n");
				return NULL;
			}
		} else {
			flist->list = (char **)realloc(flist->list, count * sizeof(char*));
			if (flist->list == NULL) {
				filter_window_seaudit_filter_list_free(flist);
				fprintf(stderr, "out of memory\n");
				return NULL;
			}
		}
		/* We subtract 1 from the count to get the correct index because count is incremented above */
		flist->list[count - 1] = (char *)malloc(strlen((const char*)str_data) + 1);
		if(flist->list[count - 1] == NULL) {
			filter_window_seaudit_filter_list_free(flist);
			fprintf(stderr, "out of memory\n");
			return NULL;
		}
		strcpy(flist->list[count - 1], (const char*)str_data);
		valid = gtk_tree_model_iter_next (incl_model, &iter);
	}
	flist->size = count;

	return flist;
}

static void filter_window_clear_other_tab_values(filter_window_t *filter_window)
{
	GtkWidget *widget;

	widget = glade_xml_get_widget(filter_window->xml, "IPAddressEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");

	/* clear network port */
	widget = glade_xml_get_widget(filter_window->xml, "PortEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");

	/* clear network interface */
	widget = glade_xml_get_widget(filter_window->xml, "InterfaceEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");

	/* clear executable */
	widget = glade_xml_get_widget(filter_window->xml, "ExeEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");

	/* clear command */
	widget = glade_xml_get_widget(filter_window->xml, "CommEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");

	/* clear path */
	widget = glade_xml_get_widget(filter_window->xml, "PathEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");

	/* clear message */
	widget = glade_xml_get_widget(filter_window->xml, "MsgCombo");
	g_assert(widget);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget), SEAUDIT_MSG_NONE);


}

static void filter_window_clear_context_tab_values(filter_window_t *filter_window)
{
	GtkEntry *entry;

	entry = filters_select_items_get_entry(filter_window->src_types_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");

	entry = filters_select_items_get_entry(filter_window->src_users_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");

	entry = filters_select_items_get_entry(filter_window->src_roles_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");

	entry = filters_select_items_get_entry(filter_window->tgt_types_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");

	entry = filters_select_items_get_entry(filter_window->tgt_users_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");

	entry = filters_select_items_get_entry(filter_window->tgt_roles_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");

	entry = filters_select_items_get_entry(filter_window->obj_class_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");
}

static void filter_window_on_custom_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	if (filter_items_list->window != NULL) {
		/* add anything from the entry to the list stores */
		filters_select_items_parse_entry(filter_items_list);
		gtk_window_present(filter_items_list->window);
		return;
	}
	/* add anything from the entry to the list stores */
	filters_select_items_parse_entry(filter_items_list);
	filters_select_items_display(filter_items_list, seaudit_app->window->window);
}

static void filter_window_on_close_button_pressed(GtkButton *button, filter_window_t *filter_window)
{
	if (filter_window_verify_filter_values(filter_window) == 0)
		filter_window_hide(filter_window);
}

static gboolean filter_window_on_filter_window_destroy(GtkWidget *widget, GdkEvent *event, filter_window_t *filter_window)
{
	filter_window_hide(filter_window);
	return TRUE;
}

static void filter_window_on_ContextClearButton_clicked(GtkButton *button, filter_window_t *filter_window)
{
	filter_window_clear_context_tab_values(filter_window);
}

static void filter_window_on_OtherClearButton_clicked(GtkButton *button, filter_window_t *filter_window)
{
	filter_window_clear_other_tab_values(filter_window);
}

static void filter_window_on_radio_toggled(GtkToggleButton *tb, gpointer user_data)
{
	filter_window_date_set_sensitive(tb, user_data);
}

static void filter_window_on_month_changed(GtkComboBox *cb, gpointer user_data)
{
	filter_window_t *fw = (filter_window_t *)user_data;
	filter_window_date_update_days(fw->xml);
}

static gboolean filter_window_name_entry_text_changed(GtkWidget *widget, GdkEventKey *event, filter_window_t *filter_window)
{
	const gchar *name;

	name = gtk_entry_get_text(GTK_ENTRY(widget));
	g_string_assign(filter_window->name, name);
	filter_window_set_title(filter_window);
	multifilter_window_set_filter_name_in_list(filter_window->parent, filter_window);
	return FALSE;
}

/***************************************************
 * Public member functions for the filter_window object  *
 ***************************************************/
filter_window_t* filter_window_create(multifilter_window_t *parent, gint parent_index, const char *name)
{
	filter_window_t *filter_window;
	time_t t;

	if (!parent || !name)
		return NULL;

	filter_window = (filter_window_t *)malloc(sizeof(filter_window_t));
	if (filter_window == NULL) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	memset (filter_window, 0, sizeof(filter_window_t));

	filter_window->src_types_items = filters_select_items_create(filter_window, SEAUDIT_SRC_TYPES);
	filter_window->src_users_items = filters_select_items_create(filter_window, SEAUDIT_SRC_USERS);
	filter_window->src_roles_items = filters_select_items_create(filter_window, SEAUDIT_SRC_ROLES);
	filter_window->tgt_types_items = filters_select_items_create(filter_window, SEAUDIT_TGT_TYPES);
	filter_window->tgt_users_items = filters_select_items_create(filter_window, SEAUDIT_TGT_USERS);
	filter_window->tgt_roles_items = filters_select_items_create(filter_window, SEAUDIT_TGT_ROLES);
	filter_window->obj_class_items = filters_select_items_create(filter_window, SEAUDIT_OBJECTS);

	filter_window->ip_address = g_string_new("");
	filter_window->port = g_string_new("");
	filter_window->interface = g_string_new("");
	filter_window->executable = g_string_new("");
	filter_window->comm = g_string_new("");
	filter_window->path = g_string_new("");
	filter_window->match = g_string_new("All");
	filter_window->notes = g_string_new("");
	filter_window->host = g_string_new("");

	filter_window->msg = SEAUDIT_MSG_NONE;

	filter_window->window = NULL;
	filter_window->xml = NULL;
	filter_window->name = g_string_new(name);
	filter_window->parent = parent;
	filter_window->parent_index = parent_index;

	filter_window->dates = (filters_date_item_t *)calloc(1, sizeof(filters_date_item_t));
	t = time(NULL);
	filter_window->dates->start = (struct tm *)calloc(1, sizeof(struct tm));
	filter_window->dates->start = localtime_r(&t, filter_window->dates->start);
	filter_window->dates->end = (struct tm *)calloc(1, sizeof(struct tm));
	filter_window->dates->end = localtime_r(&t, filter_window->dates->end);

	/* set the hour/min/secs up so that we have one full day */
	filter_window->dates->start->tm_hour = 0;
	filter_window->dates->start->tm_min = 0;
	filter_window->dates->start->tm_sec = 0;

	filter_window->dates->end->tm_hour = 23;
	filter_window->dates->end->tm_min = 59;
	filter_window->dates->end->tm_sec = 59;

	return filter_window;
}

void filter_window_destroy(filter_window_t *filter_window)
{
	if (filter_window == NULL)
		return;

	filters_select_items_destroy(filter_window->src_types_items);
	filters_select_items_destroy(filter_window->src_users_items);
	filters_select_items_destroy(filter_window->src_roles_items);

	filters_select_items_destroy(filter_window->tgt_types_items);
	filters_select_items_destroy(filter_window->tgt_users_items);
	filters_select_items_destroy(filter_window->tgt_roles_items);

	filters_select_items_destroy(filter_window->obj_class_items);

	if (filter_window->ip_address)
		g_string_free(filter_window->ip_address, TRUE);
	if (filter_window->port)
		g_string_free(filter_window->port, TRUE);
	if (filter_window->interface)
		g_string_free(filter_window->interface, TRUE);
	if (filter_window->executable)
		g_string_free(filter_window->executable, TRUE);
	if (filter_window->comm)
		g_string_free(filter_window->comm, TRUE);
	if (filter_window->path)
		g_string_free(filter_window->path, TRUE);
	if (filter_window->name)
		g_string_free(filter_window->name, TRUE);
	if (filter_window->match)
		g_string_free(filter_window->match, TRUE);
	if (filter_window->notes)
		g_string_free(filter_window->notes, TRUE);
	if (filter_window->host)
		g_string_free(filter_window->host, TRUE);

	if (filter_window->window != NULL)
		gtk_widget_destroy(GTK_WIDGET(filter_window->window));
	if (filter_window->xml != NULL)
		g_object_unref(G_OBJECT(filter_window->xml));

	free(filter_window->dates);

	free(filter_window);
}


void filter_window_hide(filter_window_t *filter_window)
{
	if (!filter_window->window)
		return;

	show_wait_cursor(GTK_WIDGET(filter_window->window));
	if (filter_window->src_types_items->window) {
		filters_select_items_on_close_button_clicked(NULL, filter_window->src_types_items);
		filter_window->src_types_items->window = NULL;
	}
	if (filter_window->tgt_types_items->window) {
		filters_select_items_on_close_button_clicked(NULL, filter_window->tgt_types_items);
		filter_window->tgt_types_items->window = NULL;
	}
	if (filter_window->src_users_items->window) {
		filters_select_items_on_close_button_clicked(NULL, filter_window->src_users_items);
		filter_window->src_users_items->window = NULL;
	}
	if (filter_window->tgt_users_items->window) {
		filters_select_items_on_close_button_clicked(NULL, filter_window->tgt_users_items);
		filter_window->tgt_users_items->window = NULL;
	}
	if (filter_window->src_roles_items->window) {
		filters_select_items_on_close_button_clicked(NULL, filter_window->src_roles_items);
		filter_window->src_roles_items->window = NULL;
	}
	if (filter_window->tgt_roles_items->window) {
		filters_select_items_on_close_button_clicked(NULL, filter_window->tgt_roles_items);
		filter_window->tgt_roles_items->window = NULL;
	}
	if (filter_window->obj_class_items->window) {
		filters_select_items_on_close_button_clicked(NULL, filter_window->obj_class_items);
		filter_window->obj_class_items->window = NULL;
	}
	filter_window_update_values(filter_window);

	/* if there is an idle function for this window
	 * then we must remove it to avoid that function
	 * being executed after we delete the window.  This
	 * may happen if the window is closed during a search. */
	while(g_idle_remove_by_data(filter_window->window));

	gtk_widget_destroy(GTK_WIDGET(filter_window->window));
	filter_window->window = NULL;
}

void filter_window_display(filter_window_t* filter_window, GtkWindow *parent)
{
	GladeXML *xml;
	GtkWindow *window;
	GtkWidget *widget;
	GString *path;
	char *dir;

	if (!filter_window || !parent)
		return;

	if (filter_window->window) {
		gtk_window_present(filter_window->window);
		return;
	}
	dir = apol_file_find("filter_window.glade");
	if (!dir){
		fprintf(stderr, "could not find filter_window.glade\n");
		return;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/filter_window.glade");
	xml = glade_xml_new(path->str, NULL, NULL);
	g_string_free(path, TRUE);
	g_assert(xml);

	window = GTK_WINDOW(glade_xml_get_widget(xml, "FilterWindow"));
	g_assert(window);
	/* set this window to be transient on the parent window, so that when it pops up it gets centered on it */
	/* however to have it "appear" to be centered we have to hide and then show */
	gtk_window_set_transient_for(window, parent);
	gtk_window_set_position(window, GTK_WIN_POS_CENTER_ON_PARENT);

	filter_window->window = window;
	filter_window->xml = xml;

	g_signal_connect(G_OBJECT(window), "delete_event",
			 G_CALLBACK(filter_window_on_filter_window_destroy), filter_window);

	widget = glade_xml_get_widget(filter_window->xml, "CloseButton");
	g_signal_connect(G_OBJECT(widget), "pressed",
			 G_CALLBACK(filter_window_on_close_button_pressed), filter_window);
	widget = glade_xml_get_widget(filter_window->xml, "NameEntry");
	g_signal_connect(G_OBJECT(widget), "key-release-event",
			 G_CALLBACK(filter_window_name_entry_text_changed), filter_window);

	glade_xml_signal_connect_data(xml, "filters_on_src_type_custom_clicked",
				      G_CALLBACK(filter_window_on_custom_clicked),
				      filter_window->src_types_items);
	glade_xml_signal_connect_data(xml, "filters_on_src_users_custom_clicked",
				      G_CALLBACK(filter_window_on_custom_clicked),
				      filter_window->src_users_items);
	glade_xml_signal_connect_data(xml, "filters_on_src_roles_custom_clicked",
				      G_CALLBACK(filter_window_on_custom_clicked),
				      filter_window->src_roles_items);

	glade_xml_signal_connect_data(xml, "filters_on_tgt_type_custom_clicked",
				      G_CALLBACK(filter_window_on_custom_clicked),
				      filter_window->tgt_types_items);
	glade_xml_signal_connect_data(xml, "filters_on_tgt_users_custom_clicked",
				      G_CALLBACK(filter_window_on_custom_clicked),
				      filter_window->tgt_users_items);
	glade_xml_signal_connect_data(xml, "filters_on_tgt_roles_custom_clicked",
				      G_CALLBACK(filter_window_on_custom_clicked),
				      filter_window->tgt_roles_items);

	glade_xml_signal_connect_data(xml, "filters_on_objs_custom_clicked",
				      G_CALLBACK(filter_window_on_custom_clicked),
				      filter_window->obj_class_items);
	glade_xml_signal_connect_data(xml, "filters_on_ContextClearButton_clicked",
				      G_CALLBACK(filter_window_on_ContextClearButton_clicked),
				      filter_window);
	glade_xml_signal_connect_data(xml, "filters_on_OtherClearButton_clicked",
				      G_CALLBACK(filter_window_on_OtherClearButton_clicked),
				      filter_window);

	/* rename vars, or comment to make clear for dates */
	glade_xml_signal_connect_data(xml, "filters_on_MatchNoneRadio_toggled",
				      G_CALLBACK(filter_window_on_radio_toggled),
				      filter_window);
	glade_xml_signal_connect_data(xml, "filters_on_MatchBeforeRadio_toggled",
				      G_CALLBACK(filter_window_on_radio_toggled),
				      filter_window);
	glade_xml_signal_connect_data(xml, "filters_on_MatchAfterRadio_toggled",
				      G_CALLBACK(filter_window_on_radio_toggled),
				      filter_window);
	glade_xml_signal_connect_data(xml, "filters_on_MatchBetweenRadio_toggled",
				      G_CALLBACK(filter_window_on_radio_toggled),
				      filter_window);

	glade_xml_signal_connect_data(xml, "filters_on_DateEndMonth_changed",
				      G_CALLBACK(filter_window_on_month_changed),
				      filter_window);

	glade_xml_signal_connect_data(xml, "filters_on_DateStartMonth_changed",
				      G_CALLBACK(filter_window_on_month_changed),
				      filter_window);

	widget = glade_xml_get_widget(filter_window->xml, "MsgCombo");
	g_assert(widget);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget), msg_type_strs[SEAUDIT_MSG_NONE]);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget), msg_type_strs[SEAUDIT_MSG_AVC_DENIED]);
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget), msg_type_strs[SEAUDIT_MSG_AVC_GRANTED]);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget), filter_window->msg);

	/* Restore previous values and selections for the filter dialog */
	filter_window_set_values(filter_window);
}

seaudit_filter_t* filter_window_get_filter(filter_window_t *filter_window)
{
	seaudit_filter_t *rt;
	GtkTreeIter iter;
	seaudit_filter_list_t *items_list = NULL;
	GtkWidget *widget;
	GtkTextBuffer *buffer;
	GtkTextIter start, end;
	char *text;
	int int_val;
	struct tm *dt_start, *dt_end;

	rt = seaudit_filter_create();

	/* check for src type filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->src_types_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->src_types_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->src_types_items);
		if (items_list) {
			rt->src_type_criteria = src_type_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}
	/* check for tgt type filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->tgt_types_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->tgt_types_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->tgt_types_items);
		if (items_list) {
			rt->tgt_type_criteria = tgt_type_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}
	/* check for obj class filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->obj_class_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->obj_class_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->obj_class_items);
		if (items_list) {
			rt->class_criteria = class_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for src user filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->src_users_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->src_users_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->src_users_items);
		if (items_list) {
			rt->src_user_criteria = src_user_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for src role filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->src_roles_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->src_roles_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->src_roles_items);
		if (items_list) {
			rt->src_role_criteria = src_role_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for tgt user filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->tgt_users_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->tgt_users_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->tgt_users_items);
		if (items_list) {
			rt->tgt_user_criteria = tgt_user_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for tgt role filter */
	if (filter_window->window)
		filters_select_items_parse_entry(filter_window->tgt_roles_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_window->tgt_roles_items->selected_items), &iter)) {
		items_list = filter_window_seaudit_filter_list_get(filter_window->tgt_roles_items);
		if (items_list) {
			rt->tgt_role_criteria = tgt_role_criteria_create(items_list->list, items_list->size);
			filter_window_seaudit_filter_list_free(items_list);
		}
	}

	/* check for network address filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "IPAddressEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->ip_address->str;
	if (strcmp(text, "") != 0) {
		rt->ipaddr_criteria = ipaddr_criteria_create(text);
	}

	/* check for network port filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "PortEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->port->str;
	if (strcmp(text, "") != 0) {
		int_val = atoi(text);
		rt->ports_criteria = ports_criteria_create(int_val);
	}

	/* check for network interface filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "InterfaceEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->interface->str;
	if (strcmp(text, "") != 0) {
		rt->netif_criteria = netif_criteria_create(text);
	}

	/* check for executable filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "ExeEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->executable->str;
	if (strcmp(text, "") != 0) {
		rt->exe_criteria = exe_criteria_create(text);
	}

	/* check for command filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "CommEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->comm->str;
	if (strcmp(text, "") != 0) {
		rt->comm_criteria = comm_criteria_create(text);
	}

	/* check for path filter */
	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "PathEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->path->str;
	if (strcmp(text, "") != 0) {
		rt->path_criteria = path_criteria_create(text);
	}


	dt_start = (struct tm *)calloc(1, sizeof(struct tm));
	dt_end = (struct tm *)calloc(1, sizeof(struct tm));

	*dt_start = *(filter_window->dates->start);
	*dt_end = *(filter_window->dates->end);
	if (filter_window->window) {
		filters_window_update_tm(filter_window, TRUE, dt_start);
		filters_window_update_tm(filter_window, FALSE, dt_end);
		int_val = filters_window_get_tm_option(filter_window->xml);
	} else {
		int_val = filter_window->dates->option;
	}
	/* check for date time filter */
	if (int_val != SEAUDIT_DT_OPTION_NONE) {
		switch (int_val) {
		case SEAUDIT_DT_OPTION_BEFORE:
			rt->date_time_criteria = date_time_criteria_create(dt_start, dt_end, FILTER_CRITERIA_DT_OPTION_BEFORE);
			break;
		case SEAUDIT_DT_OPTION_AFTER:
			rt->date_time_criteria = date_time_criteria_create(dt_start, dt_end, FILTER_CRITERIA_DT_OPTION_AFTER);
			break;
		default:
			rt->date_time_criteria = date_time_criteria_create(dt_start, dt_end, FILTER_CRITERIA_DT_OPTION_BETWEEN);
			break;
		}
	}
	free(dt_start);
	free(dt_end);

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "MatchEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->match->str;
	if (strcmp("All", text) == 0)
		seaudit_filter_set_match(rt, SEAUDIT_FILTER_MATCH_ALL);
	else
		seaudit_filter_set_match(rt, SEAUDIT_FILTER_MATCH_ANY);

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "NameEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->name->str;
	if (strcmp(text, "") != 0)
		seaudit_filter_set_name(rt, text);

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "HostEntry");
		text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	} else
		text = filter_window->host->str;
	if (strcmp(text, "") != 0)
		rt->host_criteria = host_criteria_create(text);

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "MsgCombo");
		int_val = gtk_combo_box_get_active(GTK_COMBO_BOX(widget));
	} else
		int_val = filter_window->msg;
	switch (int_val)
	{
	case SEAUDIT_MSG_AVC_DENIED:
		rt->msg_criteria = msg_criteria_create(AVC_DENIED);
		break;
	case SEAUDIT_MSG_AVC_GRANTED:
		rt->msg_criteria = msg_criteria_create(AVC_GRANTED);
		break;
	default:
		break;
	}

	if (filter_window->window) {
		widget = glade_xml_get_widget(filter_window->xml, "NotesTextView");
		buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
		gtk_text_buffer_get_start_iter(buffer, &start);
		gtk_text_buffer_get_end_iter(buffer, &end);
		text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
	} else
		text = filter_window->notes->str;
	if (strcmp(text, "") != 0)
		seaudit_filter_set_desc(rt, text);

	return rt;
}

void filter_window_set_values_from_filter(filter_window_t *filter_window, seaudit_filter_t *filter)
{
	apol_vector_t *strs;
	int i;
	char ports_str[16];
	const int ports_str_len = 16;

	if (!filter_window || !filter)
		return;
	if (filter->match == SEAUDIT_FILTER_MATCH_ALL)
		filter_window->match = g_string_assign(filter_window->match, "All");
	else
		filter_window->match = g_string_assign(filter_window->match, "Any");

	if (filter->desc)
		filter_window->notes = g_string_assign(filter_window->notes, filter->desc);
	if (filter->src_type_criteria) {
		strs = src_type_criteria_get_strs(filter->src_type_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->src_types_items, apol_vector_get_element(strs, i));
	}
	if (filter->tgt_type_criteria) {
		strs = tgt_type_criteria_get_strs(filter->tgt_type_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->tgt_types_items, apol_vector_get_element(strs,i));
	}
	if (filter->src_user_criteria) {
		strs = src_user_criteria_get_strs(filter->src_user_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->src_users_items, apol_vector_get_element(strs,i));
	}
	if (filter->tgt_user_criteria) {
		strs = tgt_user_criteria_get_strs(filter->tgt_user_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->tgt_users_items, apol_vector_get_element(strs,i));
	}
	if (filter->src_role_criteria) {
		strs = src_role_criteria_get_strs(filter->src_role_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->src_roles_items, apol_vector_get_element(strs,i));
	}
	if (filter->tgt_role_criteria) {
		strs = tgt_role_criteria_get_strs(filter->tgt_role_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->tgt_roles_items, apol_vector_get_element(strs,i));
	}
	if (filter->class_criteria) {
		strs = class_criteria_get_strs(filter->class_criteria);
		for (i = 0; i < apol_vector_get_size(strs); i++)
			filters_select_items_add_selected_value(filter_window->obj_class_items, apol_vector_get_element(strs,i));
	}
	if (filter->ports_criteria) {
		snprintf(ports_str, ports_str_len, "%d", ports_criteria_get_val(filter->ports_criteria));
		filter_window->port = g_string_assign(filter_window->port, ports_str);
	}
	if (filter->ipaddr_criteria)
		filter_window->ip_address = g_string_assign(filter_window->ip_address, ipaddr_criteria_get_str(filter->ipaddr_criteria));
	if (filter->netif_criteria)
		filter_window->interface = g_string_assign(filter_window->interface, netif_criteria_get_str(filter->netif_criteria));
	if (filter->path_criteria)
		filter_window->path = g_string_assign(filter_window->path, path_criteria_get_str(filter->path_criteria));
	if (filter->exe_criteria)
		filter_window->executable = g_string_assign(filter_window->executable, exe_criteria_get_str(filter->exe_criteria));
	if (filter->comm_criteria)
		filter_window->comm = g_string_assign(filter_window->comm, comm_criteria_get_str(filter->comm_criteria));
	if (filter->host_criteria)
		filter_window->host = g_string_assign(filter_window->host, host_criteria_get_str(filter->host_criteria));
	if (filter->msg_criteria) {
		switch (msg_criteria_get_val(filter->msg_criteria))
		{
		case AVC_GRANTED:
			filter_window->msg = SEAUDIT_MSG_AVC_GRANTED;
			break;
		case AVC_DENIED:
			filter_window->msg = SEAUDIT_MSG_AVC_DENIED;
			break;
		default:
			filter_window->msg = SEAUDIT_MSG_NONE;
			break;
		}
	}
	if (filter->date_time_criteria) {
		if (!filter_window->dates)
			filter_window->dates = (filters_date_item_t *)calloc(1, sizeof(filters_date_item_t));
		*(filter_window->dates->start) = *(date_time_criteria_get_date(filter->date_time_criteria, TRUE));
		*(filter_window->dates->end) = *(date_time_criteria_get_date(filter->date_time_criteria, FALSE));
		i = date_time_criteria_get_option(filter->date_time_criteria);
		switch(i) {
		case FILTER_CRITERIA_DT_OPTION_BEFORE:
			filter_window->dates->option = SEAUDIT_DT_OPTION_BEFORE;
			break;
		case FILTER_CRITERIA_DT_OPTION_AFTER:
			filter_window->dates->option = SEAUDIT_DT_OPTION_AFTER;
			break;

		case FILTER_CRITERIA_DT_OPTION_BETWEEN:
			filter_window->dates->option = SEAUDIT_DT_OPTION_BETWEEN;
			break;
		default:
			filter_window->dates->option = SEAUDIT_DT_OPTION_NONE;
			break;
		}
	}

}

/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Kevin Carr <kcarr@tresys.com>
 * Date: October 23, 2003
 *
 * Modified by Don Patterson <don.patterson@tresys.com>
 * Comment(s): Changed to a more object-oriented design.
 * Date Modified: November 17, 2003
 *
 * Karl MacMillan <kmacmillan@tresys.com>
 *
 */

#include "filter_window.h"
#include "seaudit.h"
#include "utilgui.h"
#include <libseaudit/filters.h>
#include <libseaudit/auditlog.h>
#include <string.h>

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

typedef struct  seaudit_filter_list {
	char **list;
	int size;
} seaudit_filter_list_t;

typedef struct filters_select_items {
	GtkListStore *selected_items;
	GtkListStore *unselected_items;
	enum items_list_types_t items_list_type;
	GtkWindow *window;
	GladeXML *xml;
	filters_t *parent;
} filters_select_items_t;


extern seaudit_t *seaudit_app;

/******************************************************************
 * The following are private methods for the filters_select_items *
 * object. This object is encapsulated by the filters object. 	  *
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
static void filters_select_items_add_item_to_list_model(GtkTreeModel *model, gchar *item)
{
	GtkTreeIter iter;
	gchar *str_data = NULL;
	gint row = 0;
	gboolean valid;
	
	/* As a defensive programming technique, we first make sure the string is */
	/* a valid size before adding it to the list store. If not, then ignore.  */
	if (!is_valid_str_sz((char *)item)) {
		fprintf(stderr, "Item string too large....Ignoring");
		return;
	}
	
	valid = gtk_tree_model_get_iter_first(model, &iter);
	while (valid) {
		gtk_tree_model_get(model, &iter, ITEMS_LIST_COLUMN, &str_data, -1);
		if (strcmp((const char*)item, (const char*)str_data) < 0) 
			break;
		valid = gtk_tree_model_iter_next (model, &iter);
		row++;
	}
	/* now insert it into the specified list model */
	gtk_list_store_insert(GTK_LIST_STORE(model), &iter, row);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter, ITEMS_LIST_COLUMN, item, -1);
}

static void filters_select_items_set_list_stores_default_values(filters_select_items_t* filter_items_list)
{ 
	int i = 0; 
	user_item_t *cur_user;
	
	if (filter_items_list->items_list_type == SEAUDIT_SRC_TYPES
	    || filter_items_list->items_list_type == SEAUDIT_TGT_TYPES) {
		/* types - start iteration of types at index 1 in order to skip 'self' type */
		for (i = 1; i < seaudit_app->cur_policy->num_types; i++) {
			filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(filter_items_list->unselected_items),
									 seaudit_app->cur_policy->types[i].name);
		}
	} else if (filter_items_list->items_list_type == SEAUDIT_SRC_USERS
		   || filter_items_list->items_list_type == SEAUDIT_TGT_USERS) {
		/* users */
		for (cur_user = seaudit_app->cur_policy->users.head;
		     cur_user != NULL; cur_user = cur_user->next) {
			filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(filter_items_list->unselected_items),
									 cur_user->name);
			
		}
	} else if (filter_items_list->items_list_type == SEAUDIT_SRC_ROLES
		   || filter_items_list->items_list_type == SEAUDIT_TGT_ROLES) {
		/* roles */
		for (i = 0; i < seaudit_app->cur_policy->num_roles; i++) {
			filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(filter_items_list->unselected_items),
									 seaudit_app->cur_policy->roles[i].name);

		}
	} else if (filter_items_list->items_list_type == SEAUDIT_OBJECTS ) {
		for (i = 0; i < seaudit_app->cur_policy->num_obj_classes; i++) {
			/* Add to excluded objects list store */
			filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(filter_items_list->unselected_items),
									 seaudit_app->cur_policy->obj_classes[i].name);
		}
	} else {
		fprintf(stderr, "Wrong filter parameter specified.\n");
	}
}

static void filters_select_items_fill_entry(filters_select_items_t *s)

{	GtkTreeIter iter;
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

static bool_t filters_select_items_is_valid_item(filters_select_items_t *s, char *item)
{
	switch (s->items_list_type) {
	case SEAUDIT_SRC_TYPES:
	case SEAUDIT_TGT_TYPES:
		if (get_type_idx(item, seaudit_app->cur_policy) < 0)
			return FALSE;
		else
			return TRUE;
		break;

	case SEAUDIT_SRC_USERS:
	case SEAUDIT_TGT_USERS:
		return does_user_exists(item, seaudit_app->cur_policy);
		break;

	case SEAUDIT_SRC_ROLES:
	case SEAUDIT_TGT_ROLES:
		if (get_role_idx(item, seaudit_app->cur_policy) < 0)
			return FALSE;
		else
			return TRUE;
		break;

	case SEAUDIT_OBJECTS:
		if (get_obj_class_idx(item, seaudit_app->cur_policy) < 0)
			return FALSE;
		else
			return TRUE;
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
		return FALSE;
	};
}

static void filters_select_items_display_invalid_items(filters_select_items_t *s, GList *invalid_items)
{
	GString *msg, *tmp;
	guint i;
	char *item_str;
	const int SEAUDIT_STR_SZ = 128;

	switch (s->items_list_type) {
	case SEAUDIT_SRC_TYPES:
		msg = g_string_new("The following were invalid source types and will be removed:\n\n");
		break;
	case SEAUDIT_TGT_TYPES:
		msg = g_string_new("The following were invalid target types and will be removed:\n\n");
		break;

	case SEAUDIT_SRC_USERS:
		msg = g_string_new("The following were invalid source users and will be removed:\n\n");
		break;
	case SEAUDIT_TGT_USERS:
		msg = g_string_new("The following were invalid target users and will be removed:\n\n");
		break;

	case SEAUDIT_SRC_ROLES:
		msg = g_string_new("The following were invalid source roles and will be removed:\n\n");
		break;
	case SEAUDIT_TGT_ROLES:
		msg = g_string_new("The following were invalid target roles and will be removed:\n\n");
		break;

	case SEAUDIT_OBJECTS:
		msg = g_string_new("The following were invalid object classes and will be removed:\n\n");
		break;
	default:
		fprintf(stderr, "Bad filters_select_items_t object!!\n");
		return;
	};
	
	for (i = 0; i < g_list_length(invalid_items); i++) {
		g_string_append(msg, "\t\"");
		/* We perform a deep copy using the defined valid string size in order 	*/
		/* to put a cap on the size of the error message pop-up dialog. 	*/
		tmp = g_list_nth_data(invalid_items, i);
		if (strlen(tmp->str) > SEAUDIT_STR_SZ) {
			item_str = g_strndup(tmp->str, SEAUDIT_STR_SZ);
			g_string_append(msg, item_str);
			g_string_append(msg, "...");
			g_free(item_str);
		} else {
			g_string_append(msg, tmp->str);
		}
		g_string_append(msg, "\"\n");
	}
	message_display(seaudit_app->filters->window, GTK_MESSAGE_ERROR, msg->str);
	g_string_free(msg, TRUE);
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

static void filters_select_items_move_to_unselected_items_list(filters_select_items_t *filter_items_list)
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
		filters_select_items_add_item_to_list_model(excl_model, item_str);
		g_free(item_str);
				
		/* Free the list of selected tree paths; we have to get the list of selected items again since the list has now changed */
		g_list_foreach(sel_rows, (GFunc) gtk_tree_path_free, NULL);
		g_list_free (sel_rows);
		sel_rows = gtk_tree_selection_get_selected_rows(gtk_tree_view_get_selection(include_tree), &incl_model);
	}
	filters_select_items_fill_entry(filter_items_list);
}

static void g_list_free_1_gstring(void *data, void *user_data)
{
	if (data)
		g_string_free((GString*)data, TRUE);
}

/* filters_select_items events */
static void filters_select_items_on_add_button_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	filters_select_items_move_to_selected_items_list(filter_items_list);
}

static void filters_select_items_on_remove_button_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{
	filters_select_items_move_to_unselected_items_list(filter_items_list);
}

static void filters_select_items_on_close_button_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{	
	if (filter_items_list->window != NULL) {
		gtk_widget_destroy(GTK_WIDGET(filter_items_list->window));
		filter_items_list->window = NULL;
		filters_select_items_fill_entry(filter_items_list);
	}
}

static gboolean filters_select_items_on_window_destroy(GtkWidget *widget, GdkEvent *event, filters_select_items_t *filter_items_list)
{
	if (filter_items_list->window != NULL) {
		gtk_widget_destroy(GTK_WIDGET(filter_items_list->window));
		filter_items_list->window = NULL;
		filters_select_items_fill_entry(filter_items_list);
	}
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
	gboolean valid, found;
	const gchar *entry_text;
	gchar **items, *cur, *item;
	int cur_index;
	GList *invalid_items = NULL;
	GtkEntry *entry;
	GString *tmp = NULL;
	
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
	
			/* see if it is valid */
			if (filters_select_items_is_valid_item(s, cur)) {
				/* See if item exists in unselected list store; if so, remove */
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
						
				/* See if the string already exists in the selected items list store */
				found = FALSE;
				valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(s->selected_items), &iter);
				while (valid) {
					gtk_tree_model_get(GTK_TREE_MODEL(s->selected_items), &iter, ITEMS_LIST_COLUMN, &item, -1);
					if (strcmp(cur, item) == 0) {
						found = TRUE;
						break;
					}
					valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(s->selected_items), &iter);
					g_free(item);
				}			
				/* insertions should be folded into existence checking for efficiency - too much
				 * trouble for now, though */
				if (!found) {
					filters_select_items_add_item_to_list_model(GTK_TREE_MODEL(s->selected_items), cur);
				}
			} else {
				tmp = g_string_new(cur);				
				invalid_items = g_list_append(invalid_items, tmp);
			}
			cur_index++;
			cur = items[cur_index];
		}
		g_strfreev(items);
		if (invalid_items != NULL) {
			filters_select_items_display_invalid_items(s, invalid_items);
			g_list_foreach(invalid_items, g_list_free_1_gstring, NULL);
			g_list_free(invalid_items);
			/* Since there were invalid items found we must re-fill the entry box. */
			filters_select_items_fill_entry(s);
		}
	}
}

static filters_select_items_t* filters_select_items_create(filters_t *parent, enum items_list_types_t items_type)
{
	filters_select_items_t *item = NULL;
	
	/* Create and initialize the object */
	item = (filters_select_items_t *)malloc(sizeof(filters_select_items_t));
	if (item == NULL) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	memset (item, 0, sizeof(filters_select_items_t));
	item->selected_items = gtk_list_store_new(NUMBER_ITEMS_LIST_COLUMNS, G_TYPE_STRING);;
	item->unselected_items = gtk_list_store_new(NUMBER_ITEMS_LIST_COLUMNS, G_TYPE_STRING);;
	item->items_list_type = items_type;
	item->parent = parent;
	
	return item;
}

static void filters_select_items_display(filters_select_items_t *filter_items_list)
{
	GladeXML *xml;
	GtkTreeView *include_tree, *exclude_tree;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *excl_column, *incl_column;
	GtkWindow *window;
	GString *path;
	GtkTreeIter iter;
	char *dir;
	GtkLabel *lbl;
	GtkLabel *incl_lbl;
	GtkLabel *excl_lbl;

	/* Load the glade interface specifications */
	dir = find_file("customize_filter_window.glade");
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
	gtk_window_set_transient_for(window, filter_items_list->parent->window);
	gtk_window_set_destroy_with_parent(window, FALSE);
	                                             
	if (!seaudit_app->cur_policy) {
		g_assert(window);
		message_display(window, GTK_MESSAGE_ERROR, "You must load a policy first.\n");
		return;
	}

	/* Connect all signals to callback functions */
	g_signal_connect(G_OBJECT(window), "delete_event", 
			 G_CALLBACK(filters_select_items_on_window_destroy), 
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
	
	/* List stores are already created */	
	/* Set default values if they have not been set already */
	if(gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_items_list->selected_items), &iter) == FALSE 
		&& gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filter_items_list->unselected_items), &iter) == FALSE)	
		filters_select_items_set_list_stores_default_values(filter_items_list);
	
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
}

/********************************************************
 * Private methods and callbacks for the filters object *
 ********************************************************/ 
static void filters_set_values(filters_t *filters)
{
	GtkWidget *widget;
	
	filters_select_items_fill_entry(filters->src_types_items);
	filters_select_items_fill_entry(filters->src_users_items);
	filters_select_items_fill_entry(filters->src_roles_items);
	filters_select_items_fill_entry(filters->tgt_types_items);
	filters_select_items_fill_entry(filters->tgt_users_items);
	filters_select_items_fill_entry(filters->tgt_roles_items);
	filters_select_items_fill_entry(filters->obj_class_items);
	
	/* set network address */
	widget = glade_xml_get_widget(filters->xml, "IPAddressEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filters->ip_address->str);

	/* set network port */
	widget = glade_xml_get_widget(filters->xml, "PortEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filters->port->str);
	
	/* set network interface */
	widget = glade_xml_get_widget(filters->xml, "InterfaceEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filters->interface->str);
	
	/* set executable */
	widget = glade_xml_get_widget(filters->xml, "ExeEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filters->executable->str);
	
	/* set path */
	widget = glade_xml_get_widget(filters->xml, "PathEntry");
	gtk_entry_set_text(GTK_ENTRY(widget), filters->path->str);
	
}

static void filters_update_values(filters_t *filters)
{
	GtkWidget *widget;
	
	/* First parse all selection enabled entry boxes, because the user may have typed in the value */
	filters_select_items_parse_entry(filters->src_types_items);
	filters_select_items_parse_entry(filters->src_users_items);
	filters_select_items_parse_entry(filters->src_roles_items);
	filters_select_items_parse_entry(filters->tgt_types_items);
	filters_select_items_parse_entry(filters->tgt_users_items);
	filters_select_items_parse_entry(filters->tgt_roles_items);
	filters_select_items_parse_entry(filters->obj_class_items);
	
	/* update network address value */
	widget = glade_xml_get_widget(filters->xml, "IPAddressEntry");
	filters->ip_address = g_string_assign(filters->ip_address, gtk_entry_get_text(GTK_ENTRY(widget)));

	/* update network port value */
	widget = glade_xml_get_widget(filters->xml, "PortEntry");
	filters->port = g_string_assign(filters->port, gtk_entry_get_text(GTK_ENTRY(widget)));
	
	/* update network interface value */
	widget = glade_xml_get_widget(filters->xml, "InterfaceEntry");
	filters->interface = g_string_assign(filters->interface, gtk_entry_get_text(GTK_ENTRY(widget)));

	/* update executable value */
	widget = glade_xml_get_widget(filters->xml, "ExeEntry");
	filters->executable = g_string_assign(filters->executable, gtk_entry_get_text(GTK_ENTRY(widget)));
	
	/* update path value */
	widget = glade_xml_get_widget(filters->xml, "PathEntry");
	filters->path = g_string_assign(filters->path, gtk_entry_get_text(GTK_ENTRY(widget)));
}

static void filters_seaudit_filter_list_free(seaudit_filter_list_t *list)
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
static seaudit_filter_list_t* filters_seaudit_filter_list_set(filters_select_items_t *filters_select_item)
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
				filters_seaudit_filter_list_free(flist);
				fprintf(stderr, "out of memory\n");
				return NULL;
			}
		}
		/* We subtract 1 from the count to get the correct index because count is incremented above */
		flist->list[count - 1] = (char *)malloc(strlen((const char*)str_data) + 1);
		if(flist->list[count - 1] == NULL) {
			filters_seaudit_filter_list_free(flist);
			fprintf(stderr, "out of memory\n");
			return NULL;
		}
		strcpy(flist->list[count - 1], (const char*)str_data);
		valid = gtk_tree_model_iter_next (incl_model, &iter);
	}
	flist->size = count;
	
	return flist;
}

static void filters_clear_other_tab_values(filters_t *filters)
{
	GtkWidget *widget;
	
	widget = glade_xml_get_widget(filters->xml, "IPAddressEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");

	/* clear network port */
	widget = glade_xml_get_widget(filters->xml, "PortEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");
	
	/* clear network interface */
	widget = glade_xml_get_widget(filters->xml, "InterfaceEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");
	
	/* clear executable */
	widget = glade_xml_get_widget(filters->xml, "ExeEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");
	
	/* clear path */
	widget = glade_xml_get_widget(filters->xml, "PathEntry");
	g_assert(widget);
	gtk_entry_set_text(GTK_ENTRY(widget), "");
}

static void filters_clear_context_tab_values(filters_t *filters)
{
	GtkEntry *entry;
	
	entry = filters_select_items_get_entry(filters->src_types_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");
	
	entry = filters_select_items_get_entry(filters->src_users_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");
	
	entry = filters_select_items_get_entry(filters->src_roles_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");
	
	entry = filters_select_items_get_entry(filters->tgt_types_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");
	
	entry = filters_select_items_get_entry(filters->tgt_users_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");
	
	entry = filters_select_items_get_entry(filters->tgt_roles_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");
	
	entry = filters_select_items_get_entry(filters->obj_class_items);
	g_assert(entry);
	gtk_entry_set_text(entry, "");
}

/* filters events */
static void filters_on_opened_new_policy(void *user_data)
{
	filters_t *filters = (filters_t *)user_data;

	/* Here, we only need to update the 'Context' tab values, because a new
	 * policy has been loaded. The 'Other' tab values can stay around as they
	 * are policy independant */
	filters_select_items_parse_entry(filters->src_types_items);
	filters_select_items_parse_entry(filters->src_users_items);
	filters_select_items_parse_entry(filters->src_roles_items);
	filters_select_items_parse_entry(filters->tgt_types_items);
	filters_select_items_parse_entry(filters->tgt_users_items);
	filters_select_items_parse_entry(filters->tgt_roles_items);
	filters_select_items_parse_entry(filters->obj_class_items);
}

static void filters_on_custom_clicked(GtkButton *button, filters_select_items_t *filter_items_list)
{	
	if (filter_items_list->window != NULL) {
		/* add anything from the entry to the list stores */
		filters_select_items_parse_entry(filter_items_list);
		gtk_window_present(filter_items_list->window);
		return;
	}
	/* add anything from the entry to the list stores */
	filters_select_items_parse_entry(filter_items_list);
	filters_select_items_display(filter_items_list);
}

static gboolean filters_on_filter_window_destroy(GtkWidget *widget, GdkEvent *event, filters_t *filters)
{
	if (filters->window != NULL) {
		if (filters->src_types_items->window) {
			gtk_widget_destroy(GTK_WIDGET(filters->src_types_items->window));
			filters->src_types_items->window = NULL;
		}
		if (filters->tgt_types_items->window) {
			gtk_widget_destroy(GTK_WIDGET(filters->tgt_types_items->window));
			filters->tgt_types_items->window = NULL;
		}
		if (filters->src_users_items->window) {
			gtk_widget_destroy(GTK_WIDGET(filters->src_users_items->window));
			filters->src_users_items->window = NULL;
		}
		if (filters->tgt_users_items->window) {
			gtk_widget_destroy(GTK_WIDGET(filters->tgt_users_items->window));
			filters->tgt_users_items->window = NULL;
		}
		if (filters->src_roles_items->window) {
			gtk_widget_destroy(GTK_WIDGET(filters->src_roles_items->window));
			filters->src_roles_items->window = NULL;
		}
		if (filters->tgt_roles_items->window) {
			gtk_widget_destroy(GTK_WIDGET(filters->tgt_roles_items->window));
			filters->tgt_roles_items->window = NULL;
		}
		if (filters->obj_class_items->window) {
			gtk_widget_destroy(GTK_WIDGET(filters->obj_class_items->window));
			filters->obj_class_items->window = NULL;
		}
		filters_update_values(filters);
		policy_load_callback_remove(&filters_on_opened_new_policy, filters);
		gtk_widget_destroy(GTK_WIDGET(filters->window));
		filters->window = NULL;
	}
	return FALSE;
}

static void filters_on_do_filter_button_clicked(GtkButton *button, filters_t *filters)
{
	GtkWidget *widget;
	GtkWidget *window;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GladeXML *xml;
	SEAuditLogStore *store;
	seaudit_filter_list_t *items_list = NULL;
	filter_t *filter;
	char *text;
	int int_val;
	
	window = GTK_WIDGET(filters->window);
	show_wait_cursor(window);	
	g_assert(window);
	
	xml = filters->xml;
	widget = glade_xml_get_widget(seaudit_app->top_window_xml, "LogListView");
 	model = gtk_tree_view_get_model(GTK_TREE_VIEW(widget));
	store = (SEAuditLogStore*)model;
	audit_log_purge_filters(store->log);

	/* Result message value */
	widget = glade_xml_get_widget(xml, "ResultComboEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "SHOW messages that match ALL criteria") == 0) {
		seaudit_app->log_store->log->fltr_out = FALSE;
		seaudit_app->log_store->log->fltr_and = TRUE;
	} else if (strcmp(text, "SHOW messages that match ANY criteria") == 0) {
		seaudit_app->log_store->log->fltr_out = FALSE;
		seaudit_app->log_store->log->fltr_and = FALSE;
	} else if (strcmp(text, "HIDE messages that match ALL criteria") == 0) {
		seaudit_app->log_store->log->fltr_out = TRUE;
		seaudit_app->log_store->log->fltr_and = TRUE;
	} else if (strcmp(text, "HIDE messages that match ANY criteria") == 0) {
		seaudit_app->log_store->log->fltr_out = TRUE;
		seaudit_app->log_store->log->fltr_and = FALSE;
	} else {
		message_display(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Invalid results message combobox value.\n");
		return;		
	}
	
	/* check for src type filter */
	filters_select_items_parse_entry(filters->src_types_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filters->src_types_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_set(filters->src_types_items);
		if (items_list == NULL) 
			return;
		filter = src_type_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_add_filter(store->log, filter);	
	}

	/* check for tgt type filter */
	filters_select_items_parse_entry(filters->tgt_types_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filters->tgt_types_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_set(filters->tgt_types_items);
		if (items_list == NULL) 
			return;
		filter = tgt_type_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_add_filter(store->log, filter);
	}
	/* check for obj class filter */
	filters_select_items_parse_entry(filters->obj_class_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filters->obj_class_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_set(filters->obj_class_items);
		if (items_list == NULL) 
			return;
		filter = class_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_add_filter(store->log, filter);
	}

	/* check for src user filter */
	filters_select_items_parse_entry(filters->src_users_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filters->src_users_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_set(filters->src_users_items);
		if (items_list == NULL) 
			return;
		filter = src_user_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_add_filter(store->log, filter);
	}

	/* check for src role filter */
	filters_select_items_parse_entry(filters->src_roles_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filters->src_roles_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_set(filters->src_roles_items);
		if (items_list == NULL) 
			return;
		filter = src_role_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_add_filter(store->log, filter);
	}

	/* check for tgt user filter */
	filters_select_items_parse_entry(filters->tgt_users_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filters->tgt_users_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_set(filters->tgt_users_items);
		if (items_list == NULL) 
			return;
		filter = tgt_user_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_add_filter(store->log, filter);
	}

	/* check for tgt role filter */
	filters_select_items_parse_entry(filters->tgt_roles_items);
	if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(filters->tgt_roles_items->selected_items), &iter)) {
		items_list = filters_seaudit_filter_list_set(filters->tgt_roles_items);
		if (items_list == NULL) 
			return;
		filter = tgt_role_filter_create(items_list->list, items_list->size);
		filters_seaudit_filter_list_free(items_list);
		audit_log_add_filter(store->log, filter);
	}
	
	/* check for network address filter */
	widget = glade_xml_get_widget(xml, "IPAddressEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		filter = ipaddr_filter_create(text);
		audit_log_add_filter(store->log, filter);
	}

	/* check for network port filter */
	widget = glade_xml_get_widget(xml, "PortEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		int_val = atoi(text);
		filter = ports_filter_create(int_val);
		audit_log_add_filter(store->log, filter);
	}
	
	/* check for network interface filter */
	widget = glade_xml_get_widget(xml, "InterfaceEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		filter = netif_filter_create(text);
		audit_log_add_filter(store->log, filter);
	}
	
	/* check for executable filter */
	widget = glade_xml_get_widget(xml, "ExeEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		filter = exe_filter_create(text);
		audit_log_add_filter(store->log, filter);
	}
	
	/* check for path filter */
	widget = glade_xml_get_widget(xml, "PathEntry");
	text = (char*)gtk_entry_get_text(GTK_ENTRY(widget));
	if (strcmp(text, "") != 0) {
		filter = path_filter_create(text);
		audit_log_add_filter(store->log, filter);
	}
	
	show_wait_cursor(window);

	/* do the filter on the model */
 	seaudit_log_store_do_filter(store);
 	log_filtered_signal_emit();
	clear_wait_cursor(window);
}

static void filters_on_ContextClearButton_clicked(GtkButton *button, filters_t *filters)
{
	filters_clear_context_tab_values(filters);
}

static void filters_on_OtherClearButton_clicked(GtkButton *button, filters_t *filters)
{
	filters_clear_other_tab_values(filters);
}

/***************************************************
 * Public member functions for the filters object  *
 ***************************************************/
filters_t* filters_create(void)
{
	filters_t *filters;
	
	filters = (filters_t *)malloc(sizeof(filters_t));
	if (filters == NULL) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	memset (filters, 0, sizeof(filters_t));

	filters->src_types_items = filters_select_items_create(filters, SEAUDIT_SRC_TYPES);
	filters->src_users_items = filters_select_items_create(filters, SEAUDIT_SRC_USERS);
	filters->src_roles_items = filters_select_items_create(filters, SEAUDIT_SRC_ROLES);
	filters->tgt_types_items = filters_select_items_create(filters, SEAUDIT_TGT_TYPES);
	filters->tgt_users_items = filters_select_items_create(filters, SEAUDIT_TGT_USERS);
	filters->tgt_roles_items = filters_select_items_create(filters, SEAUDIT_TGT_ROLES);
	filters->obj_class_items = filters_select_items_create(filters, SEAUDIT_OBJECTS);
	
	filters->ip_address = g_string_new("");
	filters->port = g_string_new("");
	filters->interface = g_string_new("");
	filters->executable = g_string_new("");
	filters->path = g_string_new("");
	
	filters->window = NULL;
	filters->xml = NULL;

	return filters;
}

void filters_destroy(filters_t *filters)
{
	if (filters == NULL)
		return;
	
	filters_select_items_destroy(filters->src_types_items);
	filters_select_items_destroy(filters->src_users_items);
	filters_select_items_destroy(filters->src_roles_items);

	filters_select_items_destroy(filters->tgt_types_items);
	filters_select_items_destroy(filters->tgt_users_items);
	filters_select_items_destroy(filters->tgt_roles_items);

	filters_select_items_destroy(filters->obj_class_items);
	
	if (filters->ip_address)
		g_string_free(filters->ip_address, TRUE);
	if (filters->port)
		g_string_free(filters->port, TRUE);
	if (filters->interface)
		g_string_free(filters->interface, TRUE);
	if (filters->executable)
		g_string_free(filters->executable, TRUE);
	if (filters->path)
		g_string_free(filters->path, TRUE);
		
	if (filters->window != NULL)
		gtk_widget_destroy(GTK_WIDGET(filters->window));
	if (filters->xml != NULL)
		g_object_unref(G_OBJECT(filters->xml));
	free(filters);
	filters = NULL;
}

void filters_display(filters_t* filters)
{
	GladeXML *xml;
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkWindow *window;
	SEAuditLogStore *store;
	GString *path;
	char *dir;

	dir = find_file("filter_window.glade");
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
		
	filters->window = window;
	filters->xml = xml;

	g_signal_connect(G_OBJECT(window), "delete_event", 
			 G_CALLBACK(filters_on_filter_window_destroy), 
			 filters);
	glade_xml_signal_connect_data(xml, "filters_on_src_type_custom_clicked",
				      G_CALLBACK(filters_on_custom_clicked),
				      filters->src_types_items);
	glade_xml_signal_connect_data(xml, "filters_on_src_users_custom_clicked",
				      G_CALLBACK(filters_on_custom_clicked),
				      filters->src_users_items);
	glade_xml_signal_connect_data(xml, "filters_on_src_roles_custom_clicked",
				      G_CALLBACK(filters_on_custom_clicked),
				      filters->src_roles_items);

	glade_xml_signal_connect_data(xml, "filters_on_tgt_type_custom_clicked",
				      G_CALLBACK(filters_on_custom_clicked),
				      filters->tgt_types_items);
	glade_xml_signal_connect_data(xml, "filters_on_tgt_users_custom_clicked",
				      G_CALLBACK(filters_on_custom_clicked),
				      filters->tgt_users_items);
	glade_xml_signal_connect_data(xml, "filters_on_tgt_roles_custom_clicked",
				      G_CALLBACK(filters_on_custom_clicked),
				      filters->tgt_roles_items);

	glade_xml_signal_connect_data(xml, "filters_on_objs_custom_clicked",
				      G_CALLBACK(filters_on_custom_clicked),
				      filters->obj_class_items);
	glade_xml_signal_connect_data(xml, "filters_on_do_filter_button_clicked",
				      G_CALLBACK(filters_on_do_filter_button_clicked),
				      filters);
	
	glade_xml_signal_connect_data(xml, "filters_on_ContextClearButton_clicked",
				      G_CALLBACK(filters_on_ContextClearButton_clicked),
				      filters);
	glade_xml_signal_connect_data(xml, "filters_on_OtherClearButton_clicked",
				      G_CALLBACK(filters_on_OtherClearButton_clicked),
				      filters);
				      			      
	policy_load_callback_register(&filters_on_opened_new_policy, filters);

	widget = glade_xml_get_widget(seaudit_app->top_window_xml, "LogListView");
 	model = gtk_tree_view_get_model(GTK_TREE_VIEW(widget));
	store = (SEAuditLogStore*)model;
	store->log->fltr_out = TRUE;
	store->log->fltr_and = TRUE;
	
	/* Restore previous values and selections for the filter dialog */
	filters_set_values(filters);
	
}

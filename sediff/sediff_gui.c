/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 28, 2004
 */

#include "sediff_gui.h"
#include "sediff_treemodel.h"
#include "utilgui.h"

/* libapol */
#include <policy.h>
#include <policy-io.h>
#include <poldiff.h>
#include <render.h>
#include <binpol/binpol.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <time.h>

/* The following should be defined in the make environment */
#ifndef SEDIFF_GUI_VERSION_NUM
	#define SEDIFF_GUI_VERSION_NUM "UNKNOWN"
#endif

#define GLADEFILE 	"sediff.glade"
#define MAIN_WINDOW_ID 	"sediff_main_window"
#define OPEN_DIALOG_ID 	"sediff_dialog"

sediff_app_t *sediff_app = NULL;

gboolean toggle = TRUE;
gint curr_option = OPT_CLASSES; 


/* Generic function prototype for getting policy components */
typedef int(*get_iad_name_fn_t)(int idx, char **name, policy_t *policy);
typedef void(*sediff_callback_t)(void *user_data);

typedef struct registered_callback {
	GSourceFunc function; 	/* gboolean (*GSourceFunc)(gpointer data); */
	void *user_data;
	unsigned int type;

/* callback types */
#define LISTBOX_SELECTED_CALLBACK   0
#define LISTBOX_SELECTED_SIGNAL     LISTBOX_SELECTED_CALLBACK
} registered_callback_t;

#define row_selected_signal_emit() sediff_callback_signal_emit(LISTBOX_SELECTED_SIGNAL)

static void sediff_callback_signal_emit(unsigned int type);
static void txt_view_populate_buffers(apol_diff_t *stuff_removed,
				     apol_diff_t *stuff_added,
				     policy_t *policy_old,
				     policy_t *policy_new);

static void txt_view_switch_buffer(GtkTextView *textview,gint option,gint policy_option);

static void sediff_callback_signal_emit_1(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *)data;
	unsigned int type = *(unsigned int*)user_data;
	if (callback->type == type) {
		gpointer data = &callback->user_data;
		g_idle_add_full(G_PRIORITY_HIGH_IDLE+10, callback->function, &data, NULL);
	}
	return;
}

/* the signal emit function executes each function registered with 
 * sediff_callback_register() */
void sediff_callback_signal_emit(unsigned int type)
{

	g_list_foreach(sediff_app->callbacks, &sediff_callback_signal_emit_1, &type);
	return;
}

static int get_iad_string(GString *string, int id, int_a_diff_t *iad_removed, int_a_diff_t *iad_added, 
			  policy_t *p_old, policy_t *p_new)
{
	get_iad_name_fn_t get_name, get_a_name;
	char *name, *tmp, *descrp = NULL, *adescrp = NULL;
	int rt, i, num_new, num_old, idx;
	int_a_diff_t *t;
	bool_t missing;
		
	assert(string != NULL && p_old != NULL && p_new != NULL);
	assert((id & (IDX_TYPE|IDX_ATTRIB|IDX_ROLE|IDX_USER|IDX_OBJ_CLASS|IDX_COMMON_PERM|IDX_PERM)) != 0);
	
	switch(id) {
	case IDX_ROLE|IDX_PERM:
		get_name = &get_role_name;
		get_a_name = &get_role_name;
		descrp = "Roles";
		adescrp = "Roles";
		num_new = p_new->num_roles;
		num_old = p_old->num_roles;
		break;
	case IDX_TYPE:
		get_name = &get_type_name;
		get_a_name = &get_attrib_name;
		descrp = "Types";
		adescrp = "Attributes";
		num_new = p_new->num_types;
		num_old = p_old->num_types;
		break;
	case IDX_ATTRIB:
		get_name = &get_attrib_name;
		get_a_name = &get_type_name;
		descrp = "Attributes";
		adescrp = "Types";
		num_new = p_new->num_attribs;
		num_old = p_old->num_attribs;
		break;
	case IDX_ROLE:
		get_name = &get_role_name;
		get_a_name = &get_type_name;
		descrp = "Roles";
		adescrp = "Types";
		num_new = p_new->num_roles;
		num_old = p_old->num_roles;
		break;
	case IDX_USER:
		get_name = &get_user_name2;
		get_a_name = &get_role_name;
		descrp = "Users";
		adescrp = "Roles";
		num_new = p_new->num_users;
		num_old = p_old->num_users;
		break;
	case IDX_OBJ_CLASS:
		get_name = &get_obj_class_name;
		get_a_name = &get_perm_name;
		descrp = "Classes";
		adescrp = "Permissions";
		num_new = p_new->num_obj_classes;
		num_old = p_old->num_obj_classes;
		break;
	case IDX_COMMON_PERM:
		get_name = &get_common_perm_name;
		get_a_name = &get_perm_name;
		descrp = "Common Permissions";
		adescrp = "Permissions";
		num_new = p_new->num_common_perms;
		num_old = p_old->num_common_perms;
		break;
	default:
		g_return_val_if_reached(-1);
		break;
	}

	for (idx = 0; idx < num_new; idx++) {
		rt = (*get_name)(idx, &name, p_new);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for %s %d\n", descrp, idx);
			return -1;
		}

		/* Looking for items that are not in the old policy, hence indicating it was ADDED */
		if (iad_added != NULL) {
			for (t = iad_added; t != NULL; t = t->next) {
				rt = (*get_name)(t->idx, &tmp, p_new);
				if (rt < 0) {
					fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
					return -1;
				}
				if (strcmp(name, tmp) != 0) {
					free(tmp);
					continue;
				}
				free(tmp);
				
				missing = (t->a == NULL);
				/* This means that the item exists in the old policy */
				if (!missing) {
					g_string_append_printf(string, "\n%s (changed, %d added %s)\n", name, t->numa, adescrp);
					for (i = 0; i < t->numa; i++) {
						rt = (*get_a_name)(t->a[i], &tmp, p_new);
						if (rt < 0) {
							fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, t->a[i]);
							return -1;
						}
						g_string_append_printf(string, "+        %s\n", tmp);
						free(tmp);
					}
				} else {
					g_string_append_printf(string, "\n+%s\n", name);
					/* TODO: List its' members (+) */
				}			 
			}
		}
		free(name);
	}

	for (idx = 0; idx < num_old; idx++) {
		rt = (*get_name)(idx, &name, p_old);
		if (rt < 0) {
			fprintf(stderr, "Problem getting name for %s %d\n", descrp, idx);
			return -1;
		}
		/* Looking for items that are not in new policy */
		if (iad_removed != NULL) {
			for (t = iad_removed; t != NULL; t = t->next) {
				rt = (*get_name)(t->idx, &tmp, p_old);
				if (rt < 0) {
					fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
					return -1;
				}
				if (strcmp(name, tmp) != 0) {
					free(tmp);
					continue;
				}
				free(tmp);
				
				missing = (t->a == NULL);
				/* This means that the item exists in the new policy, so we indicate whether it has been changed. */
				if (!missing) {
					g_string_append_printf(string, "\n%s (changed, %d missing %s)\n", name, t->numa, adescrp);
					for (i = 0; i < t->numa; i++) {
						rt = (*get_a_name)(t->a[i], &tmp, p_old);
						if (rt < 0) {
							fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, t->a[i]);
							return -1;
						}
						g_string_append_printf(string, "-        %s\n", tmp);
						free(tmp);
					}
				} else {
					g_string_append_printf(string, "\n-%s\n", name);
					/* TODO: List its' members (-) */
				}				 
			}
		}
		free(name);
	}
			 	
	return 0;
}

/* returns true if policy is binary */
static bool_t fn_is_binpol(const char *fn)
{
	FILE *fp;
	bool_t rt;
	
	g_assert(fn != NULL);
	fp = fopen(fn, "r");
	if (fp == NULL)
		return FALSE;
	if (ap_is_file_binpol(fp)) 
		rt = TRUE;
	else
		rt = FALSE;
	fclose(fp);
	return rt;
}

/* returns a binary policy version */
static int fn_binpol_ver(const char *fn)
{
	FILE *fp;
	int rt;
	
	g_assert(fn != NULL);
	fp = fopen(fn, "r");
	if (fp == NULL) 
		return -1;
	
	if (!ap_is_file_binpol(fp)) 
		rt = -1;
	else 
		rt = ap_binpol_version(fp);
	fclose(fp);
	return rt;
}

/* 
   returns the result of diffing p1_file and p2_file 2 policy files 
   also sets up the buffers used in gui so we can switch faster
*/
static apol_diff_result_t *diff_policies(const char *p1_file, const char *p2_file)
{
	policy_t *p1 = NULL, *p2 = NULL;
	apol_diff_result_t *diff = NULL;
	unsigned int opts = POLOPT_ALL;
	int rt;
	GdkCursor *cursor = NULL;

	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();



	/* attempt to open the policies */
	if (fn_is_binpol(p1_file) && fn_binpol_ver(p1_file) < 15) {
		g_warning("Policy 1:  Binary policies are only supported for version 15 or higher.\n");
		goto err;
	}
	if (fn_is_binpol(p2_file) && fn_binpol_ver(p2_file) < 15 ) {
		g_warning("Policy 2:  Binary policies are only supported for version 15 or higer.\n");
		goto err;
	}	
	rt = open_partial_policy(p1_file, opts, &p1);
	if (rt != 0) {
		g_warning("Problem opening first policy file: %s\n", p1_file);
		goto err;
	}
	if (get_policy_version_id(p1) < POL_VER_12) {
		g_warning("Policy 1:  Unsupport version: Supported versions are Source (12 and higher), Binary (15 and higher).\n");
		goto err;
	}
	rt = open_partial_policy(p2_file, opts, &p2);
	if (rt != 0) {
		g_warning("Problem opening second policy file: %s\n", p2_file);
		goto err;
	}
	if (get_policy_version_id(p1) < POL_VER_12 ) {
		g_warning("Policy 1:  Unsupport version: Supported versions are Source (12 and higher), Binary (15 and higher).\n");
		goto err;
	}

	/* diff and display requested info */
	diff = apol_diff_policies(opts, p1, p2);

	/* load up the buffers */
	txt_view_populate_buffers(diff->diff1,diff->diff2,diff->p1,diff->p2);

	if (diff == NULL) {
		g_warning("Error differentiating policies\n");
		goto err;
	}
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();


	return diff;
err:
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();

	if (p1)
		close_policy(p1);
	if (p2)
		close_policy(p2);
	return NULL;
}


static int get_boolean_diff(GString *string, bool_diff_t *bools_removed, bool_diff_t *bools_added,
			    policy_t *policy_old, policy_t *policy_new)
{
	bool_diff_t *t;
	int rt;
	char *name;
	bool_t state;
	
	if (policy_old == NULL || policy_new == NULL)
		return -1;
		
	if (bools_removed != NULL) {
		for (t = bools_removed; t != NULL; t = t->next) {
			rt = get_cond_bool_name(t->idx, &name, policy_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
				return -1;
			}
			if (t->state_diff) {
				g_string_append_printf(string, "   %s (%s", name, (t->state_diff ? "changed" : "missing"));
				rt = get_cond_bool_default_val_idx(t->idx, &state, policy_old);
				if (rt < 0) {
					fprintf(stderr, "Problem getting boolean state for %s\n", name);
					free(name);
					return -1;
				}
				g_string_append_printf(string, " from %s to %s)\n", (state ? "TRUE" : "FALSE"), (state ? "FALSE" : "TRUE") );
			}
			else
				g_string_append_printf(string, "   -%s\n", name);
			free(name);
		}
	}
	if (bools_added != NULL) {
		for (t = bools_added; t != NULL; t = t->next) {
			rt = get_cond_bool_name(t->idx, &name, policy_new);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
				return -1;
			}
			if (!t->state_diff) {
				g_string_append_printf(string, "   +%s\n", name);
			}
			free(name);
		}
	}
	
	return 0;
}

/* raise the correct policy tab on the gui, and go to the line clicked by the user */
static void txt_view_raise_policy_tab_goto_line(unsigned long line, GtkTextView *text_view_in)
{
	GtkNotebook *notebook;
	GtkTextBuffer *buffer;
	GtkTextIter iter;
	GtkTextView *text_view = NULL;

	g_assert(text_view_in);
	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));
	g_assert(notebook);

	if (strcmp(gtk_widget_get_name((GtkWidget *)text_view_in), "sediff_p1_results_txt_view") == 0) {
		gtk_notebook_set_current_page(notebook, 1);
		text_view = (GtkTextView *)(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text"));
	}
	else { 
		gtk_notebook_set_current_page(notebook, 2);
		text_view = (GtkTextView *)(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text"));
	}

	buffer = gtk_text_view_get_buffer(text_view);
	g_assert(buffer);

	gtk_text_buffer_get_start_iter(buffer, &iter);
	gtk_text_iter_set_line(&iter, line);
	gtk_text_view_scroll_to_iter(text_view, &iter, 0.0, TRUE, 0.0, 0.5);

	gtk_text_iter_backward_line(&iter);
	gtk_text_buffer_place_cursor(buffer, &iter);

	gtk_text_view_set_cursor_visible(text_view, TRUE);
	return;
}

/* 
   returns true if when user clicks line number we are able to get it, and 
   raise the correct tab 
*/
static gboolean txt_view_on_policy_link_event(GtkTextTag *tag, GObject *event_object, 
					      GdkEvent *event, const GtkTextIter *iter, 
					      gpointer user_data)
{
	int offset;
	unsigned long line;
	GtkTextBuffer *buffer;
	GtkTextIter *start, *end;

	if (event->type == GDK_BUTTON_PRESS) {
		buffer = gtk_text_iter_get_buffer(iter);
		start = gtk_text_iter_copy(iter);
		offset = gtk_text_iter_get_line_offset(start);
		if (offset == 0)
			gtk_text_iter_forward_char(start);
		else {
			while ( offset > 1) {
				gtk_text_iter_backward_char(start);
				offset = gtk_text_iter_get_line_offset(start);
			}
		}
		end = gtk_text_iter_copy(start);
		while (!gtk_text_iter_ends_word(end))
			gtk_text_iter_forward_char(end);
				
		line = atoi(gtk_text_iter_get_slice(start, end));

		txt_view_raise_policy_tab_goto_line(line, user_data);
		return TRUE;
	}

	return FALSE;
}

/* set the cursor to a hand when user scrolls over a line number in when displaying te diff */
gboolean txt_view_on_text_view_motion(GtkWidget *widget, GdkEventMotion *event, gpointer user_data)
{
	GtkTextBuffer *buffer;
 	GtkTextView *tree_view;
	GdkCursor *cursor;
	GtkTextIter iter;
	GSList *tags;
	GtkTextTag *tag;
	gint x, ex, ey, y;

	tree_view = GTK_TEXT_VIEW(widget);

	if (event->is_hint) {	
		gdk_window_get_pointer(event->window, &ex, &ey, NULL);
	} else {
		ex = event->x;
		ey = event->y;
	}

	gtk_text_view_window_to_buffer_coords(tree_view, GTK_TEXT_WINDOW_WIDGET,
					       ex, ey, &x, &y);

	buffer = gtk_text_view_get_buffer(tree_view);
	gtk_text_view_get_iter_at_location(tree_view, &iter, x, y);
	tags = gtk_text_iter_get_tags(&iter);
	
	if (g_slist_length(tags) == 0)
		goto out;
	tag = GTK_TEXT_TAG(g_slist_last(tags)->data);

	if (user_data == tag) {
		cursor = gdk_cursor_new(GDK_HAND2);
		gdk_window_set_cursor(event->window, cursor);
		gdk_cursor_unref(cursor);
		gdk_flush();
	} else {
		gdk_window_set_cursor(event->window, NULL);	
	}
out:
	g_slist_free(tags);
	return FALSE;
}

/* set the cursor to a hand when user scrolls over a line number in when displaying te diff */
gboolean txt_view_on_text_view_motion2(GtkWidget *widget, GdkEventMotion *event, gpointer user_data)
{
	GtkTextBuffer *buffer;
 	GtkTextView *tree_view;
	GdkCursor *cursor;
	GtkTextIter iter;
	GSList *tags;
	GtkTextTag *tag;
	gint x, ex, ey, y;

	tree_view = GTK_TEXT_VIEW(widget);

	if (event->is_hint) {	
		gdk_window_get_pointer(event->window, &ex, &ey, NULL);
	} else {
		ex = event->x;
		ey = event->y;
	}

	gtk_text_view_window_to_buffer_coords(tree_view, GTK_TEXT_WINDOW_WIDGET,
					       ex, ey, &x, &y);

	buffer = gtk_text_view_get_buffer(tree_view);
	gtk_text_view_get_iter_at_location(tree_view, &iter, x, y);
	tags = gtk_text_iter_get_tags(&iter);
	
	if (g_slist_length(tags) == 0)
		goto out;
	tag = GTK_TEXT_TAG(g_slist_last(tags)->data);

	if (user_data == tag) {
		cursor = gdk_cursor_new(GDK_HAND2);
		gdk_window_set_cursor(event->window, cursor);
		gdk_cursor_unref(cursor);
		gdk_flush();
	} else {
		gdk_window_set_cursor(event->window, NULL);	
	}
out:
	g_slist_free(tags);
	return FALSE;
}


static int txt_buffer_insert_type_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "TYPES: %d removed, %d added.\n", 
		stuff_removed->num_types, stuff_added->num_types);
	rt = get_iad_string(string, IDX_TYPE, stuff_removed->types, stuff_added->types, policy_old, policy_new);
	if (rt < 0) {
		fprintf(stderr, "Problem printing types for policy.\n");
		return -1;
	}
	return 0;
}

static int txt_buffer_insert_attrib_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	    policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "ATTRIBS: %d removed, %d added.\n", 
		stuff_removed->num_attribs, stuff_added->num_attribs);
	rt = get_iad_string(string, IDX_ATTRIB, stuff_removed->attribs, stuff_added->attribs, policy_old, policy_new);
	if (rt < 0) {
		fprintf(stderr, "Problem printing attributes.\n");
		return -1;
	}
	return 0;
}

static int txt_buffer_insert_role_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "ROLES: %d removed, %d added.\n", 
		stuff_removed->num_roles, stuff_added->num_roles);
	rt = get_iad_string(string, IDX_ROLE, stuff_removed->roles, stuff_added->roles, policy_old, policy_new);
	if (rt < 0) {
		fprintf(stderr, "Problem printing roles.\n");
		return -1;
	}
	
	return 0;
}

static int txt_buffer_insert_user_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "USERS: %d removed, %d added.\n", 
		stuff_removed->num_users, stuff_added->num_users);
	rt = get_iad_string(string, IDX_USER, stuff_removed->users, stuff_added->users, policy_old, policy_new);
	if (rt < 0) {
		fprintf(stderr, "Problem printing users.\n");
		return -1;
	}

	return 0;
}

static int txt_buffer_insert_boolean_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	     policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "BOOLEANS: %d removed, %d added.\n", 
		stuff_removed->num_booleans, stuff_added->num_booleans);
	rt = get_boolean_diff(string, stuff_removed->booleans, stuff_added->booleans, policy_old, policy_new);
	if(rt < 0){
		fprintf(stderr, "Problem printing booleans.\n");
		return -1;
	}
	
	return 0;
}

static int txt_buffer_insert_classes_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	     policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "CLASSES: %d removed, %d added.\n", 
		stuff_removed->num_classes, stuff_added->num_classes);
	rt = get_iad_string(string, IDX_OBJ_CLASS, stuff_removed->classes, stuff_added->classes, policy_old, policy_new);
	if (rt < 0){
		fprintf(stderr, "Problem printing classes.\n");
		return -1;
	}
	return 0;	
}

static int txt_buffer_insert_common_perms_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	     	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;

	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "COMMON PERMISSIONS: %d removed, %d added.\n", 
		stuff_removed->num_common_perms, stuff_added->num_common_perms);
	rt = get_iad_string(string, IDX_COMMON_PERM, stuff_removed->common_perms, stuff_added->common_perms, 
		policy_old, policy_new);
	if (rt < 0) {
		fprintf(stderr, "Problem printing common permissions.\n");
		return -1;
	}
	return 0;	
}

static int txt_buffer_insert_perms_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	   policy_t *policy_old, policy_t *policy_new)
{
	int rt, i;
	char *name;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "PERMISSIONS: %d removed, %d added.\n", 
		stuff_removed->num_perms, stuff_added->num_perms);
	for (i = 0; i < stuff_removed->num_perms; i++) {
		rt = get_perm_name(stuff_removed->perms[i], &name, policy_old);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d\n", stuff_removed->perms[i]);
			return -1;
		}
		g_string_append_printf(string, "   -%s\n", name);
		free(name);
	}
	for (i = 0; i < stuff_added->num_perms; i++) {
		rt = get_perm_name(stuff_added->perms[i], &name, policy_new);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d\n", stuff_added->perms[i]);
			return -1;
		}
		g_string_append_printf(string, "   +%s\n", name);
		free(name);
	}
	
	return 0;	
}

static void txt_buffer_insert_te_results(GtkTextBuffer *txt, GtkTextIter *txt_iter, 
				    	 GString *string, apol_diff_t *diff, policy_t *policy)
{
	int i, j;
	avh_node_t *cur;
	char *rule;
	GtkTextTag *link_tag, *rules_tag;
	GtkTextTagTable *table;
	gchar **split_line_array = NULL;
					


	g_return_if_fail(diff != NULL);
	table = gtk_text_buffer_get_tag_table(txt);
	link_tag = gtk_text_tag_table_lookup(table, "policy-link-tag");
	if (!is_binary_policy(policy)) {
		if (!link_tag) {
			link_tag = gtk_text_buffer_create_tag(txt, "policy-link-tag",
							      "family", "monospace",
							      "foreground", "blue", 
							      "underline", PANGO_UNDERLINE_SINGLE, NULL);
		}
	}
	rules_tag = gtk_text_tag_table_lookup(table, "rules-tag");
	if (!rules_tag) {
		rules_tag = gtk_text_buffer_create_tag(txt, "rules-tag",
						       "family", "monospace", NULL);
	}
	
	g_string_printf(string, "%d different TE RULES in policy.\n", diff->te.num);
	gtk_text_buffer_insert(txt, txt_iter, string->str, -1);

	gtk_text_buffer_get_end_iter(txt, txt_iter);

	for (i = 0; i < AVH_SIZE; i++) {
		for (cur = diff->te.tab[i];cur != NULL; cur = cur->next) {
			rule = re_render_avh_rule_linenos(cur, policy);
			if (rule != NULL) {
				j = 0;
				split_line_array = g_strsplit((const gchar*)rule, " ", 0);  
				while (split_line_array[j] != NULL) {  
					gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, "(", -1, "rules-tag", NULL);
					g_string_printf(string, "%s", split_line_array[j]);
					if (!is_binary_policy(policy)) {
						gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, -1, "policy-link-tag", NULL);
					}
					gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, ")", -1, "rules-tag", NULL);
					j++;
				}
				free(rule);
				g_strfreev(split_line_array);
			}
			
			rule = re_render_avh_rule(cur, policy);
			if (rule == NULL) {
				g_return_if_reached();
			}
			g_string_printf(string, "  %s", rule);
			gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, -1, "rules-tag", NULL);
			gtk_text_buffer_get_iter_at_offset(txt, txt_iter, -1);
			free(rule);
			
			if (cur->flags & AVH_FLAG_COND) {
				rule = re_render_avh_rule_cond_state(cur, policy);
				if (rule == NULL) {
					g_return_if_reached();
				}
				g_string_printf(string, "   %s", rule);
				gtk_text_buffer_insert(txt, txt_iter, string->str, -1);
				gtk_text_buffer_get_iter_at_offset(txt, txt_iter, -1);
				free(rule);
			
				g_string_printf(string, " (cond = %d)", cur->cond_expr);
				gtk_text_buffer_insert(txt, txt_iter, string->str, -1);
				gtk_text_buffer_get_iter_at_offset(txt, txt_iter, -1);
			}
		
			gtk_text_buffer_insert(txt, txt_iter, "\n", -1);
			gtk_text_buffer_get_iter_at_offset(txt, txt_iter, -1);
		}
//		gtk_main_iteration_do(FALSE);
	}

}

static int txt_buffer_insert_rbac_results(GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;

	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	g_string_append_printf(string, "ROLES: %d removed, %d added.\n", 
		stuff_removed->num_role_allow, stuff_added->num_role_allow);
	rt = get_iad_string(string, IDX_ROLE|IDX_PERM, stuff_removed->role_allow, stuff_added->role_allow, policy_old, policy_new);
	if (rt < 0) {
		fprintf(stderr, "Problem printing rbac for policy.\n");
		return -1;
	}

	return 0;
}

static int txt_buffer_insert_cond_results(GString *string, apol_diff_t *diff, policy_t *policy)
{
	g_return_val_if_fail(diff != NULL, -1);
	
	return 0;
}

static int txt_buffer_insert_sid_results(GString *string, apol_diff_t *diff, policy_t *policy)
{
	g_return_val_if_fail(diff != NULL, -1);
	
	return 0;
}

/*
  clear the text buffers 
*/
static void sediff_clear_buffers()
{
	if (sediff_app->classes_buffer) {
		g_object_unref (G_OBJECT(sediff_app->classes_buffer)); 

	}
	if (sediff_app->types_buffer) {
		g_object_unref (G_OBJECT(sediff_app->types_buffer)); 
	}
	if (sediff_app->roles_buffer) {
		g_object_unref (G_OBJECT(sediff_app->roles_buffer)); 
	}
	if (sediff_app->users_buffer) {
		g_object_unref (G_OBJECT(sediff_app->users_buffer)); 
	}
	if (sediff_app->booleans_buffer) {
		g_object_unref (G_OBJECT(sediff_app->booleans_buffer)); 
	}
	if (sediff_app->sids_buffer) {
		g_object_unref (G_OBJECT(sediff_app->sids_buffer)); 
	}
	if (sediff_app->te_buffer) {
		g_object_unref (G_OBJECT(sediff_app->te_buffer)); 
	}
	if (sediff_app->rbac_buffer) {
		g_object_unref (G_OBJECT(sediff_app->rbac_buffer)); 
	}
	if (sediff_app->cond_buffer) {
		g_object_unref (G_OBJECT(sediff_app->cond_buffer)); 
	}
	if (sediff_app->classes_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->classes_buffer2)); 
	}
	if (sediff_app->types_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->types_buffer2)); 
	}
	if (sediff_app->roles_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->roles_buffer2)); 
	} 
	if (sediff_app->users_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->users_buffer2)); 
	}
	if (sediff_app->booleans_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->booleans_buffer2)); 
	}
	if (sediff_app->sids_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->sids_buffer2)); 
	} 
	if (sediff_app->te_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->te_buffer2)); 
	}
	if (sediff_app->rbac_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->rbac_buffer2)); 
	} 
	if (sediff_app->cond_buffer2) {
		g_object_unref (G_OBJECT(sediff_app->cond_buffer2)); 
	}

	sediff_app->classes_buffer = NULL;
	sediff_app->types_buffer = NULL;	
	sediff_app->roles_buffer = NULL;
	sediff_app->users_buffer = NULL;
	sediff_app->booleans_buffer = NULL;
	sediff_app->sids_buffer = NULL;
	sediff_app->te_buffer = NULL;
	sediff_app->rbac_buffer = NULL;
	sediff_app->cond_buffer = NULL;

	sediff_app->classes_buffer2 = NULL;
	sediff_app->types_buffer2 = NULL;	
	sediff_app->roles_buffer2 = NULL;
	sediff_app->users_buffer2 = NULL;
	sediff_app->booleans_buffer2 = NULL;
	sediff_app->sids_buffer2 = NULL;
	sediff_app->te_buffer2 = NULL;
	sediff_app->rbac_buffer2 = NULL;
	sediff_app->cond_buffer2 = NULL;

}


/*
  create the text buffers we use to display diff results 
*/
static void sediff_create_buffers()
{
	sediff_app->classes_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->classes_buffer)); 


	sediff_app->types_buffer = gtk_text_buffer_new(NULL);	
	g_object_ref (G_OBJECT(sediff_app->types_buffer)); 

	sediff_app->roles_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->roles_buffer)); 


	sediff_app->users_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->users_buffer)); 


	sediff_app->booleans_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->booleans_buffer)); 


	sediff_app->sids_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->sids_buffer)); 


	sediff_app->te_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->te_buffer)); 


	sediff_app->rbac_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->rbac_buffer)); 


	sediff_app->cond_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->cond_buffer)); 


	sediff_app->classes_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->classes_buffer2)); 

	sediff_app->types_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->types_buffer2)); 

	sediff_app->roles_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->roles_buffer2)); 

	sediff_app->users_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->users_buffer2)); 

	sediff_app->booleans_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->booleans_buffer2)); 

	sediff_app->sids_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->sids_buffer2)); 

	sediff_app->te_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->te_buffer2)); 

	sediff_app->rbac_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->rbac_buffer2)); 

	sediff_app->cond_buffer2 = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->cond_buffer2)); 

}

/*
  puts the diff results into the precreated text buffers
*/
static void txt_view_populate_buffers(apol_diff_t *stuff_removed,
				     apol_diff_t *stuff_added,
				     policy_t *policy_old,
				     policy_t *policy_new)
{
	gint rt;
	GString *string = g_string_new("");
	GtkTextIter end;

	sediff_clear_buffers();
	sediff_create_buffers();

  
	/* case OPT_CLASSES: */
	rt = txt_buffer_insert_classes_results(string, stuff_removed, 
					       stuff_added, policy_old, policy_new);
	g_string_append(string, "\n");
	rt = txt_buffer_insert_perms_results(string, stuff_removed, stuff_added, 
					     policy_old, policy_new);
	g_string_append(string, "\n");
	rt = txt_buffer_insert_common_perms_results(string, stuff_removed, stuff_added, 
						    policy_old, policy_new);

	gtk_text_buffer_get_end_iter(sediff_app->classes_buffer, &end); 
	gtk_text_buffer_insert(sediff_app->classes_buffer, &end, string->str, -1);

	/* case OPT_TYPES: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_type_results(string, stuff_removed, stuff_added, 
					    policy_old, policy_new);
	g_string_append(string, "\n");
	rt = txt_buffer_insert_attrib_results(string, stuff_removed, stuff_added, 
					      policy_old, policy_new);
	gtk_text_buffer_get_end_iter(sediff_app->types_buffer, &end);
	gtk_text_buffer_insert(sediff_app->types_buffer, &end, string->str, -1);

	/* case OPT_ROLES: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_role_results(string, stuff_removed, stuff_added, 
					    policy_old, policy_new);
	gtk_text_buffer_get_end_iter(sediff_app->roles_buffer, &end);
	gtk_text_buffer_insert(sediff_app->roles_buffer, &end, string->str, -1);

	/* case OPT_USERS: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_user_results(string, stuff_removed, stuff_added, 
					    policy_old, policy_new);
	gtk_text_buffer_get_end_iter(sediff_app->users_buffer, &end);
	gtk_text_buffer_insert(sediff_app->users_buffer, &end, string->str, -1);

	/* case OPT_BOOLEANS: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_boolean_results(string, stuff_removed, stuff_added, 
					       policy_old, policy_new);
	gtk_text_buffer_get_end_iter(sediff_app->booleans_buffer, &end);
	gtk_text_buffer_insert(sediff_app->booleans_buffer, &end, string->str, -1);

	/* case OPT_SIDS: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_sid_results(string, stuff_removed, policy_old);
	gtk_text_buffer_get_end_iter(sediff_app->sids_buffer, &end);
	gtk_text_buffer_insert(sediff_app->sids_buffer, &end, string->str, -1);

	/* case OPT_TE_RULES: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->te_buffer, &end);
	txt_buffer_insert_te_results(sediff_app->te_buffer, &end, 
				     string, stuff_removed, policy_old);

	/* case OPT_RBAC_RULES: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_rbac_results(string, stuff_removed, stuff_added, 
					    policy_old, policy_new);
	g_string_append(string, "\n");
	gtk_text_buffer_get_end_iter(sediff_app->rbac_buffer, &end);
	gtk_text_buffer_insert(sediff_app->rbac_buffer, &end, string->str, -1);

	/* case OPT_CONDITIONALS: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_cond_results(string, stuff_removed, policy_old);
	gtk_text_buffer_get_end_iter(sediff_app->cond_buffer, &end);
	gtk_text_buffer_insert(sediff_app->cond_buffer, &end, string->str, -1);



	/* case OPT_CLASSES: */
	rt = txt_buffer_insert_classes_results(string, stuff_added, 
					       stuff_removed, policy_new, policy_old);
	g_string_append(string, "\n");
	rt = txt_buffer_insert_perms_results(string, stuff_added, stuff_removed, 
					     policy_new, policy_old);
	g_string_append(string, "\n");
	rt = txt_buffer_insert_common_perms_results(string, stuff_added, stuff_removed, 
						    policy_new, policy_old);

	gtk_text_buffer_get_end_iter(sediff_app->classes_buffer2, &end); 
	gtk_text_buffer_insert(sediff_app->classes_buffer2, &end, string->str, -1);

	/* case OPT_TYPES: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_type_results(string, stuff_added, stuff_removed, 
					    policy_new, policy_old);
	g_string_append(string, "\n");
	rt = txt_buffer_insert_attrib_results(string, stuff_added, stuff_removed, 
					      policy_new, policy_old);
	gtk_text_buffer_get_end_iter(sediff_app->types_buffer2, &end);
	gtk_text_buffer_insert(sediff_app->types_buffer2, &end, string->str, -1);

	/* case OPT_ROLES: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_role_results(string, stuff_added, stuff_removed, 
					    policy_new, policy_old);
	gtk_text_buffer_get_end_iter(sediff_app->roles_buffer2, &end);
	gtk_text_buffer_insert(sediff_app->roles_buffer2, &end, string->str, -1);

	/* case OPT_USERS: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_user_results(string, stuff_added, stuff_removed, 
					    policy_new, policy_old);
	gtk_text_buffer_get_end_iter(sediff_app->users_buffer2, &end);
	gtk_text_buffer_insert(sediff_app->users_buffer2, &end, string->str, -1);

	/* case OPT_BOOLEANS: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_boolean_results(string, stuff_added, stuff_removed, 
					       policy_new, policy_old);
	gtk_text_buffer_get_end_iter(sediff_app->booleans_buffer2, &end);
	gtk_text_buffer_insert(sediff_app->booleans_buffer2, &end, string->str, -1);

	/* case OPT_SIDS: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_sid_results(string, stuff_added, policy_new);
	gtk_text_buffer_get_end_iter(sediff_app->sids_buffer2, &end);
	gtk_text_buffer_insert(sediff_app->sids_buffer2, &end, string->str, -1);

	/* case OPT_TE_RULES: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->te_buffer2, &end);
	txt_buffer_insert_te_results(sediff_app->te_buffer2, &end, 
				     string, stuff_added, policy_new);

	/* case OPT_RBAC_RULES: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_rbac_results(string, stuff_added, stuff_removed, 
					    policy_new, policy_old);
	g_string_append(string, "\n");
	gtk_text_buffer_get_end_iter(sediff_app->rbac_buffer2, &end);
	gtk_text_buffer_insert(sediff_app->rbac_buffer2, &end, string->str, -1);

	/* case OPT_CONDITIONALS: */
	g_string_truncate(string,0);
	rt = txt_buffer_insert_cond_results(string, stuff_added, policy_new);
	gtk_text_buffer_get_end_iter(sediff_app->cond_buffer2, &end);
	gtk_text_buffer_insert(sediff_app->cond_buffer2, &end, string->str, -1);

	g_string_free(string, TRUE);
}

/*
  switches the currently displayed text buffer
*/
static void txt_view_switch_buffer(GtkTextView *textview,gint option,gint policy_option)
{
	GtkTextTag *link_tag;
	GtkTextTagTable *table;
	

	if (policy_option == 1) {
		switch (option) {
		case OPT_CLASSES:
			gtk_text_view_set_buffer(textview,sediff_app->classes_buffer);
			break;
		case OPT_TYPES:
			gtk_text_view_set_buffer(textview,sediff_app->types_buffer);
			break;
		case OPT_ROLES:
			gtk_text_view_set_buffer(textview,sediff_app->roles_buffer);
			break;
		case OPT_USERS:
			gtk_text_view_set_buffer(textview,sediff_app->users_buffer);
			break;
		case OPT_BOOLEANS:
			gtk_text_view_set_buffer(textview,sediff_app->booleans_buffer);
			break;
		case OPT_SIDS:
			gtk_text_view_set_buffer(textview,sediff_app->sids_buffer);
			break;
		case OPT_TE_RULES:
			table = gtk_text_buffer_get_tag_table(sediff_app->te_buffer);
			link_tag = gtk_text_tag_table_lookup(table, "policy-link-tag");
			g_signal_connect_after(G_OBJECT(link_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						textview);
			glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
						GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link_tag);
			gtk_text_view_set_buffer(textview,sediff_app->te_buffer);
			break;
		case OPT_RBAC_RULES:
			gtk_text_view_set_buffer(textview,sediff_app->rbac_buffer);
			break;
		case OPT_CONDITIONALS:
			gtk_text_view_set_buffer(textview,sediff_app->cond_buffer);
			break;
		default:
			fprintf(stderr, "Invalid list item %d!", option);
			break;
		};
	}
	else {
		switch (option) {
		case OPT_CLASSES:
			gtk_text_view_set_buffer(textview,sediff_app->classes_buffer2);
			break;
		case OPT_TYPES:
			gtk_text_view_set_buffer(textview,sediff_app->types_buffer2);
			break;
		case OPT_ROLES:
			gtk_text_view_set_buffer(textview,sediff_app->roles_buffer2);
			break;
		case OPT_USERS:
			gtk_text_view_set_buffer(textview,sediff_app->users_buffer2);
			break;
		case OPT_BOOLEANS:
			gtk_text_view_set_buffer(textview,sediff_app->booleans_buffer2);
			break;
		case OPT_SIDS:
			gtk_text_view_set_buffer(textview,sediff_app->sids_buffer2);
			break;
		case OPT_TE_RULES:
			table = gtk_text_buffer_get_tag_table(sediff_app->te_buffer2);
			link_tag = gtk_text_tag_table_lookup(table, "policy-link-tag");
			g_signal_connect_after(G_OBJECT(link_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						textview);
			glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion2", 
						GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link_tag);
			gtk_text_view_set_buffer(textview,sediff_app->te_buffer2);
			break;
		case OPT_RBAC_RULES:
			gtk_text_view_set_buffer(textview,sediff_app->rbac_buffer2);
			break;
		case OPT_CONDITIONALS:
			gtk_text_view_set_buffer(textview,sediff_app->cond_buffer2);
			break;
		default:
			fprintf(stderr, "Invalid list item %d!", option);
			break;
		};
	}

}

/* 
   callback used to switch our text buffer based on
   user input from the treeview
*/
static gboolean txt_buffer_insert_results(gpointer data)
{
	GValue gval = {0};
	GtkTreeIter iter;
	GtkTextView *textview1, *textview2;
	gint option;
	apol_diff_result_t *diff_results = NULL;
	GtkTreeModel *tree_model;
	GtkTreeSelection *sel;
	GList *glist = NULL, *item = NULL;
	GtkTreePath *path = NULL;

	tree_model = gtk_tree_view_get_model((GtkTreeView*)sediff_app->tree_view);
	sel = gtk_tree_view_get_selection((GtkTreeView*)sediff_app->tree_view);
	glist = gtk_tree_selection_get_selected_rows(sel, &tree_model);
	if (glist == NULL) {
		return FALSE;
	}
	/* Only grab the top-most selected item */
	item = glist;
	path = item->data;
	
	/* if we can't get the iterator, then we need to just exit */
	if (!gtk_tree_model_get_iter(tree_model, &iter, path)) {
		if (glist) {	
			g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
			g_list_free(glist);			
		}	
		return FALSE;
	}
	if (glist) {	
		g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
		g_list_free(glist);			
	}
	
	option = GPOINTER_TO_INT(iter.user_data);
	gtk_tree_model_get_value(tree_model, &iter, SEDIFF_HIDDEN_COLUMN, &gval);	
	
	/* grab the text buffers for our text views */
	textview1 = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_p1_results_txt_view");
	g_assert(textview1);
	textview2 = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_p2_results_txt_view");
	g_assert(textview2);

	diff_results = (apol_diff_result_t *)g_value_get_pointer(&gval);
	g_return_val_if_fail(diff_results != NULL, FALSE);
	
	/* Configure text_view */
	gtk_text_view_set_editable(GTK_TEXT_VIEW (textview1), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview1), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (textview1), GTK_WRAP_WORD);
			
	txt_view_switch_buffer(textview1,option,1);

	gtk_text_view_set_editable(GTK_TEXT_VIEW (textview2), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview2), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (textview2), GTK_WRAP_WORD);
	
	txt_view_switch_buffer(textview2,option,2);
	g_value_unset(&gval);	
	
	return FALSE;
}


static void sediff_treeview_on_row_double_clicked(GtkTreeView *tree_view, 
						  GtkTreePath *path, 
						  GtkTreeViewColumn *col, 
						  gpointer user_data)
{
	/* Finish later */

	g_idle_add_full(G_PRIORITY_HIGH_IDLE, &txt_buffer_insert_results, NULL, NULL);	
	row_selected_signal_emit();

}


static gboolean sediff_treeview_on_row_selected(GtkTreeSelection *selection,
					    	GtkTreeModel     *model,
					    	GtkTreePath      *path,
					    	gboolean          path_currently_selected,
					    	gpointer          userdata)
{	

	/* if the row is not selected, then its about to be selected ! */
	/* we put in this toggle because for some reason if we have a previously selected path
	   then this callback is called like this
	   1  new_path is not selected
	   2  old_path is selected
	   3  new_path is not selected
	   This messes up our te rules stuff so I just put in a check to make sure we're not called
	   2 times when we are really only selected once 
	*/
	if (toggle && gtk_tree_selection_path_is_selected(selection,path) == FALSE) {
		g_idle_add_full(G_PRIORITY_HIGH_IDLE, &txt_buffer_insert_results, NULL, NULL);
		row_selected_signal_emit();
  
	}
	else
		toggle = !toggle;
	return TRUE; /* allow selection state to change */
}

static void sediff_callbacks_free_elem_data(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t*)data;
	if (callback)
		free(callback);
	return;
}

static void sediff_destroy(sediff_app_t *sediff_app)
{
	g_assert(sediff_app != NULL);
	if (sediff_app->tree_view) 
		gtk_widget_destroy((GtkWidget *)sediff_app->tree_view);
	if (sediff_app->window != NULL)
		gtk_widget_destroy((GtkWidget *)sediff_app->window);
	if (sediff_app->open_dlg != NULL)
		gtk_widget_destroy((GtkWidget *)sediff_app->open_dlg);
	if (sediff_app->window_xml != NULL)
		g_object_unref(G_OBJECT(sediff_app->window_xml));
	if (sediff_app->open_dlg_xml != NULL)
		g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	g_list_foreach(sediff_app->callbacks, &sediff_callbacks_free_elem_data, NULL);
	g_list_free(sediff_app->callbacks);

	free(sediff_app);
}

static void sediff_exit_app(sediff_app_t *sediff_app)
{
	sediff_destroy(sediff_app);
	gtk_main_quit();
}

static void on_sediff_main_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data) 
{
	sediff_exit_app(sediff_app);	
}

static GtkWidget *sediff_tree_view_create_from_store(SEDiffTreeViewStore *tree_store)
{
	GtkTreeViewColumn   *col;
	GtkCellRenderer     *renderer;
	GtkWidget           *tree_view = NULL;
	GtkTreeSelection    *selection;

	sediff_tree_store_populate(tree_store);	
	tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(tree_store));

	g_object_unref(tree_store); /* destroy store automatically with tree_view */
	
	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start (col, renderer, TRUE);
	gtk_tree_view_column_add_attribute (col, renderer, "text", SEDIFF_LABEL_COLUMN);
	gtk_tree_view_column_set_title (col, "SEDiff Items");
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view),col);
	
	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start (col, renderer, TRUE);
	gtk_tree_view_column_add_attribute (col, renderer, "text", SEDIFF_HIDDEN_COLUMN);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view),col);
	gtk_tree_view_column_set_visible(col, FALSE);

	g_signal_connect(G_OBJECT(tree_view), "row-activated", 
			 G_CALLBACK(sediff_treeview_on_row_double_clicked), NULL);
	
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
        gtk_tree_selection_set_mode(selection,GTK_SELECTION_BROWSE);
	gtk_tree_selection_set_select_function(selection, sediff_treeview_on_row_selected, tree_view, NULL);


	return tree_view;
}

static void sediff_policy_stats_textview_populate(apol_diff_result_t *diff, GtkTextView *textview)
{
	GtkTextBuffer *txt;
	GtkTextIter iter, start, end;
	gchar *contents = NULL;
	policy_t *p1 = NULL, *p2 = NULL; 

	p1 = diff->p1;
	p2 = diff->p2;
	/* grab the text buffer for our tree_view */
	txt = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview));

	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	gtk_text_buffer_delete(txt, &start, &end);

	/* set some variables up */
	gtk_text_view_set_editable (GTK_TEXT_VIEW (textview), FALSE);
	gtk_text_view_set_cursor_visible (GTK_TEXT_VIEW (textview), FALSE);
	gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (textview), GTK_WRAP_WORD);

	contents = g_strdup_printf("Policy 1\n"
				   "Version: %d\n"
				   "Number of Types: %d\n"
				   "Number of Attributes: %d\n"
				   "Number of AV Access: %d\n"
				   "Number of AV Audit: %d\n"
				   "Number of TE Transition: %d\n"
				   "Number of Conditional Booleans: %d\n"
				   "Number of Conditional Expressions: %d\n"
				   "Number of Roles: %d\n"
				   "Number of Roles allowed: %d\n"
				   "Number of Users: %d\n"
				   "Number of Role Transitions: %d\n"
				   "Number of Permissions: %d\n"
				   "Number of Common Permissions: %d\n"
				   "Number of Object Classes: %d\n"
				   "Number of Aliases: %d\n"
				   "Number of Initial SIDS: %d\n"
				   "\nPolicy 2 \n"
				   "Version: %d\n"
				   "Number of Types: %d\n"
				   "Number of Attributes: %d\n"
				   "Number of AV Access: %d\n"
				   "Number of AV Audit: %d\n"
				   "Number of TE Transition: %d\n"
				   "Number of Conditional Booleans: %d\n"
				   "Number of Conditional Expressions: %d\n"
				   "Number of Roles: %d\n"
				   "Number of Roles allowed: %d\n"
				   "Number of Use: %d\n"
				   "Number of Role Transitions: %d\n"
				   "Number of Permissions: %d\n"
				   "Number of Common Permissions: %d\n"
				   "Number of Object Classes: %d\n"
				   "Number of Aliases: %d\n"
				   "Number of Initial SIDS: %d\n",
				   p1->version,p1->num_types,p1->num_attribs,p1->num_av_access,p1->num_av_audit,
				   p1->num_te_trans,p1->num_cond_bools,p1->num_cond_exprs,p1->num_roles,p1->num_role_allow,
				   p1->num_users,p1->num_role_trans,p1->num_perms,p1->num_common_perms,p1->num_obj_classes,
				   p1->num_aliases,p1->num_initial_sids,
				   p2->version,p2->num_types,p2->num_attribs,p2->num_av_access,p2->num_av_audit,
				   p2->num_te_trans,p2->num_cond_bools,p2->num_cond_exprs,p2->num_roles,p2->num_role_allow,
				   p2->num_users,p2->num_role_trans,p2->num_perms,p2->num_common_perms,p2->num_obj_classes,
				   p2->num_aliases,p2->num_initial_sids
		);
	gtk_text_buffer_get_iter_at_offset(txt, &iter, 0);
	gtk_text_buffer_insert(txt, &iter, contents,-1);
	g_free(contents);
}

static int sediff_policy_file_textview_populate(const gchar *filename,GtkTextView *textview)
{
        GtkTextBuffer *txt;
	GtkTextIter iter,start,end;
	gchar *contents = NULL;
	gsize length;
	GError *error;
	
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview));

	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	gtk_text_buffer_delete(txt, &start, &end);
	gtk_text_buffer_get_iter_at_offset (txt, &iter, 0);

	/* set some variables up */
	gtk_text_view_set_editable (GTK_TEXT_VIEW (textview), FALSE);
	gtk_text_view_set_cursor_visible (GTK_TEXT_VIEW (textview), TRUE);
	gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (textview), GTK_WRAP_WORD);

	if (!g_file_get_contents(filename, &contents, &length, &error)){
		g_warning("Unable to read file %s\n",filename);
		return -1;
	}
	gtk_text_buffer_insert (txt, &iter, contents, length);
	
	return 0;
}

void sediff_open_dialog_on_p1browse_button_clicked(GtkButton *button, gpointer user_data)
{
	GtkEntry *entry = NULL;
	GString *filename= NULL;
	
	entry = (GtkEntry *)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry");
	g_assert(entry);
	filename = get_filename_from_user("Open Policy", gtk_entry_get_text(entry));
	if (filename){
		gtk_entry_set_text(entry,filename->str);
	}
}

void sediff_open_dialog_on_p2browse_button_clicked(GtkButton *button, gpointer user_data)
{
	GtkEntry *entry = NULL;
	GString *filename = NULL;

	entry = (GtkEntry*)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry");
	g_assert(entry);
	filename = get_filename_from_user("Open Policy", gtk_entry_get_text(entry));
	if (filename){
		gtk_entry_set_text(entry, filename->str);
	}
}

void sediff_open_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy(widget);
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;	
}

void sediff_open_dialog_on_cancel_button_clicked(GtkButton *button, gpointer user_data)
{
	gtk_widget_destroy(gtk_widget_get_toplevel((GtkWidget *)button));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;
}

void sediff_menu_on_open_clicked(GtkMenuItem *menuitem, gpointer user_data)
{	
	if (sediff_app->open_dlg) {
		gtk_window_present(sediff_app->open_dlg);
	} else {
		sediff_app->open_dlg_xml = glade_xml_new(GLADEFILE, OPEN_DIALOG_ID, NULL);
		g_assert(sediff_app->open_dlg_xml != NULL);
		sediff_app->open_dlg = GTK_WINDOW(glade_xml_get_widget(sediff_app->open_dlg_xml, OPEN_DIALOG_ID));
		g_assert(sediff_app->open_dlg);
		g_signal_connect(G_OBJECT(sediff_app->open_dlg), "delete_event", 
			G_CALLBACK(sediff_open_dialog_on_window_destroy), sediff_app);
		glade_xml_signal_autoconnect(sediff_app->open_dlg_xml);
	}
}

void sediff_menu_on_quit_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_exit_app(sediff_app);
}

void sediff_menu_on_help_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget *window;
	GtkWidget *scroll;
	GtkWidget *text_view;
	GtkTextBuffer *buffer;
	GString *string;
	char *help_text = NULL;
	int len, rt;
	char *dir;

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	scroll = gtk_scrolled_window_new(NULL, NULL);
	text_view = gtk_text_view_new();
	gtk_window_set_title(GTK_WINDOW(window), "SeDiff Help");
	gtk_window_set_default_size(GTK_WINDOW(window), 480, 300);
	gtk_container_add(GTK_CONTAINER(window), scroll);
	gtk_container_add(GTK_CONTAINER(scroll), text_view);
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));	
	dir = find_file("sediff_help.txt");
	if (!dir) {
		string = g_string_new("");
		g_string_append(string, "Cannot find help file");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return;
	}
	string = g_string_new(dir);
	free(dir);
	g_string_append(string, "/sediff_help.txt");
	rt = read_file_to_buffer(string->str, &help_text, &len);
	g_string_free(string, TRUE);
	if (rt != 0) {
		if (help_text)
			free(help_text);
		return;
	}
	gtk_text_buffer_set_text(buffer, help_text, len);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_widget_show(text_view);
	gtk_widget_show(scroll);
	gtk_widget_show(window);
	return;

}

void sediff_menu_on_about_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget *dialog;
	GString *str;
	
	str = g_string_new("");
	g_string_assign(str, "Policy Semantic Diff Tool for Security \nEnhanced Linux");
        g_string_append(str, "\n\nCopyright (c) 2005\nTresys Technology, LLC\nwww.tresys.com/selinux");
	g_string_append(str, "\n\nGUI version ");
	g_string_append(str, SEDIFF_GUI_VERSION_NUM);
	g_string_append(str, "\nlibapol version ");
	g_string_append(str, libapol_get_version()); /* the libapol version */
	
	dialog = gtk_message_dialog_new(sediff_app->window,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_INFO,
					GTK_BUTTONS_CLOSE,
					str->str);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_string_free(str, TRUE);
}

void sediff_open_dialog_on_diff_button_clicked(GtkButton *button, gpointer user_data)
{
	const gchar *p1_file = NULL;
	const gchar *p2_file = NULL;
	GtkEntry *p1_entry;
	GtkEntry *p2_entry;
	GtkTextView *p1_textview;
	GtkTextView *p2_textview;
	GtkTextView *stats;
	GtkWidget *container = NULL;
	SEDiffTreeViewStore *tree_store = NULL;
	apol_diff_result_t *diff_results = NULL;
	GString *string = NULL;
	GtkLabel *lbl_p1, *lbl_p2;
	
	/* get the scrolled window we are going to put the tree_store in */
	container = glade_xml_get_widget(sediff_app->window_xml, "scrolledwindow_list");

	/* grab the GtkEntry widgets so we can get their data*/
	p1_entry = (GtkEntry *)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry");
	p2_entry = (GtkEntry *)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry");

	/* get the data */
	p1_file = gtk_entry_get_text(p1_entry);
	p2_file = gtk_entry_get_text(p2_entry);
	
	if (!g_file_test(p1_file, G_FILE_TEST_EXISTS) || g_file_test(p2_file, G_FILE_TEST_IS_DIR)) {
		string = g_string_new("Invalid file specified for policy 1!");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return;
	}
	if (!g_file_test(p2_file, G_FILE_TEST_EXISTS) || g_file_test(p2_file, G_FILE_TEST_IS_DIR)) {
		string = g_string_new("Invalid file specified for policy 2!");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
	}
			
	/* delete tree_view if it existed before */
	if (sediff_app->tree_view) {
		gtk_widget_destroy((GtkWidget *)sediff_app->tree_view);
		sediff_app->tree_view = NULL;
	}

	/* diff the two policies */
	diff_results = diff_policies((const char*)p1_file, (const char*)p2_file);
	if (!diff_results) {
		return;
	}
	
	/* Update the Label widgets */
	lbl_p1 = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "lbl_policy1");
	lbl_p2 = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "lbl_policy2");
	
	gtk_label_set_text(lbl_p1, (const char*)p1_file);
	gtk_label_set_text(lbl_p2, (const char*)p2_file);
                                             
	/* create a new tree_store */
	tree_store = sediff_tree_store_new();
	tree_store->diff_results = diff_results;
	
	/* Grab the 2 policy textviews */
	p1_textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");
	p2_textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text");
	
	/* now lets populate the textviews with our new policies */
	sediff_policy_file_textview_populate(p1_file, p1_textview);
	sediff_policy_file_textview_populate(p2_file, p2_textview);

	stats = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_pstats_text");
	sediff_policy_stats_textview_populate(tree_store->diff_results, stats);

	/* create the tree_view */
	sediff_app->tree_view = sediff_tree_view_create_from_store(tree_store);
	
	/* make it viewable */
	gtk_container_add(GTK_CONTAINER(container), sediff_app->tree_view);
	gtk_widget_show_all(container);
	
	/* destroy the no longer needed dialog widget */
	gtk_widget_destroy(gtk_widget_get_toplevel((GtkWidget *)button));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;
}

int main(int argc, char **argv)
{
	char *dir;
	GString *path; 



	
	gtk_init(&argc, &argv);
	glade_init();
	dir = find_file(GLADEFILE);
	if (!dir){
		fprintf(stderr, "Could not find sediff.glade!");
		return -1;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append_printf(path, "/%s", GLADEFILE);
	
	sediff_app = (sediff_app_t *)malloc(sizeof(sediff_app_t));
	if (!sediff_app) {
		g_warning("Out of memory!");
		exit(-1);
	}
	memset(sediff_app, 0, sizeof(sediff_app_t));

	sediff_app->classes_buffer = NULL;
	sediff_app->types_buffer = NULL;	
	sediff_app->roles_buffer = NULL;
	sediff_app->users_buffer = NULL;
	sediff_app->booleans_buffer = NULL;
	sediff_app->sids_buffer = NULL;
	sediff_app->te_buffer = NULL;
	sediff_app->rbac_buffer = NULL;
	sediff_app->cond_buffer = NULL;

	sediff_app->classes_buffer2 = NULL;
	sediff_app->types_buffer2 = NULL;	
	sediff_app->roles_buffer2 = NULL;
	sediff_app->users_buffer2 = NULL;
	sediff_app->booleans_buffer2 = NULL;
	sediff_app->sids_buffer2 = NULL;
	sediff_app->te_buffer2 = NULL;
	sediff_app->rbac_buffer2 = NULL;
	sediff_app->cond_buffer2 = NULL;



	gtk_set_locale();
	gtk_init(&argc, &argv);
	sediff_app->window_xml = glade_xml_new(GLADEFILE, MAIN_WINDOW_ID, NULL);
	if (!sediff_app->window_xml) {
		free(sediff_app);
		g_warning("Unable to create interface");
		return -1;
	}
	sediff_app->window = GTK_WINDOW(glade_xml_get_widget(sediff_app->window_xml, MAIN_WINDOW_ID));
	g_signal_connect(G_OBJECT(sediff_app->window), "delete_event", 
			 G_CALLBACK(on_sediff_main_window_destroy), sediff_app);
	

	glade_xml_signal_autoconnect(sediff_app->window_xml);

	gtk_main();
	
	return 0;
}
                          

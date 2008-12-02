/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *         Kevin Carr <kcarr@tresys.com>
 */

#include "seaudit.h"
#include "utilgui.h"
#include "seaudit_callback.h"
#include <string.h>
#include <libapol/render.h>
#include <libapol/policy-query.h>
#include <stdlib.h>
#include <stdio.h>

extern seaudit_t *seaudit_app;

static gint query_window_str_compare(gconstpointer a, gconstpointer b)
{
	return strcmp((const char*)a, (const char*)b);
}

static void raise_policy_tab_goto_line(unsigned long line, GladeXML *xml)
{
	GtkNotebook *notebook;
	GtkTextBuffer *buffer;
	GtkTextView *view;
	GtkTextIter iter;

	notebook = GTK_NOTEBOOK(glade_xml_get_widget(xml, "query_policy_notebook"));
	g_assert(notebook);
	gtk_notebook_set_current_page(notebook, -1);

	view = GTK_TEXT_VIEW(glade_xml_get_widget(xml, "policy_text"));
	g_assert(view);
	buffer = gtk_text_view_get_buffer(view);
	g_assert(buffer);
	gtk_text_buffer_get_start_iter(buffer, &iter);
	gtk_text_iter_set_line(&iter, line);
	gtk_text_view_scroll_to_iter(view, &iter, 0.0001, TRUE, 0.0, 0.5);
	gtk_text_iter_backward_line(&iter);
	gtk_text_buffer_place_cursor(buffer, &iter);
	gtk_text_view_set_cursor_visible(view, TRUE);
	return;
}

gboolean on_policy_link_event(GtkTextTag *tag, GObject *event_object, GdkEvent *event, const GtkTextIter *iter, gpointer user_data)
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
		else 
			while ( offset > 1) {
				gtk_text_iter_backward_char(start);
				offset = gtk_text_iter_get_line_offset(start);
			}
			
		end = gtk_text_iter_copy(start);
		while (!gtk_text_iter_ends_word(end))
			gtk_text_iter_forward_char(end);
		
		line = atoi(gtk_text_iter_get_slice(start, end));
		raise_policy_tab_goto_line(line, user_data);
		return TRUE;
	}

	return FALSE;
}

gboolean on_text_view_motion(GtkWidget *widget, GdkEventMotion *event, gpointer user_data)
{
	GtkTextBuffer *buffer;
 	GtkTextView *view;
	GdkCursor *cursor;
	GtkTextIter iter;
	GSList *tags;
	GtkTextTag *tag;
	gint x, ex, ey, y;

	view = GTK_TEXT_VIEW(widget);

	if (event->is_hint) {	
		gdk_window_get_pointer(event->window, &ex, &ey, NULL);
	} else {
		ex = event->x;
		ey = event->y;
	}

	gtk_text_view_window_to_buffer_coords (view, GTK_TEXT_WINDOW_WIDGET,
					       ex, ey, &x, &y);

	buffer = gtk_text_view_get_buffer(view);
	gtk_text_view_get_iter_at_location(view, &iter, x, y);
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

static void display_policy_query_results(GladeXML *xml, GString *src_type, GString *tgt_type, GString *obj_class, teq_results_t *r)
{
	GtkTextView *view;
	GtkTextBuffer *buffer;
	GtkTextIter start, end; 
	GtkTextTag *link_tag, *rules_tag, *summary_tag;
	GtkTextTagTable *table;
	char *string = NULL, tbuf[APOL_STR_SZ + 64];
	char str[STR_SIZE]; 
	int i;

	view = GTK_TEXT_VIEW(glade_xml_get_widget(xml, "query_results"));
	g_assert(view);

	buffer = gtk_text_view_get_buffer(view);
	g_assert(buffer);
	gtk_text_buffer_get_start_iter(buffer, &start);
	gtk_text_buffer_get_end_iter(buffer, &end);
	gtk_text_buffer_delete(buffer, &start, &end);
	table = gtk_text_buffer_get_tag_table(buffer);
	summary_tag = gtk_text_tag_table_lookup(table, "summary-tag");
	if (!summary_tag) {
		summary_tag = gtk_text_buffer_create_tag(buffer, "summary-tag",
							 "family", "monospace",
							 "weight", "bold", NULL);
	}
	link_tag = gtk_text_tag_table_lookup(table, "policy-link-tag");
	if (!is_binary_policy(seaudit_app->cur_policy)) {
		if (!link_tag) {
			link_tag = gtk_text_buffer_create_tag(buffer, "policy-link-tag",
							      "family", "monospace",
							      "foreground", "blue", 
							      "underline", PANGO_UNDERLINE_SINGLE, NULL);
			g_signal_connect_after(G_OBJECT(link_tag), "event", GTK_SIGNAL_FUNC(on_policy_link_event), xml);
		}
		glade_xml_signal_connect_data(xml, "on_text_view_motion", GTK_SIGNAL_FUNC(on_text_view_motion), link_tag);
	}

	rules_tag = gtk_text_tag_table_lookup(table, "rules-tag");
	if (!rules_tag) {
		rules_tag = gtk_text_buffer_create_tag(buffer, "rules-tag",
						       "family", "monospace", NULL);
	}
	
	snprintf(str, STR_SIZE, 
		 "Found %d Rule(s) containing ", r->num_av_access);
	gtk_text_buffer_insert_with_tags_by_name(buffer, &end, str, -1, "summary-tag", NULL);

	if (strcmp(src_type->str, "") != 0) {
		snprintf(str, STR_SIZE,
			 "Source Type: %s ",
			 src_type->str);
		gtk_text_buffer_insert_with_tags_by_name(buffer, &end, str, -1, "summary-tag", NULL);
	}

	if (strcmp(tgt_type->str, "") != 0) {
		snprintf(str, STR_SIZE,
			 "Target Type: %s ",
			 tgt_type->str);
		gtk_text_buffer_insert_with_tags_by_name(buffer, &end, str, -1, "summary-tag", NULL);
	}

	if (strcmp(obj_class->str, "") != 0) {
		snprintf(str, STR_SIZE,
			 "Object Class: %s ",
			 obj_class->str);
		gtk_text_buffer_insert_with_tags_by_name(buffer, &end, str, -1, "summary-tag", NULL);
	}

	gtk_text_buffer_insert(buffer, &end, "\n", -1);

	for (i = 0; i < r->num_av_access; i++) {
		if (!is_binary_policy(seaudit_app->cur_policy)) {
                       sprintf(tbuf, "(");
                       gtk_text_buffer_insert_with_tags_by_name(buffer, &end, tbuf, -1, "rules-tag", NULL);
                       sprintf(tbuf, "%d", r->av_access_lineno[i]);
                       gtk_text_buffer_insert_with_tags_by_name(buffer, &end, tbuf, -1, "policy-link-tag", NULL);
                       sprintf(tbuf, ") ");
                       gtk_text_buffer_insert_with_tags_by_name(buffer, &end, tbuf, -1, "rules-tag", NULL);
               	}
		string = re_render_av_rule(FALSE, r->av_access[i], FALSE, seaudit_app->cur_policy);
		gtk_text_buffer_insert_with_tags_by_name(buffer, &end, string, -1, "rules-tag", NULL);
		gtk_text_buffer_insert(buffer, &end, "\n", -1);
	}
	return;
}

static int do_policy_query(GString *src_type, GString *tgt_type, GString *obj_class, GladeXML *xml)
{

	GtkWindow *window;
	GtkWidget *widget;
	teq_query_t q;
	teq_results_t r;
	int obj_class_idx, i;

	/* setup the query struct */
	init_teq_query(&q);
	q.rule_select = TEQ_ALLOW;
	q.any = FALSE;
	widget = glade_xml_get_widget(xml, "SrcTypeIndirectCheck");
	g_assert(widget);
	q.ta1.indirect = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	if (strcmp(src_type->str, "") != 0)
		q.ta1.ta = strdup(src_type->str);
	else 
		q.ta1.ta = NULL;
	q.ta1.t_or_a = IDX_TYPE;

	widget = glade_xml_get_widget(xml, "TgtTypeIndirectCheck");
	g_assert(widget);
	q.ta2.indirect = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
	if (strcmp(tgt_type->str, "") != 0)
		q.ta2.ta = strdup(tgt_type->str);
	else 
		q.ta2.ta = NULL;
	q.ta2.t_or_a = IDX_TYPE;

	/* get the object class index.  
	 * If its valid use it in the query */
	if (strcmp(obj_class->str, "") != 0) {
		obj_class_idx = get_obj_class_idx(obj_class->str, seaudit_app->cur_policy);
		if (obj_class_idx >= 0) {
			q.classes = (int*)malloc(sizeof(int));
			*q.classes = obj_class_idx;
			q.num_classes = 1;
		} else {
			window = GTK_WINDOW(glade_xml_get_widget(xml, "query_window"));
			g_assert(window);
			message_display(window, GTK_MESSAGE_ERROR, "Invalid object class");
			free_teq_query_contents(&q);
			return -1;
		}
	}

	/* initialize the results structure */
	init_teq_results(&r);
	i = search_te_rules(&q, &r, seaudit_app->cur_policy);

	/* free the query */
	free_teq_query_contents(&q);

	if (i < 0) {
		window = GTK_WINDOW(glade_xml_get_widget(xml, "query_window"));
		g_assert(window);
		if(r.errmsg) {
			message_display(window, GTK_MESSAGE_ERROR, r.errmsg);
			free(r.errmsg);
			return -1;
		} else {
			message_display(window, GTK_MESSAGE_ERROR, "unrecoverable error in search.");
			return -1;
		}
	}
	display_policy_query_results(xml, src_type, tgt_type, obj_class, &r);
	free_teq_results_contents(&r);
	return 0;
}

void on_query_policy_button_clicked(GtkButton *button, GladeXML *xml)
{
	GtkEntry *src_entry, *tgt_entry, *obj_entry;
	GtkToggleButton *toggle;
	GString *src_type, *tgt_type, *obj_class;
	GtkWindow *window;
	gboolean src_on, tgt_on, obj_on;

	window = GTK_WINDOW(glade_xml_get_widget(xml, "query_window"));
		
	src_type = g_string_new("");
	tgt_type = g_string_new("");
	obj_class = g_string_new("");

	src_entry = GTK_ENTRY(glade_xml_get_widget(xml, "src_combo_entry"));
	tgt_entry = GTK_ENTRY(glade_xml_get_widget(xml, "tgt_combo_entry"));
	obj_entry = GTK_ENTRY(glade_xml_get_widget(xml, "obj_combo_entry"));
	g_assert(src_entry);
	g_assert(tgt_entry);
	g_assert(obj_entry);

	g_string_assign(src_type, gtk_entry_get_text(src_entry));
	g_string_assign(tgt_type, gtk_entry_get_text(tgt_entry));
	g_string_assign(obj_class, gtk_entry_get_text(obj_entry));

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "src_type_check_button"));
	src_on = gtk_toggle_button_get_active(toggle);
	if (src_on) {
		if (strcmp(src_type->str, "") == 0) {
			message_display(window, GTK_MESSAGE_ERROR, "You must select a source type.");
			goto exit;
		}
	} else
		g_string_assign(src_type, "");


	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "tgt_type_check_button"));
	tgt_on = gtk_toggle_button_get_active(toggle);
	if (tgt_on) {
		if (strcmp(tgt_type->str, "") == 0) {
			message_display(window, GTK_MESSAGE_ERROR, "You must select a target type.");
			goto exit;
		}
	} else 
		g_string_assign(tgt_type, "");

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "obj_check_button"));
	obj_on = gtk_toggle_button_get_active(toggle);
	if (obj_on) {
		if (strcmp(obj_class->str, "") == 0) {
			message_display(window, GTK_MESSAGE_ERROR, "You must select an object class.");
			goto exit;
		}
	} else
		g_string_assign(obj_class, "");

	if ( !src_on && !obj_on && !tgt_on) {
		message_display(window, GTK_MESSAGE_ERROR, "You must select a Source Type, Target Type,\nor Object Class");
		goto exit;
	}

	show_wait_cursor(GTK_WIDGET(window));
	do_policy_query(src_type, tgt_type, obj_class, xml);
	clear_wait_cursor(GTK_WIDGET(window));
	
 exit:
	if (src_type)
		g_string_free(src_type, TRUE);
	if (tgt_type)
		g_string_free(tgt_type, TRUE);
	if (obj_class)
		g_string_free(obj_class, TRUE);
	return;
}

void on_tgt_type_check_button_toggled(GtkToggleButton *button, gpointer user_data)
{
	GladeXML *xml = (GladeXML*)user_data;
	GtkWidget *widget;
	
	if (gtk_toggle_button_get_active(button)) {
		widget = glade_xml_get_widget(xml, "tgt_combo");
		gtk_widget_set_sensitive(widget, TRUE);
		widget = glade_xml_get_widget(xml, "TgtTypeIndirectCheck");
		gtk_widget_set_sensitive(widget, TRUE);
	} else {
		widget = glade_xml_get_widget(xml, "tgt_combo");
		gtk_widget_set_sensitive(widget, FALSE);
		widget = glade_xml_get_widget(xml, "TgtTypeIndirectCheck");
		gtk_widget_set_sensitive(widget, FALSE);		
	}
}

void on_src_type_check_button_toggled(GtkToggleButton *button, gpointer user_data)
{
	GladeXML *xml = (GladeXML*)user_data;
	GtkWidget *widget;
	
	if (gtk_toggle_button_get_active(button)) {
		widget = glade_xml_get_widget(xml, "src_combo");
		gtk_widget_set_sensitive(widget, TRUE);
		widget = glade_xml_get_widget(xml, "SrcTypeIndirectCheck");
		gtk_widget_set_sensitive(widget, TRUE);
	} else {
		widget = glade_xml_get_widget(xml, "src_combo");
		gtk_widget_set_sensitive(widget, FALSE);
		widget = glade_xml_get_widget(xml, "SrcTypeIndirectCheck");
		gtk_widget_set_sensitive(widget, FALSE);
	}	
}

void on_obj_check_button_toggled(GtkToggleButton *button, gpointer user_data)
{
	GladeXML *xml = (GladeXML*)user_data;
	GtkWidget *combo;
	
	combo = glade_xml_get_widget(xml, "obj_combo");

	if (gtk_toggle_button_get_active(button))
		gtk_widget_set_sensitive(combo, TRUE);
	else
		gtk_widget_set_sensitive(combo, FALSE);		
}

static void query_window_populate_combo_boxes(GtkWidget *src_type_combo, GtkWidget *tgt_type_combo, GtkWidget *obj_class_combo) 
{
	GList *items = NULL;
	int i;
	
	for (i = 0; i < seaudit_app->cur_policy->num_types; i++) {
		items = g_list_append(items, seaudit_app->cur_policy->types[i].name);
	}
	items = g_list_sort(items, &query_window_str_compare);
	gtk_combo_set_popdown_strings(GTK_COMBO(src_type_combo), items);
	gtk_combo_set_popdown_strings(GTK_COMBO(tgt_type_combo), items);
	g_list_free(items);
	items = NULL;
	
	for (i = 0; i < seaudit_app->cur_policy->num_obj_classes; i++) {
		items = g_list_append(items, seaudit_app->cur_policy->obj_classes[i].name);
	}
	items = g_list_sort(items, &query_window_str_compare);
	gtk_combo_set_popdown_strings(GTK_COMBO(obj_class_combo), items);
	g_list_free(items);
	return;
}

static void populate_query_window_widgets(GladeXML *xml, int *tree_item_idx)
{
	GtkTreeSelection *sel;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *src_type_combo, *tgt_type_combo, *obj_class_combo;
	GtkWidget *src_entry, *tgt_entry, *obj_entry;
	gboolean selected;
	GString *str;
	msg_t *msg = NULL;
	avc_msg_t *avc_msg = NULL;
	int fltr_msg_idx, msg_list_idx;
	seaudit_filtered_view_t *view;
	GtkTreePath *path = NULL;
	GList *glist = NULL, *item = NULL;
	
	g_assert(seaudit_app->cur_policy);
	view = seaudit_window_get_current_view(seaudit_app->window);
	
	if (tree_item_idx == NULL) {
		sel = gtk_tree_view_get_selection(view->tree_view);
		glist = gtk_tree_selection_get_selected_rows(sel, &model);
		if (glist == NULL) {
			return;
		}
		/* Only grab the top-most selected item */
		item = glist;
		path = item->data;
		if (gtk_tree_model_get_iter(model, &iter, path) == 0) {
			fprintf(stderr, "Could not get valid iterator for the selected path.\n");
			if (glist) {	
				g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
				g_list_free (glist);			
			}
			return;	
		}
		fltr_msg_idx = seaudit_log_view_store_iter_to_idx((SEAuditLogViewStore*)model, &iter);
		selected = TRUE;
	} else {
		fltr_msg_idx = *tree_item_idx;	
		selected = TRUE;
	}
	
	msg_list_idx = view->store->log_view->fltr_msgs[fltr_msg_idx];
	msg = seaudit_app->cur_log->msg_list[msg_list_idx];
	if (msg->msg_type!=AVC_MSG) {
		selected = FALSE;
	} else {
		g_assert(fltr_msg_idx >= 0);
		avc_msg = msg->msg_data.avc_msg;
	}
	
	src_type_combo = glade_xml_get_widget(xml, "src_combo");
	g_assert(src_type_combo);
	tgt_type_combo = glade_xml_get_widget(xml, "tgt_combo");
	g_assert(tgt_type_combo);
	obj_class_combo = glade_xml_get_widget(xml, "obj_combo");
	g_assert(obj_class_combo);

	gtk_combo_disable_activate(GTK_COMBO(src_type_combo));   
	gtk_combo_disable_activate(GTK_COMBO(tgt_type_combo));   
	gtk_combo_disable_activate(GTK_COMBO(obj_class_combo));   

	query_window_populate_combo_boxes(src_type_combo, tgt_type_combo, obj_class_combo);

	src_entry = glade_xml_get_widget(xml, "src_combo_entry");
	g_assert(src_entry);	
	tgt_entry = glade_xml_get_widget(xml, "tgt_combo_entry");
	g_assert(tgt_entry);
	obj_entry = glade_xml_get_widget(xml, "obj_combo_entry");
	g_assert(obj_entry);	

	if (selected) {
		str = g_string_new("");
		g_string_assign(str, audit_log_get_type(seaudit_app->cur_log, avc_msg->src_type));
		g_string_prepend(str, "^");
		g_string_append(str, "$");
		gtk_entry_set_text(GTK_ENTRY(src_entry), str->str);
		g_string_assign(str, audit_log_get_type(seaudit_app->cur_log, avc_msg->tgt_type));
		g_string_prepend(str, "^");
		g_string_append(str, "$");
		gtk_entry_set_text(GTK_ENTRY(tgt_entry), str->str);
		gtk_entry_set_text(GTK_ENTRY(obj_entry), audit_log_get_obj(seaudit_app->cur_log, avc_msg->obj_class));
		g_string_free(str, TRUE);
		
		/* Free selected rows list */
		if (glist) {
			g_list_foreach(glist, (GFunc)gtk_tree_path_free, NULL);
			g_list_free(glist);
		}
	} else { 
		gtk_entry_set_text(GTK_ENTRY(src_entry), "");
		gtk_entry_set_text(GTK_ENTRY(tgt_entry), "");
		gtk_entry_set_text(GTK_ENTRY(obj_entry), "");
	}
		
	return;
}

static void on_new_policy_opened(void *user_data);

void query_window_remove_callbacks(GtkWidget *widget)
{
	policy_load_callback_remove(&on_new_policy_opened, widget);

	/* if there is an idle function for this window
	 * then we must remove it to avoid that function
	 * being executed after we delete the window.  This 
	 * may happen if the window is closed during a search. */
	while(g_idle_remove_by_data(widget));
}

gboolean on_query_window_delete_event(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	query_window_remove_callbacks(widget);

	return FALSE;
}

static void on_new_policy_opened(void *user_data)
{
	query_window_remove_callbacks((GtkWidget*)user_data);
	gtk_widget_destroy((GtkWidget*)user_data);
}

void on_list_selection_changed(GtkList *list, GtkWidget *widget, gpointer data)
{
	printf("select-child *%s*\n", gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(data)->entry)));

}

void on_event_after(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	GString *str;

	if (event->selection.type ==  GDK_BUTTON_RELEASE) {
		str = g_string_new("");
		g_string_assign(str, gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(user_data)->entry)));
		g_string_prepend(str, "^");
		g_string_append(str, "$");
		gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(user_data)->entry), str->str);
		g_string_free(str, TRUE);
	}
	return;
}

int query_window_create(int *tree_item_idx)
{
	GladeXML *xml;
	GtkWidget *text, *button, *combo;
	GtkWindow *window;
	GString *path;
	GtkNotebook *notebook;
	char *dir;

	if (!seaudit_app->cur_policy) {
		message_display(seaudit_app->window->window, GTK_MESSAGE_ERROR, "You must load a policy first.\n");
		return -1;
	}	

	dir = find_file("query_window.glade");
	if (!dir){
		fprintf(stderr, "could not find query_window.glade\n");
		return -1;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/query_window.glade");
	xml = glade_xml_new(path->str, NULL, NULL);
	g_string_free(path, TRUE);
	window = GTK_WINDOW(glade_xml_get_widget(xml, "query_window"));
	g_assert(window);
		
	/* connect functions to display selection as regular expression */
	combo = glade_xml_get_widget(xml, "src_combo");
	g_assert(combo);
	g_signal_connect(GTK_COMBO(combo)->list, "event-after", G_CALLBACK(on_event_after), combo);
	combo = glade_xml_get_widget(xml, "tgt_combo");
	g_assert(combo);
	g_signal_connect(GTK_COMBO(combo)->list, "event-after", G_CALLBACK(on_event_after), combo);
	
	glade_xml_signal_connect_data(xml, "on_query_policy_button_clicked",
				      G_CALLBACK(on_query_policy_button_clicked),
				      xml);
	g_signal_connect(G_OBJECT(window), "delete_event", 
			 G_CALLBACK(on_query_window_delete_event), 
			 NULL);

	policy_load_callback_register(&on_new_policy_opened, window);
	
	populate_query_window_widgets(xml, tree_item_idx);
	
	if (is_binary_policy(seaudit_app->cur_policy)) {
		/* Remove the policy.conf tab if this is a binary policy. */
		notebook = GTK_NOTEBOOK(glade_xml_get_widget(xml, "query_policy_notebook"));
		g_assert(notebook);
		gtk_notebook_remove_page(notebook, 1);
	} else {
		text = glade_xml_get_widget(xml, "policy_text");
		g_assert(text);
	
		gtk_text_view_set_buffer(GTK_TEXT_VIEW(text), seaudit_app->policy_text);
		gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
	}
	
	text = glade_xml_get_widget(xml, "query_results");
	g_assert(text);

	button = glade_xml_get_widget(xml, "src_type_check_button");
	gtk_signal_connect(GTK_OBJECT(button), "toggled", GTK_SIGNAL_FUNC(on_src_type_check_button_toggled), xml);
	
	button = glade_xml_get_widget(xml, "tgt_type_check_button");
	gtk_signal_connect(GTK_OBJECT(button), "toggled", GTK_SIGNAL_FUNC(on_tgt_type_check_button_toggled), xml);
	
	button = glade_xml_get_widget(xml, "obj_check_button");
	gtk_signal_connect(GTK_OBJECT(button), "toggled", GTK_SIGNAL_FUNC(on_obj_check_button_toggled), xml);

	return 0;
}

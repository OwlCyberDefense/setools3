/**
 *  @file
 *  Implementation of policy viewer.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include <config.h>

#include "policy_view.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <apol/policy-query.h>
#include <apol/util.h>
#include <glade/glade.h>
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include <seaudit/avc_message.h>

/* these are for mmaping the policy file */
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

struct policy_view
{
	toplevel_t *top;
	GladeXML *xml;
	GtkWindow *window;
	GtkNotebook *notebook;
	GtkToggleButton *stype_check, *ttype_check, *class_check;
	GtkComboBoxEntry *stype_combo, *ttype_combo, *class_combo;
	GtkToggleButton *stype_direct, *ttype_direct;
	GtkListStore *type_model, *class_model;
	apol_vector_t *type_list, *class_list;
	GtkTextBuffer *rules_text, *policy_text;
	char *policy_text_mmap;
	size_t policy_text_len;
};

/**
 * Display a vector of rules (either qpol_avrule_t or
 * qpol_syn_avrule_t) in the rules text buffer.
 */
static void policy_view_display_avrule_results(policy_view_t * pv, apol_vector_t * results, int is_syn_rules)
{
	apol_policy_t *policy = toplevel_get_policy(pv->top);
	qpol_policy_t *qp = apol_policy_get_qpol(policy);
	GtkTextIter start, end;
	char *string, buf[64];
	size_t i;

	gtk_text_buffer_get_start_iter(pv->rules_text, &start);
	gtk_text_buffer_get_end_iter(pv->rules_text, &end);
	gtk_text_buffer_delete(pv->rules_text, &start, &end);

	snprintf(buf, 64, "%zd rule(s) match the search criteria.\n\n", apol_vector_get_size(results));
	gtk_text_buffer_insert_with_tags_by_name(pv->rules_text, &end, buf, -1, "summary", NULL);
	for (i = 0; i < apol_vector_get_size(results); i++) {
		if (!is_syn_rules) {
			qpol_avrule_t *rule = apol_vector_get_element(results, i);
			string = apol_avrule_render(policy, rule);
		} else {
			qpol_syn_avrule_t *rule = apol_vector_get_element(results, i);
			string = apol_syn_avrule_render(policy, rule);
			unsigned long lineno;
			if (qpol_policy_has_capability(qp, QPOL_CAP_LINE_NUMBERS)) {
				qpol_syn_avrule_get_lineno(qp, rule, &lineno);
				sprintf(buf, "%ld", lineno);
				gtk_text_buffer_insert_with_tags_by_name(pv->rules_text, &end, "[", -1, "rule", NULL);
				gtk_text_buffer_insert_with_tags_by_name(pv->rules_text, &end, buf, -1, "line-number", NULL);
				gtk_text_buffer_insert_with_tags_by_name(pv->rules_text, &end, "] ", -1, "rule", NULL);
			}
		}
		if (string == NULL) {
			toplevel_ERR(pv->top, "Error displaying rule: %s", strerror(errno));
			return;
		}
		gtk_text_buffer_insert_with_tags_by_name(pv->rules_text, &end, string, -1, "rule", NULL);
		free(string);
		gtk_text_buffer_insert(pv->rules_text, &end, "\n", -1);
	}
}

struct find_terules_datum
{
	apol_policy_t *policy;
	apol_avrule_query_t *query;
	apol_vector_t *results;
	int is_syn_rules, retval;
	progress_t *progress;
};

/**
 * Perform the rule query within a thread.
 */
static gpointer policy_view_find_terules_runner(gpointer data)
{
	struct find_terules_datum *run = (struct find_terules_datum *)data;
	run->results = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(run->policy);
	if (!qpol_policy_has_capability(q, QPOL_CAP_SYN_RULES)) {
		progress_update(run->progress, "Searching AV rules");
		run->retval = apol_avrule_get_by_query(run->policy, run->query, &run->results);
		run->is_syn_rules = 0;
	} else {
		qpol_policy_build_syn_rule_table(q);
		progress_update(run->progress, "Searching syntactic AV rules");
		run->retval = apol_syn_avrule_get_by_query(run->policy, run->query, &run->results);
		run->is_syn_rules = 1;
	}
	if (run->retval == 0) {
		progress_done(run->progress);
	} else {
		progress_abort(run->progress, NULL);
	}
	return NULL;
}

/**
 * Collect the rule search criteria into an avrule_query_t object.
 * Actually execute the query in a progress thread.
 */
static void policy_view_on_find_terules_click(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	policy_view_t *pv = (policy_view_t *) user_data;
	apol_policy_t *policy = toplevel_get_policy(pv->top);
	apol_avrule_query_t *query = apol_avrule_query_create();
	apol_avrule_query_set_regex(policy, query, 1);
	struct find_terules_datum run;
	const char *s;
	gboolean only_direct;
	apol_avrule_query_set_rules(policy, query, QPOL_RULE_ALLOW);
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pv->stype_check))) {
		s = util_combo_box_get_active_text(GTK_COMBO_BOX(pv->stype_combo));
		only_direct = gtk_toggle_button_get_active(pv->stype_direct);
		if (strcmp(s, "") == 0) {
			toplevel_ERR(pv->top, "No source type was selected.");
			return;
		}
		apol_avrule_query_set_source(policy, query, s, only_direct == FALSE);
		apol_avrule_query_set_source_component(policy, query, APOL_QUERY_SYMBOL_IS_TYPE);
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pv->ttype_check))) {
		s = util_combo_box_get_active_text(GTK_COMBO_BOX(pv->ttype_combo));
		only_direct = gtk_toggle_button_get_active(pv->ttype_direct);
		if (strcmp(s, "") == 0) {
			toplevel_ERR(pv->top, "No target type was selected.");
			return;
		}
		apol_avrule_query_set_target(policy, query, s, only_direct == FALSE);
		apol_avrule_query_set_source_component(policy, query, APOL_QUERY_SYMBOL_IS_TYPE);
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(pv->class_check))) {
		s = util_combo_box_get_active_text(GTK_COMBO_BOX(pv->class_combo));
		if (strcmp(s, "") == 0) {
			toplevel_ERR(pv->top, "No object class was selected.");
			return;
		}
		apol_avrule_query_append_class(policy, query, s);
	}

	util_cursor_wait(GTK_WIDGET(pv->window));
	run.policy = policy;
	run.query = query;
	run.progress = toplevel_get_progress(pv->top);
	progress_show(run.progress, "Finding TE Rules");
	g_thread_create(policy_view_find_terules_runner, &run, FALSE, NULL);
	progress_wait(run.progress);
	progress_hide(run.progress);
	util_cursor_clear(GTK_WIDGET(pv->window));
	apol_avrule_query_destroy(&query);
	if (run.retval == 0) {
		policy_view_display_avrule_results(pv, run.results, run.is_syn_rules);
	}
	apol_vector_destroy(&run.results);
}

static void policy_view_close(GtkButton * button __attribute__ ((unused)), gpointer user_data)
{
	policy_view_t *pv = (policy_view_t *) user_data;
	gtk_widget_hide(GTK_WIDGET(pv->window));
}

static gboolean policy_view_on_delete_event(GtkWidget * widget, GdkEvent * event __attribute__ ((unused)), gpointer user_data
					    __attribute__ ((unused)))
{
	gtk_widget_hide(widget);
	return TRUE;
}

static void policy_view_on_stype_toggle(GtkToggleButton * toggle, gpointer user_data)
{
	gboolean sens = gtk_toggle_button_get_active(toggle);
	policy_view_t *pv = (policy_view_t *) user_data;
	gtk_widget_set_sensitive(GTK_WIDGET(pv->stype_combo), sens);
	gtk_widget_set_sensitive(GTK_WIDGET(pv->stype_direct), sens);
}

static void policy_view_on_ttype_toggle(GtkToggleButton * toggle, gpointer user_data)
{
	gboolean sens = gtk_toggle_button_get_active(toggle);
	policy_view_t *pv = (policy_view_t *) user_data;
	gtk_widget_set_sensitive(GTK_WIDGET(pv->ttype_combo), sens);
	gtk_widget_set_sensitive(GTK_WIDGET(pv->ttype_direct), sens);
}

static void policy_view_on_class_toggle(GtkToggleButton * toggle, gpointer user_data)
{
	gboolean sens = gtk_toggle_button_get_active(toggle);
	policy_view_t *pv = (policy_view_t *) user_data;
	gtk_widget_set_sensitive(GTK_WIDGET(pv->class_combo), sens);

}

static gboolean policy_view_on_line_event(GtkTextTag * tag
					  __attribute__ ((unused)), GObject * event_object
					  __attribute__ ((unused)), GdkEvent * event, const GtkTextIter * iter, gpointer user_data)
{
	policy_view_t *pv = (policy_view_t *) user_data;
	GtkTextIter start, end;
	int line;
	GtkTextView *view;
	if (event->type != GDK_BUTTON_PRESS) {
		return FALSE;
	}
	start = *iter;
	while (!gtk_text_iter_starts_word(&start))
		gtk_text_iter_backward_char(&start);
	end = start;
	while (!gtk_text_iter_ends_word(&end))
		gtk_text_iter_forward_char(&end);
	/* subtract 1 because text buffers are indexed from 0 */
	line = atoi(gtk_text_iter_get_slice(&start, &end)) - 1;
	view = GTK_TEXT_VIEW(glade_xml_get_widget(pv->xml, "PolicyWindowPolicyText"));
	assert(view != NULL);
	gtk_notebook_set_current_page(pv->notebook, 1);
	gtk_text_buffer_get_start_iter(pv->policy_text, &start);
	gtk_text_iter_set_line(&start, line);
	gtk_text_view_scroll_to_iter(view, &start, 0.0001, TRUE, 0.0, 0.5);
	gtk_text_buffer_place_cursor(pv->policy_text, &start);
	gtk_text_view_set_cursor_visible(view, TRUE);
	return TRUE;
}

static gboolean policy_view_on_rules_motion(GtkWidget * widget, GdkEventMotion * event, gpointer user_data __attribute__ ((unused)))
{
	GtkTextView *textview = GTK_TEXT_VIEW(widget);
	gint x, ex, y, ey;
	GtkTextIter iter;
	GSList *tags, *tagp;
	int hovering = 0;
	if (event->is_hint) {
		gdk_window_get_pointer(event->window, &ex, &ey, NULL);
	} else {
		ex = event->x;
		ey = event->y;
	}
	gtk_text_view_window_to_buffer_coords(textview, GTK_TEXT_WINDOW_WIDGET, ex, ey, &x, &y);
	gtk_text_view_get_iter_at_location(textview, &iter, x, y);
	tags = gtk_text_iter_get_tags(&iter);
	for (tagp = tags; tagp != NULL; tagp = tagp->next) {
		if (strcmp(GTK_TEXT_TAG(tagp->data)->name, "line-number") == 0) {
			hovering = TRUE;
			break;
		}
	}
	if (hovering) {
		GdkCursor *cursor = gdk_cursor_new(GDK_HAND2);
		gdk_window_set_cursor(event->window, cursor);
		gdk_cursor_unref(cursor);
		gdk_flush();
	} else {
		gdk_window_set_cursor(event->window, NULL);
	}
	g_slist_free(tags);
	return FALSE;
}

/**
 * Create a text buffer to hold the results of running the TE rules
 * search.  Initialize its tags and add event handlers to the
 * "line-number" tag, such that clicking on the tag jumps to the
 * policy's line and hovering over the tag changes the cursor.
 */
static void policy_view_create_rules_buffer(policy_view_t * pv)
{
	GtkTextView *rules_textview;
	GtkTextTagTable *table;
	GtkTextTag *tag;
	rules_textview = GTK_TEXT_VIEW(glade_xml_get_widget(pv->xml, "PolicyWindowTERulesResults"));
	assert(rules_textview != NULL);
	pv->rules_text = gtk_text_buffer_new(NULL);
	gtk_text_view_set_buffer(rules_textview, pv->rules_text);
	table = gtk_text_buffer_get_tag_table(pv->rules_text);
	gtk_text_buffer_create_tag(pv->rules_text, "summary", "family", "monospace", "weight", "bold", NULL);
	tag = gtk_text_buffer_create_tag(pv->rules_text, "line-number",
					 "family", "monospace", "foreground", "blue", "underline", PANGO_UNDERLINE_SINGLE, NULL);
	g_signal_connect(G_OBJECT(tag), "event", G_CALLBACK(policy_view_on_line_event), pv);
	g_signal_connect(rules_textview, "motion-notify-event", G_CALLBACK(policy_view_on_rules_motion), NULL);
	gtk_text_buffer_create_tag(pv->rules_text, "rule", "family", "monospace", NULL);
}

policy_view_t *policy_view_create(toplevel_t * top)
{
	GtkWidget *w;
	GtkTextView *policy_textview;
	policy_view_t *pv;
	if ((pv = calloc(1, sizeof(*pv))) == NULL) {
		return NULL;
	}
	pv->top = top;
	pv->xml = glade_xml_new(toplevel_get_glade_xml(top), "PolicyWindow", NULL);
	pv->window = GTK_WINDOW(glade_xml_get_widget(pv->xml, "PolicyWindow"));
	assert(pv->window != NULL);
	gtk_window_set_transient_for(pv->window, toplevel_get_window(top));
	pv->notebook = GTK_NOTEBOOK(glade_xml_get_widget(pv->xml, "PolicyWindowNotebook"));
	assert(pv->notebook != NULL);

	pv->stype_check = GTK_TOGGLE_BUTTON(glade_xml_get_widget(pv->xml, "PolicyWindowSTypeCheck"));
	pv->ttype_check = GTK_TOGGLE_BUTTON(glade_xml_get_widget(pv->xml, "PolicyWindowTTypeCheck"));
	pv->class_check = GTK_TOGGLE_BUTTON(glade_xml_get_widget(pv->xml, "PolicyWindowClassCheck"));
	assert(pv->stype_check != NULL && pv->ttype_check != NULL && pv->class_check != NULL);
	g_signal_connect(pv->stype_check, "toggled", G_CALLBACK(policy_view_on_stype_toggle), pv);
	g_signal_connect(pv->ttype_check, "toggled", G_CALLBACK(policy_view_on_ttype_toggle), pv);
	g_signal_connect(pv->class_check, "toggled", G_CALLBACK(policy_view_on_class_toggle), pv);

	pv->stype_combo = GTK_COMBO_BOX_ENTRY(glade_xml_get_widget(pv->xml, "PolicyWindowSTypeCombo"));
	pv->ttype_combo = GTK_COMBO_BOX_ENTRY(glade_xml_get_widget(pv->xml, "PolicyWindowTTypeCombo"));
	pv->class_combo = GTK_COMBO_BOX_ENTRY(glade_xml_get_widget(pv->xml, "PolicyWindowClassCombo"));
	assert(pv->stype_combo != NULL && pv->ttype_combo != NULL && pv->class_combo != NULL);
	pv->type_model = gtk_list_store_new(1, G_TYPE_STRING);
	pv->class_model = gtk_list_store_new(1, G_TYPE_STRING);
	gtk_combo_box_set_model(GTK_COMBO_BOX(pv->stype_combo), GTK_TREE_MODEL(pv->type_model));
	gtk_combo_box_set_model(GTK_COMBO_BOX(pv->ttype_combo), GTK_TREE_MODEL(pv->type_model));
	gtk_combo_box_set_model(GTK_COMBO_BOX(pv->class_combo), GTK_TREE_MODEL(pv->class_model));
	gtk_combo_box_entry_set_text_column(pv->stype_combo, 0);
	gtk_combo_box_entry_set_text_column(pv->ttype_combo, 0);
	gtk_combo_box_entry_set_text_column(pv->class_combo, 0);

	pv->stype_direct = GTK_TOGGLE_BUTTON(glade_xml_get_widget(pv->xml, "PolicyWindowSTypeDirectCheck"));
	pv->ttype_direct = GTK_TOGGLE_BUTTON(glade_xml_get_widget(pv->xml, "PolicyWindowTTypeDirectCheck"));
	assert(pv->stype_direct != NULL && pv->ttype_direct != NULL);

	policy_view_create_rules_buffer(pv);

	policy_textview = GTK_TEXT_VIEW(glade_xml_get_widget(pv->xml, "PolicyWindowPolicyText"));
	assert(policy_textview != NULL);
	pv->policy_text = gtk_text_buffer_new(NULL);
	gtk_text_view_set_buffer(policy_textview, pv->policy_text);

	/* set up signal handlers for the widgets */

	w = glade_xml_get_widget(pv->xml, "PolicyWindowFindTERulesButton");
	assert(w != NULL);
	g_signal_connect(w, "clicked", G_CALLBACK(policy_view_on_find_terules_click), pv);

	w = glade_xml_get_widget(pv->xml, "PolicyWindowCloseButton");
	assert(w != NULL);
	g_signal_connect(w, "clicked", G_CALLBACK(policy_view_close), pv);
	g_signal_connect(pv->window, "delete_event", G_CALLBACK(policy_view_on_delete_event), NULL);

	policy_view_update(pv, NULL);
	return pv;
}

void policy_view_destroy(policy_view_t ** pv)
{
	if (pv != NULL && *pv != NULL) {
		apol_vector_destroy(&(*pv)->type_list);
		apol_vector_destroy(&(*pv)->class_list);
		free(*pv);
		*pv = NULL;
	}
}

/**
 * If the currently loaded policy is a source policy, then load its
 * contents into the policy text buffer.  Otherwise let the user know
 * that the policy is binary.
 *
 * @param pv Policy view's policy source tab to update.
 * @param path Path to the currently loaded policy, or NULL if no
 * policy is loaded.
 */
static void policy_view_load_policy_source(policy_view_t * pv, apol_policy_path_t * path)
{
	apol_policy_t *policy = toplevel_get_policy(pv->top);
	const char *primary_path;
	if (path == NULL) {
		gtk_text_buffer_set_text(pv->policy_text, "No policy has been loaded.", -1);
		return;
	}
	primary_path = apol_policy_path_get_primary(path);
	if (!qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SOURCE)) {
		GString *string = g_string_new("");
		g_string_printf(string, "Policy file %s is not a source policy.", primary_path);
		gtk_text_buffer_set_text(pv->policy_text, string->str, -1);
		g_string_free(string, TRUE);
	} else {
		/*  load the policy by mmap()ing the file */
		struct stat statbuf;
		int fd;
		if (pv->policy_text_mmap != NULL) {
			munmap(pv->policy_text_mmap, pv->policy_text_len);
		}

		pv->policy_text_mmap = NULL;
		pv->policy_text_len = 0;

		if ((fd = open(primary_path, O_RDONLY)) < 0) {
			toplevel_ERR(pv->top, "Could not open %s for reading.", primary_path);
			return;
		}
		if (fstat(fd, &statbuf) < 0) {
			close(fd);
			toplevel_ERR(pv->top, "Could not stat %s.", primary_path);
			return;
		}

		pv->policy_text_len = statbuf.st_size;
		if ((pv->policy_text_mmap = mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
			close(fd);
			pv->policy_text_mmap = NULL;
			toplevel_ERR(pv->top, "Could not mmap %s.", primary_path);
			return;
		}
		close(fd);
		gtk_text_buffer_set_text(pv->policy_text, pv->policy_text_mmap, pv->policy_text_len);
	}
}

/**
 * If a policy is currently loaded then set the rule search combo box
 * menus to that policy's components.  Otherwies clear the combo box
 * menus.
 *
 * @param pv Policy view's rule search boxes to modify.
 */
static void policy_view_populate_combo_boxes(policy_view_t * pv)
{
	apol_policy_t *policy = toplevel_get_policy(pv->top);
	gtk_list_store_clear(pv->type_model);
	gtk_list_store_clear(pv->class_model);
	apol_vector_destroy(&pv->type_list);
	apol_vector_destroy(&pv->class_list);
	pv->type_list = apol_vector_create(NULL);
	pv->class_list = apol_vector_create(NULL);
	if (policy != NULL) {
		qpol_policy_t *qp = apol_policy_get_qpol(policy);
		size_t i;
		const qpol_type_t *type;
		const qpol_class_t *obj_class;
		const char *s;
		GtkTreeIter iter;
		apol_vector_t *v;
		apol_type_get_by_query(policy, NULL, &v);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			type = apol_vector_get_element(v, i);
			qpol_type_get_name(qp, type, &s);
			apol_vector_append(pv->type_list, (void *)s);
		}
		apol_vector_destroy(&v);
		apol_vector_sort(pv->type_list, apol_str_strcmp, NULL);
		for (i = 0; i < apol_vector_get_size(pv->type_list); i++) {
			s = apol_vector_get_element(pv->type_list, i);
#ifdef GTK_2_8
			gtk_list_store_insert_with_values(pv->type_model, &iter, i, 0, s, -1);
#else
			gtk_list_store_insert(pv->type_model, &iter, i);
			gtk_list_store_set(pv->type_model, &iter, 0, s, -1);
#endif
		}
		apol_class_get_by_query(policy, NULL, &v);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			obj_class = apol_vector_get_element(v, i);
			qpol_class_get_name(qp, obj_class, &s);
			apol_vector_append(pv->class_list, (void *)s);
		}
		apol_vector_destroy(&v);
		apol_vector_sort(pv->class_list, apol_str_strcmp, NULL);
		for (i = 0; i < apol_vector_get_size(pv->class_list); i++) {
			s = apol_vector_get_element(pv->class_list, i);
#ifdef GTK_2_8
			gtk_list_store_insert_with_values(pv->class_model, &iter, i, 0, s, -1);
#else
			gtk_list_store_insert(pv->class_model, &iter, i);
			gtk_list_store_set(pv->class_model, &iter, 0, s, -1);
#endif
		}
	}
}

void policy_view_update(policy_view_t * pv, apol_policy_path_t * path)
{
	GtkTextIter start, end;
	policy_view_load_policy_source(pv, path);
	policy_view_populate_combo_boxes(pv);
	gtk_text_buffer_get_start_iter(pv->rules_text, &start);
	gtk_text_buffer_get_end_iter(pv->rules_text, &end);
	gtk_text_buffer_delete(pv->rules_text, &start, &end);

}

void policy_view_find_terules(policy_view_t * pv, seaudit_message_t * message)
{
	seaudit_message_type_e type = SEAUDIT_MESSAGE_TYPE_INVALID;
	void *data = NULL;
	const char *stype = "", *ttype = "", *obj_class = "";
	size_t i;
	assert(pv->type_list != NULL);
	assert(pv->class_list != NULL);
	if (message != NULL) {
		data = seaudit_message_get_data(message, &type);
	}
	if (type == SEAUDIT_MESSAGE_TYPE_AVC) {
		seaudit_avc_message_t *avc = data;
		if ((stype = seaudit_avc_message_get_source_type(avc)) == NULL) {
			stype = "";
		}
		if ((ttype = seaudit_avc_message_get_target_type(avc)) == NULL) {
			ttype = "";
		}
		if ((obj_class = seaudit_avc_message_get_object_class(avc)) == NULL) {
			obj_class = "";
		}
	}
	if (strcmp(stype, "") == 0 || apol_vector_get_index(pv->type_list, stype, apol_str_strcmp, NULL, &i) < 0) {
		gtk_combo_box_set_active(GTK_COMBO_BOX(pv->stype_combo), -1);
		gtk_toggle_button_set_active(pv->stype_check, FALSE);
	} else {
		gtk_combo_box_set_active(GTK_COMBO_BOX(pv->stype_combo), i);
		gtk_toggle_button_set_active(pv->stype_check, TRUE);
	}
	if (strcmp(ttype, "") == 0 || apol_vector_get_index(pv->type_list, ttype, apol_str_strcmp, NULL, &i) < 0) {
		gtk_combo_box_set_active(GTK_COMBO_BOX(pv->ttype_combo), -1);
		gtk_toggle_button_set_active(pv->ttype_check, FALSE);
	} else {
		gtk_combo_box_set_active(GTK_COMBO_BOX(pv->ttype_combo), i);
		gtk_toggle_button_set_active(pv->ttype_check, TRUE);
	}
	if (strcmp(obj_class, "") == 0 || apol_vector_get_index(pv->class_list, obj_class, apol_str_strcmp, NULL, &i) < 0) {
		gtk_combo_box_set_active(GTK_COMBO_BOX(pv->class_combo), -1);
		gtk_toggle_button_set_active(pv->class_check, FALSE);
	} else {
		gtk_combo_box_set_active(GTK_COMBO_BOX(pv->class_combo), i);
		gtk_toggle_button_set_active(pv->class_check, TRUE);
	}
	gtk_notebook_set_current_page(pv->notebook, 0);
	gtk_widget_show(GTK_WIDGET(pv->window));
}

/**
 *  @file sediff_policy_open.c
 *  Routines are responsible for loading the two policies, calculating
 *  their statistics, and displaying their source.
 *
 *  @author Don Patterson don.patterson@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

#include <config.h>

#include "sediff_gui.h"
#include "sediff_progress.h"
#include "utilgui.h"

#include <apol/policy-query.h>
#include <apol/util.h>

#include <assert.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

extern sediff_app_t *sediff_app;

static void sediff_main_window_remap_policy_tabs(GString * p1, GString * p2)
{
	const char *fname1;
	const char *fname2;
	GtkNotebook *notebook;
	GtkWidget *p1_label, *p2_label;
	GString *string = g_string_new("");

	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));

	if (p1 == NULL || p1->str == NULL) {
		p1_label = gtk_label_new("Policy 1");
		gtk_widget_show(p1_label);
		gtk_notebook_set_tab_label(notebook, gtk_notebook_get_nth_page(notebook, 1), p1_label);
	} else if (rindex(p1->str, '/')) {
		fname1 = (char *)rindex(p1->str, '/') + 1;
		g_string_printf(string, "Policy 1: %s", fname1);
		p1_label = gtk_label_new(string->str);
		gtk_widget_show(p1_label);
		gtk_notebook_set_tab_label(notebook, gtk_notebook_get_nth_page(notebook, 1), p1_label);
	}

	if (p2 == NULL || p2->str == NULL) {
		p2_label = gtk_label_new("Policy 2");
		gtk_widget_show(p2_label);
		gtk_notebook_set_tab_label(notebook, gtk_notebook_get_nth_page(notebook, 2), p2_label);
	} else if (rindex(p2->str, '/')) {
		fname2 = (char *)rindex(p2->str, '/') + 1;
		g_string_printf(string, "Policy 2: %s", fname2);
		p2_label = gtk_label_new(string->str);
		gtk_widget_show(p2_label);
		gtk_notebook_set_tab_label(notebook, gtk_notebook_get_nth_page(notebook, 2), p2_label);
	}
	g_string_free(string, TRUE);
}

void sediff_set_open_policies_gui_state(gboolean is_open)
{
	GtkWidget *widget = NULL;

	widget = glade_xml_get_widget(sediff_app->window_xml, "toolbutton_remap_types");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, is_open);
	widget = glade_xml_get_widget(sediff_app->window_xml, "toolbutton_run_diff");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, is_open);
	widget = glade_xml_get_widget(sediff_app->window_xml, "menu_remap_types");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, is_open);
	widget = glade_xml_get_widget(sediff_app->window_xml, "menu_run_diff");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, is_open);
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_menu_find");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, is_open);
	sediff_main_window_remap_policy_tabs(sediff_app->p1_sfd.name, sediff_app->p2_sfd.name);
}

static void sediff_policy_stats_textview_populate(apol_policy_t * p, GtkTextView * textview, const char *filename)
{
	GtkTextBuffer *txt;
	GtkTextIter iter;
	gchar *contents = NULL;
	char *tmp = NULL;
	size_t num_classes = 0,
		num_commons = 0,
		num_perms = 0,
		num_types = 0,
		num_attribs = 0,
		num_allow = 0,
		num_neverallow = 0,
		num_type_trans = 0,
		num_type_change = 0,
		num_auditallow = 0,
		num_dontaudit = 0, num_roles = 0, num_roleallow = 0, num_role_trans = 0, num_users = 0, num_bools = 0;
	apol_vector_t *vec = NULL;
	qpol_iterator_t *i = NULL;

	/* grab the text buffer for our tree_view */
	txt = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
	sediff_clear_text_buffer(txt);

	/* set some variables up */
	gtk_text_view_set_editable(GTK_TEXT_VIEW(textview), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(textview), FALSE);

	contents = g_strdup_printf("Filename: %s\n"
				   "Policy Version & Type: %s\n", filename, (tmp = apol_policy_get_version_type_mls_str(p)));
	free(tmp);
	tmp = NULL;
	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert(txt, &iter, contents, -1);
	g_free(contents);

	apol_class_get_by_query(p, NULL, &vec);
	num_classes = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	apol_common_get_by_query(p, NULL, &vec);
	num_commons = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	apol_perm_get_by_query(p, NULL, &vec);
	num_perms = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	contents = g_strdup_printf("\nNumber of Classes and Permissions:\n"
				   "\tObject Classes: %d\n"
				   "\tCommon Classes: %d\n" "\tPermissions: %d\n", num_classes, num_commons, num_perms);
	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert(txt, &iter, contents, -1);
	g_free(contents);

	apol_type_get_by_query(p, NULL, &vec);
	num_types = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	apol_attr_get_by_query(p, NULL, &vec);
	num_attribs = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	contents = g_strdup_printf("\nNumber of Types and Attributes:\n"
				   "\tTypes: %d\n" "\tAttributes: %d\n", num_types, num_attribs);
	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert(txt, &iter, contents, -1);
	g_free(contents);

	qpol_policy_get_avrule_iter(p->p, QPOL_RULE_ALLOW, &i);
	qpol_iterator_get_size(i, &num_allow);
	qpol_iterator_destroy(&i);

	qpol_policy_get_avrule_iter(p->p, QPOL_RULE_NEVERALLOW, &i);
	qpol_iterator_get_size(i, &num_neverallow);
	qpol_iterator_destroy(&i);

	qpol_policy_get_avrule_iter(p->p, QPOL_RULE_AUDITALLOW, &i);
	qpol_iterator_get_size(i, &num_auditallow);
	qpol_iterator_destroy(&i);

	qpol_policy_get_avrule_iter(p->p, QPOL_RULE_DONTAUDIT, &i);
	qpol_iterator_get_size(i, &num_dontaudit);
	qpol_iterator_destroy(&i);

	qpol_policy_get_terule_iter(p->p, QPOL_RULE_TYPE_TRANS, &i);
	qpol_iterator_get_size(i, &num_type_trans);
	qpol_iterator_destroy(&i);

	qpol_policy_get_terule_iter(p->p, QPOL_RULE_TYPE_CHANGE, &i);
	qpol_iterator_get_size(i, &num_type_change);
	qpol_iterator_destroy(&i);

	contents = g_strdup_printf("\nNumber of Type Enforcement Rules:\n"
				   "\tallow: %d\n"
				   "\tneverallow: %d\n"
				   "\ttype_transition: %d\n"
				   "\ttype_change: %d\n"
				   "\tauditallow: %d\n"
				   "\tdontaudit %d\n",
				   num_allow, num_neverallow, num_type_trans, num_type_change, num_auditallow, num_dontaudit);
	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert(txt, &iter, contents, -1);
	g_free(contents);

	apol_role_get_by_query(p, NULL, &vec);
	num_roles = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	qpol_policy_get_role_allow_iter(p->p, &i);
	qpol_iterator_get_size(i, &num_roleallow);
	qpol_iterator_destroy(&i);

	qpol_policy_get_role_trans_iter(p->p, &i);
	qpol_iterator_get_size(i, &num_roleallow);
	qpol_iterator_destroy(&i);

	contents = g_strdup_printf("\nNumber of Roles: %d\n"
				   "\nNumber of RBAC Rules:\n"
				   "\tallow: %d\n" "\trole_transition %d\n", num_roles, num_roleallow, num_role_trans);
	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert(txt, &iter, contents, -1);
	g_free(contents);

	apol_user_get_by_query(p, NULL, &vec);
	num_users = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	apol_bool_get_by_query(p, NULL, &vec);
	num_bools = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	contents = g_strdup_printf("\nNumber of Users: %d\n" "\nNumber of Booleans: %d\n", num_users, num_bools);
	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert(txt, &iter, contents, -1);
	g_free(contents);
}

int sediff_policy_file_textview_populate(sediff_file_data_t * sfd, GtkTextView * textview, apol_policy_t * policy)
{
	GtkTextBuffer *txt;
	GtkTextIter iter;
	gchar *contents = NULL;
	GString *string;
	GtkTextTag *mono_tag = NULL;
	GtkTextTagTable *table = NULL;

	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));

	table = gtk_text_buffer_get_tag_table(txt);
	mono_tag = gtk_text_tag_table_lookup(table, "mono-tag");
	if (!mono_tag) {
		mono_tag = gtk_text_buffer_create_tag(txt, "mono-tag",
						      "style", PANGO_STYLE_NORMAL,
						      "weight", PANGO_WEIGHT_NORMAL, "family", "monospace", NULL);
	}
	sediff_clear_text_buffer(txt);
	gtk_text_buffer_get_end_iter(txt, &iter);

	/* set some variables up */
	gtk_text_view_set_editable(GTK_TEXT_VIEW(textview), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(textview), TRUE);

	/* if this is not a binary policy */
	if (!apol_policy_is_binary(policy) && sfd->data) {
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, sfd->data, sfd->size, "mono-tag", NULL);
		gtk_text_buffer_set_modified(txt, TRUE);
		g_free(contents);
	} else {
		string = g_string_new("");
		g_string_printf(string, "Policy File %s is a binary policy", sfd->name->str);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "mono-tag", NULL);
		g_string_free(string, TRUE);
	}

	return 0;
}

void sediff_open_dialog_on_p1browse_button_clicked(GtkButton * button, gpointer user_data)
{
	GtkEntry *entry = NULL;
	GString *filename = NULL;
	GtkEntry *entry2 = NULL;

	entry = (GtkEntry *) glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry");
	entry2 = (GtkEntry *) glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry");

	g_assert(entry);

	if ((g_ascii_strcasecmp(gtk_entry_get_text(entry), "") == 0) && (g_ascii_strcasecmp(gtk_entry_get_text(entry2), "") != 0))
		filename = get_filename_from_user(sediff_app->open_dlg, "Open Policy", gtk_entry_get_text(entry2));
	else
		filename = get_filename_from_user(sediff_app->open_dlg, "Open Policy", gtk_entry_get_text(entry));
	if (filename) {
		gtk_entry_set_text(entry, filename->str);
	}
}

void sediff_open_dialog_on_p2browse_button_clicked(GtkButton * button, gpointer user_data)
{
	GtkEntry *entry = NULL;
	GString *filename = NULL;
	GtkEntry *entry1 = NULL;

	entry = (GtkEntry *) glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry");
	entry1 = (GtkEntry *) glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry");

	g_assert(entry);
	if ((g_ascii_strcasecmp(gtk_entry_get_text(entry), "") == 0) && (g_ascii_strcasecmp(gtk_entry_get_text(entry1), "") != 0))
		filename = get_filename_from_user(sediff_app->open_dlg, "Open Policy", gtk_entry_get_text(entry1));
	else
		filename = get_filename_from_user(sediff_app->open_dlg, "Open Policy", gtk_entry_get_text(entry));
	if (filename) {
		gtk_entry_set_text(entry, filename->str);
	}
}

void sediff_open_dialog_on_window_destroy(GtkWidget * widget, GdkEvent * event, gpointer user_data)
{
	gtk_widget_destroy(widget);
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;
}

void sediff_open_dialog_on_cancel_button_clicked(GtkButton * button, gpointer user_data)
{
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;
}

void sediff_open_button_clicked(void)
{
	GtkEntry *entry = NULL;
	char *dir;
	GString *path;

	if (sediff_app->open_dlg) {
		gtk_window_set_position(sediff_app->open_dlg, GTK_WIN_POS_CENTER_ON_PARENT);
		gtk_window_present(GTK_WINDOW(sediff_app->open_dlg));
	} else {
		dir = apol_file_find(GLADEFILE);
		if (!dir) {
			fprintf(stderr, "Could not find %s!", GLADEFILE);
			return;
		}

		path = g_string_new(dir);
		free(dir);
		g_string_append_printf(path, "/%s", GLADEFILE);

		sediff_app->open_dlg_xml = glade_xml_new(path->str, OPEN_DIALOG_ID, NULL);
		g_assert(sediff_app->open_dlg_xml != NULL);
		sediff_app->open_dlg = GTK_WINDOW(glade_xml_get_widget(sediff_app->open_dlg_xml, OPEN_DIALOG_ID));
		g_assert(sediff_app->open_dlg);
		gtk_window_set_transient_for(GTK_WINDOW(sediff_app->open_dlg), sediff_app->window);
		gtk_window_set_position(GTK_WINDOW(sediff_app->open_dlg), GTK_WIN_POS_CENTER_ON_PARENT);

		if (sediff_app->p1_sfd.name) {
			entry = GTK_ENTRY(glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry"));
			gtk_entry_set_text(entry, sediff_app->p1_sfd.name->str);
		}
		if (sediff_app->p2_sfd.name) {
			entry = GTK_ENTRY(glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry"));
			gtk_entry_set_text(entry, sediff_app->p2_sfd.name->str);
		}
		g_signal_connect(G_OBJECT(sediff_app->open_dlg), "delete_event",
				 G_CALLBACK(sediff_open_dialog_on_window_destroy), sediff_app);
		glade_xml_signal_autoconnect(sediff_app->open_dlg_xml);
	}
}

void sediff_on_policy1_notebook_event_after(GtkWidget * widget, GdkEvent * event, gpointer user_data)
{
	GtkNotebook *notebook = (GtkNotebook *) user_data;
	GtkLabel *label = NULL;
	guint pagenum;
	GtkTextMark *mark = NULL;
	GtkTextBuffer *txt = NULL;
	GtkTextIter iter;
	GtkTextView *p1_textview = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");

	pagenum = gtk_notebook_get_current_page(notebook);
	txt = gtk_text_view_get_buffer(p1_textview);
	assert(txt);
	sediff_find_window_reset_idx(sediff_app->find_window);
	if (pagenum == 0) {
		label = (GtkLabel *) glade_xml_get_widget(sediff_app->window_xml, "line_label");
		gtk_label_set_text(label, "");
	} else if (gtk_text_buffer_get_modified(txt)) {
		g_assert(p1_textview);
		GString *string = g_string_new("");
		mark = gtk_text_buffer_get_insert(txt);
		if (mark != NULL) {
			gtk_text_buffer_get_iter_at_mark(txt, &iter, mark);
			g_string_printf(string, "Line: %d", gtk_text_iter_get_line(&iter) + 1);
			label = (GtkLabel *) glade_xml_get_widget(sediff_app->window_xml, "line_label");
			gtk_label_set_text(label, string->str);
		}
		g_string_free(string, TRUE);
	}
}

void sediff_on_policy2_notebook_event_after(GtkWidget * widget, GdkEvent * event, gpointer user_data)
{
	GtkLabel *label = NULL;
	guint pagenum;
	GtkTextMark *mark = NULL;
	GtkTextBuffer *txt = NULL;
	GtkTextIter iter;
	GtkTextView *p2_textview;

	p2_textview = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text"));
	assert(p2_textview);
	pagenum = gtk_notebook_get_current_page(GTK_NOTEBOOK(user_data));
	txt = gtk_text_view_get_buffer(p2_textview);
	assert(txt);
	sediff_find_window_reset_idx(sediff_app->find_window);
	if (pagenum == 0) {
		label = (GtkLabel *) glade_xml_get_widget(sediff_app->window_xml, "line_label");
		gtk_label_set_text(label, "");
	} else if (gtk_text_buffer_get_modified(txt)) {
		g_assert(p2_textview);
		GString *string = g_string_new("");
		mark = gtk_text_buffer_get_insert(txt);
		if (mark != NULL) {
			gtk_text_buffer_get_iter_at_mark(txt, &iter, mark);
			g_string_printf(string, "Line: %d", gtk_text_iter_get_line(&iter) + 1);
			label = (GtkLabel *) glade_xml_get_widget(sediff_app->window_xml, "line_label");
			gtk_label_set_text(label, string->str);
		}
		g_string_free(string, TRUE);
	}
}

void sediff_reset_policy_notebooks()
{
	GtkNotebook *nb = NULL;
	nb = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook1"));
	assert(nb);
	gtk_notebook_set_current_page(nb, 0);
	nb = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook2"));
	assert(nb);
	gtk_notebook_set_current_page(nb, 0);

}

/* file_data should be a char ** that can be assigned to the data
 * allocated by mmap, size should be a preallocated int that we can
 * put the size of data into will also clear out any existing data
 * from file_data.  Will return 0 after clearing out data if file is
 * binary
 */
static int sediff_file_mmap(const char *file, char **file_data, size_t * size, apol_policy_t * policy)
{
	struct stat statbuf;
	int rt;

	/* clear out any old data */
	if (*file_data)
		munmap(*file_data, *size);

	*file_data = NULL;
	*size = 0;

	/* if this is a binary policy just return now
	 * but this is not an error */
	if (apol_policy_is_binary(policy))
		return 0;

	rt = open(file, O_RDONLY);
	if (rt < 0)
		return -1;
	if (fstat(rt, &statbuf) < 0) {
		close(rt);
		return -1;
	}

	*size = statbuf.st_size;
	if ((*file_data = mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, rt, 0)) == MAP_FAILED) {
		close(rt);
		return -1;
	}
	close(rt);
	return 0;
}

struct load_policy_datum
{
	const char *file;
	const char *which_pol;
	sediff_app_t *app;
	apol_policy_t *p;
};

static gpointer sediff_load_policy_runner(gpointer data)
{
	struct load_policy_datum *l = data;
	GString *string;
	int rt;
	unsigned int p_ver;
	sediff_progress_update(l->app, "Reading policy.");
	rt = apol_policy_open(l->file, &l->p, sediff_progress_apol_handle_func, l->app);
	if (rt != 0) {
		string = g_string_new("");
		g_string_printf(string, "Problem opening policy file: %s", l->file);
		sediff_progress_abort(l->app, string->str);
		g_string_free(string, TRUE);
		return NULL;
	}
	qpol_policy_get_policy_version(l->p->p, &p_ver);
	if (p_ver < 12) {
		string = g_string_new("");
		g_string_printf(string,
				"%s: Unsupported version: Supported versions are Source (12 and higher), Binary (15 and higher).",
				l->which_pol);
		sediff_progress_abort(l->app, string->str);
		g_string_free(string, TRUE);
		return NULL;
	}
	if (apol_policy_is_binary(l->p) && p_ver < 15) {
		string = g_string_new("");
		g_string_printf(string, "%s: Binary policies are only supported for version 15 or higher.", l->which_pol);
		sediff_progress_abort(l->app, string->str);
		g_string_free(string, TRUE);
		return NULL;
	}
	sediff_progress_done(l->app);
	return NULL;
}

/* opens p1 and p2, populates policy text buffers */
int sediff_load_policies(const char *p1_file, const char *p2_file)
{
	GtkTextView *p1_textview, *p2_textview, *stats1, *stats2;
	GdkCursor *cursor = NULL;
	GtkNotebook *notebook1, *notebook2;
	struct load_policy_datum l;

	/* set the cursor to a hourglass */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();

	sediff_initialize_policies();
	while (gtk_events_pending())
		gtk_main_iteration();

	/* attempt to open the policies */
	sediff_progress_show(sediff_app, "Loading Policy 1");
	l.file = p1_file;
	l.which_pol = "Policy 1";
	l.app = sediff_app;
	l.p = NULL;
	g_thread_create(sediff_load_policy_runner, &l, FALSE, NULL);
	if (sediff_progress_wait(sediff_app) < 0) {
		goto err;
	}
	sediff_app->orig_pol = l.p;
	sediff_progress_show(sediff_app, "Loading Policy 2");
	l.file = p2_file;
	l.which_pol = "Policy 2";
	l.app = sediff_app;
	l.p = NULL;
	g_thread_create(sediff_load_policy_runner, &l, FALSE, NULL);
	if (sediff_progress_wait(sediff_app) < 0) {
		goto err;
	}
	sediff_app->mod_pol = l.p;

	sediff_app->p1_sfd.name = g_string_new(p1_file);
	sediff_app->p2_sfd.name = g_string_new(p2_file);
	sediff_file_mmap(p1_file, &(sediff_app->p1_sfd.data), &(sediff_app->p1_sfd.size), sediff_app->orig_pol);
	sediff_file_mmap(p2_file, &(sediff_app->p2_sfd.data), &(sediff_app->p2_sfd.size), sediff_app->mod_pol);

	/* Grab the 2 policy textviews */
	p1_textview = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");
	g_assert(p1_textview);
	p2_textview = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text");
	g_assert(p2_textview);

	stats1 = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_stats_text");
	g_assert(stats1);
	stats2 = (GtkTextView *) glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_stats_text");
	g_assert(stats2);

	notebook1 = (GtkNotebook *) glade_xml_get_widget(sediff_app->window_xml, "notebook1");
	g_assert(notebook1);
	notebook2 = (GtkNotebook *) glade_xml_get_widget(sediff_app->window_xml, "notebook2");
	g_assert(notebook2);

	g_signal_connect_after(G_OBJECT(notebook1), "event-after", G_CALLBACK(sediff_on_policy1_notebook_event_after), notebook1);
	g_signal_connect_after(G_OBJECT(notebook2), "event-after", G_CALLBACK(sediff_on_policy2_notebook_event_after), notebook2);

	/* populate the 2 stat buffers */
	sediff_policy_stats_textview_populate(sediff_app->orig_pol, stats1, p1_file);
	sediff_policy_stats_textview_populate(sediff_app->mod_pol, stats2, p2_file);

	sediff_reset_policy_notebooks();
	sediff_app->diff = poldiff_create(sediff_app->orig_pol,
					  sediff_app->mod_pol, sediff_progress_poldiff_handle_func, sediff_app);
	if (sediff_app->diff == NULL) {
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, "Error creating differences.");
		goto err;
	}

	/* open is done set cursor back to a ptr */
	sediff_progress_hide(sediff_app);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, NULL);

	sediff_set_open_policies_gui_state(TRUE);
	sediff_initialize_diff();
	return 0;

      err:
	sediff_progress_hide(sediff_app);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, NULL);
	sediff_initialize_policies();
	sediff_initialize_diff();
	return -1;
}

/* open the files listed in the open_dialog */
int sediff_open_dialog_open_and_load_policies()
{
	const gchar *p1_file = NULL;
	const gchar *p2_file = NULL;
	GtkEntry *p1_entry;
	GtkEntry *p2_entry;

	GdkCursor *cursor = NULL;
	int rt;
	GString *string = NULL;

	/* grab the GtkEntry widgets so we can get their data */
	p1_entry = (GtkEntry *) glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry");
	p2_entry = (GtkEntry *) glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry");

	/* get the data */
	p1_file = gtk_entry_get_text(p1_entry);
	p2_file = gtk_entry_get_text(p2_entry);

	if (!g_file_test(p1_file, G_FILE_TEST_EXISTS) || g_file_test(p1_file, G_FILE_TEST_IS_DIR)) {
		string = g_string_new("Invalid file specified for policy 1!");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return -1;
	}
	if (!g_file_test(p2_file, G_FILE_TEST_EXISTS) || g_file_test(p2_file, G_FILE_TEST_IS_DIR)) {
		string = g_string_new("Invalid file specified for policy 2!");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return -1;
	}

	/* set the cursor to a hand */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();

	rt = sediff_load_policies((const char *)p1_file, (const char *)p2_file);

	/* load is done set cursor back to a ptr */
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();

	return rt;
}

void sediff_open_dialog_on_open_and_diff_button_clicked(GtkButton * button, gpointer user_data)
{
	GdkCursor *cursor = NULL;

	if (sediff_open_dialog_open_and_load_policies() < 0)
		return;

	/* destroy the no longer needed dialog widget */
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;

	/* set the cursor to a hand */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);

	run_diff_clicked();

	/* load is done set cursor back to a ptr */
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();
}

void sediff_open_dialog_on_open_button_clicked(GtkButton * button, gpointer user_data)
{
	sediff_open_dialog_open_and_load_policies();
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;
}

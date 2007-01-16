/**
 *  @file
 *  Routines are responsible calculating a policy's statistics and
 *  displaying its source.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
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

#include "policy_view.h"
#include "utilgui.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glade/glade.h>

struct policy_view
{
	toplevel_t *top;
	sediffx_policy_e which;
	GladeXML *xml;
	GtkTextBuffer *stats, *source;
	GtkTextView *stats_view, *source_view;
	GtkNotebook *notebook;
	GtkLabel *line_number;
	void *mmap_start;
	size_t mmap_length;
};

static const char *policy_view_widget_names[SEDIFFX_POLICY_NUM][3] = {
	{"toplevel policy_orig stats text", "toplevel policy_orig source text",
	 "toplevel policy_orig notebook"},
	{"toplevel policy_mod stats text", "toplevel policy_mod source text",
	 "toplevel policy_mod notebook"}
};

/**
 * As the user moves the cursor within the source policy text view
 * update the bottom label with the line number.  Once that view is
 * hidden, by flipping to a different tab, then clear the label.
 */
static void policy_view_notebook_on_event_after(GtkWidget * widget __attribute__ ((unused)), GdkEvent * event
						__attribute__ ((unused)), gpointer user_data)
{
	policy_view_t *view = (policy_view_t *) user_data;
	guint main_pagenum, view_pagenum;
	GtkTextMark *mark = NULL;
	GtkTextIter iter;

	main_pagenum = toplevel_get_notebook_page(view->top);
	view_pagenum = gtk_notebook_get_current_page(view->notebook);
	if (main_pagenum == 1 + view->which && view_pagenum == 1) {
		mark = gtk_text_buffer_get_insert(view->source);
		if (mark != NULL) {
			GString *string = g_string_new("");
			gtk_text_buffer_get_iter_at_mark(view->source, &iter, mark);
			g_string_printf(string, "Line: %d", gtk_text_iter_get_line(&iter) + 1);
			gtk_label_set_text(view->line_number, string->str);
			g_string_free(string, TRUE);
		}
	} else {
		gtk_label_set_text(view->line_number, "");
	}
}

policy_view_t *policy_view_create(toplevel_t * top, sediffx_policy_e which)
{
	policy_view_t *view;
	GtkTextTag *mono_tag;
	int error = 0;

	if ((view = calloc(1, sizeof(*view))) == NULL) {
		error = errno;
		goto cleanup;
	}
	view->top = top;
	view->which = which;

	view->xml = glade_get_widget_tree(GTK_WIDGET(toplevel_get_window(view->top)));
	view->stats = gtk_text_buffer_new(NULL);
	view->source = gtk_text_buffer_new(NULL);
	mono_tag = gtk_text_buffer_create_tag(view->source, "mono-tag",
					      "style", PANGO_STYLE_NORMAL,
					      "weight", PANGO_WEIGHT_NORMAL, "family", "monospace", NULL);

	view->stats_view = GTK_TEXT_VIEW(glade_xml_get_widget(view->xml, policy_view_widget_names[view->which][0]));
	view->source_view = GTK_TEXT_VIEW(glade_xml_get_widget(view->xml, policy_view_widget_names[view->which][1]));
	assert(view->stats_view != NULL && view->source_view != NULL);
	gtk_text_view_set_buffer(view->stats_view, view->stats);
	gtk_text_view_set_buffer(view->source_view, view->source);

	view->notebook = GTK_NOTEBOOK(glade_xml_get_widget(view->xml, policy_view_widget_names[view->which][2]));
	view->line_number = GTK_LABEL(glade_xml_get_widget(view->xml, "toplevel line label"));
	assert(view->notebook != NULL && view->line_number != NULL);
	g_signal_connect_after(G_OBJECT(view->notebook), "event-after", G_CALLBACK(policy_view_notebook_on_event_after), view);

      cleanup:
	if (error != 0) {
		policy_view_destroy(&view);
		errno = error;
		return NULL;
	}
	return view;
}

void policy_view_destroy(policy_view_t ** view)
{
	if (view != NULL && *view != NULL) {
		free(*view);
		*view = NULL;
	}
}

/**
 * Update the policy stats text buffer (and hence its view) to show
 * statistics about the given policy.
 *
 * @param view View to update.
 * @param p New policy whose statistics to get.
 * @param path Path to the new policy.
 */
static void policy_view_stats_update(policy_view_t * view, apol_policy_t * p, apol_policy_path_t * path)
{
	GtkTextIter iter;
	gchar *contents = NULL;
	char *path_desc, *tmp = NULL;
	size_t num_classes = 0,
		num_commons = 0,
		num_perms = 0,
		num_types = 0,
		num_attribs = 0,
		num_allow = 0,
		num_neverallow = 0,
		num_type_trans = 0,
		num_type_change = 0,
		num_auditallow = 0, num_dontaudit = 0,
		num_roles = 0, num_roleallow = 0, num_role_trans = 0, num_users = 0, num_bools = 0;
	apol_vector_t *vec = NULL;
	qpol_iterator_t *i = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(p);

	util_text_buffer_clear(view->stats);

	path_desc = util_policy_path_to_string(path);
	tmp = apol_policy_get_version_type_mls_str(p);
	contents = g_strdup_printf("Policy: %s\n" "Policy Version & Type: %s\n", path_desc, tmp);
	free(path_desc);
	free(tmp);
	tmp = NULL;
	gtk_text_buffer_get_end_iter(view->stats, &iter);
	gtk_text_buffer_insert(view->stats, &iter, contents, -1);
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
	gtk_text_buffer_insert(view->stats, &iter, contents, -1);
	g_free(contents);

	apol_type_get_by_query(p, NULL, &vec);
	num_types = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	apol_attr_get_by_query(p, NULL, &vec);
	num_attribs = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	contents = g_strdup_printf("\nNumber of Types and Attributes:\n"
				   "\tTypes: %d\n" "\tAttributes: %d\n", num_types, num_attribs);
	gtk_text_buffer_insert(view->stats, &iter, contents, -1);
	g_free(contents);

	qpol_policy_get_avrule_iter(q, QPOL_RULE_ALLOW, &i);
	qpol_iterator_get_size(i, &num_allow);
	qpol_iterator_destroy(&i);

	qpol_policy_get_avrule_iter(q, QPOL_RULE_NEVERALLOW, &i);
	qpol_iterator_get_size(i, &num_neverallow);
	qpol_iterator_destroy(&i);

	qpol_policy_get_avrule_iter(q, QPOL_RULE_AUDITALLOW, &i);
	qpol_iterator_get_size(i, &num_auditallow);
	qpol_iterator_destroy(&i);

	qpol_policy_get_avrule_iter(q, QPOL_RULE_DONTAUDIT, &i);
	qpol_iterator_get_size(i, &num_dontaudit);
	qpol_iterator_destroy(&i);

	qpol_policy_get_terule_iter(q, QPOL_RULE_TYPE_TRANS, &i);
	qpol_iterator_get_size(i, &num_type_trans);
	qpol_iterator_destroy(&i);

	qpol_policy_get_terule_iter(q, QPOL_RULE_TYPE_CHANGE, &i);
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
	gtk_text_buffer_insert(view->stats, &iter, contents, -1);
	g_free(contents);

	apol_role_get_by_query(p, NULL, &vec);
	num_roles = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	qpol_policy_get_role_allow_iter(q, &i);
	qpol_iterator_get_size(i, &num_roleallow);
	qpol_iterator_destroy(&i);

	qpol_policy_get_role_trans_iter(q, &i);
	qpol_iterator_get_size(i, &num_roleallow);
	qpol_iterator_destroy(&i);

	contents = g_strdup_printf("\nNumber of Roles: %d\n"
				   "\nNumber of RBAC Rules:\n"
				   "\tallow: %d\n" "\trole_transition %d\n", num_roles, num_roleallow, num_role_trans);
	gtk_text_buffer_insert(view->stats, &iter, contents, -1);
	g_free(contents);

	apol_user_get_by_query(p, NULL, &vec);
	num_users = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	apol_bool_get_by_query(p, NULL, &vec);
	num_bools = apol_vector_get_size(vec);
	apol_vector_destroy(&vec, NULL);

	contents = g_strdup_printf("\nNumber of Users: %d\n" "\nNumber of Booleans: %d\n", num_users, num_bools);
	gtk_text_buffer_insert(view->stats, &iter, contents, -1);
	g_free(contents);
}

/**
 * Attempt to load the primary policy into this view's source policy
 * buffer.  If the policy is not a source policy then show an
 * appropriate message.  Otherwise mmap() the policy's contents to the
 * buffer.
 *
 * @param view View whose source buffer to update.
 * @param policy Policy to show, or NULL if none loaded.
 * @param path Path to the policy.
 */
static void policy_view_source_update(policy_view_t * view, apol_policy_t * p, apol_policy_path_t * path)
{
	const char *primary_path;
	util_text_buffer_clear(view->source);

	/* clear out any old data */
	if (view->mmap_start != NULL) {
		munmap(view->mmap_start, view->mmap_length);
		view->mmap_start = NULL;
		view->mmap_length = 0;
	}
	if (p == NULL) {
		gtk_text_buffer_set_text(view->source, "No policy has been loaded.", -1);
		return;
	}
	primary_path = apol_policy_path_get_primary(path);
	if (!qpol_policy_has_capability(apol_policy_get_qpol(p), QPOL_CAP_SOURCE)) {
		GString *string = g_string_new("");
		g_string_printf(string, "Policy file %s is not a source policy.", primary_path);
		gtk_text_buffer_set_text(view->source, string->str, -1);
		g_string_free(string, TRUE);
	} else {
		/* load the policy by mmap()ing the file */
		struct stat statbuf;
		int fd;

		if ((fd = open(primary_path, O_RDONLY)) < 0) {
			toplevel_ERR(view->top, "Could not open %s for reading: %s", primary_path, strerror(errno));
			return;
		}
		if (fstat(fd, &statbuf) < 0) {
			toplevel_ERR(view->top, "Could not stat %s: %s", primary_path, strerror(errno));
			close(fd);
			return;
		}

		view->mmap_length = statbuf.st_size;
		if ((view->mmap_start = mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
			toplevel_ERR(view->top, "Could not mmap %s: %s", primary_path, strerror(errno));
			close(fd);
			view->mmap_start = NULL;
			return;
		}
		close(fd);
		gtk_text_buffer_set_text(view->source, view->mmap_start, view->mmap_length);
	}
}

void policy_view_update(policy_view_t * view, apol_policy_t * policy, apol_policy_path_t * path)
{
	policy_view_stats_update(view, policy, path);
	policy_view_source_update(view, policy, path);
}

void policy_view_show_policy_line(policy_view_t * view, unsigned long line)
{
	GtkTextTagTable *table = NULL;
	GtkTextIter iter, end_iter;
	GtkTextMark *mark = NULL;
	GString *string = g_string_new("");

	gtk_notebook_set_current_page(view->notebook, 1);

	/* when moving the buffer we must use marks to scroll because
	 * goto_line if called before the line height has been
	 * calculated can produce undesired results, in our case we
	 * get no scrolling at all */
	table = gtk_text_buffer_get_tag_table(view->source);
	gtk_text_buffer_get_start_iter(view->source, &iter);
	gtk_text_iter_set_line(&iter, line);
	gtk_text_buffer_get_start_iter(view->source, &end_iter);
	gtk_text_iter_set_line(&end_iter, line);
	while (!gtk_text_iter_ends_line(&end_iter)) {
		gtk_text_iter_forward_char(&end_iter);
	}

	mark = gtk_text_buffer_create_mark(view->source, "line-position", &iter, TRUE);
	assert(mark);
	gtk_text_view_scroll_to_mark(view->source_view, mark, 0.0, TRUE, 0.0, 0.5);

	/* destroying the mark and recreating is faster than doing a
	 * move on a mark that still exists, so we always destroy it
	 * once we're done */
	gtk_text_buffer_delete_mark(view->source, mark);
	gtk_text_view_set_cursor_visible(view->source_view, TRUE);
	gtk_text_buffer_place_cursor(view->source, &iter);
	gtk_text_buffer_select_range(view->source, &iter, &end_iter);

	gtk_container_set_focus_child(GTK_CONTAINER(view->notebook), GTK_WIDGET(view->source_view));

	g_string_printf(string, "Line: %d", gtk_text_iter_get_line(&iter) + 1);
	gtk_label_set_text(view->line_number, string->str);
	g_string_free(string, TRUE);
}

GtkTextView *policy_view_get_text_view(policy_view_t * view)
{
	gint pagenum = gtk_notebook_get_current_page(view->notebook);
	if (pagenum == 0) {
		return view->stats_view;
	} else {
		return view->source_view;
	}
}

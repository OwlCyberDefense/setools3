/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *         Kevin Carr <kcarr@tresys.com>
 */

#include "seaudit.h"
#include "parse.h"
#include "auditlog.h"
#include "query_window.h"
#include "filter_window.h"
#include <libapol/policy-io.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#define SEAUDIT_GUI_VERSION_STRING "1.0"

/* DEFAULT_POLICY should be defined in the make environment */
#ifndef DEFAULT_POLICY
	#define DEFAULT_POLICY "/etc/security/selinux/src/policy.conf"
#endif

#ifndef DEFAULT_LOG
	#define DEFAULT_LOG "/var/log/messages"
#endif

#ifndef INSTALL_LIBDIR
        #define INSTALL_LIBDIR "/usr/lib/apol"
#endif

seaudit_t *seaudit_app = NULL;

static struct option const opts[] =
{
	{"log", required_argument, NULL, 'l'},
	{"policy", required_argument, NULL, 'p'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

/* handle recent files and other user settings */
static int load_seaudit_conf_file(seaudit_conf_t *conf_file);
static void add_path_to_recent_log_files(const char *path, seaudit_conf_t *conf_file);
static void add_path_to_recent_policy_files(const char *path, seaudit_conf_t *conf_file);
static int save_seaudit_conf_file(seaudit_conf_t *conf_file);
static void free_seaudit_conf(seaudit_conf_t *conf_file);
static void set_seaudit_conf_default_policy(seaudit_conf_t *conf_file, const char *filename);
static void set_seaudit_conf_default_log(seaudit_conf_t *conf_file, const char *filename);

static void set_recent_policys_submenu(seaudit_conf_t *conf_file);
static void set_recent_logs_submenu(seaudit_conf_t *conf_file);

void message_display(GtkWindow *parent, GtkMessageType msg_type, const char *msg)
{
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(parent,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					msg_type,
					GTK_BUTTONS_CLOSE,
					msg);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}

static void update_title_bar(void *user_data)
{
	char str[STR_SIZE];
	char log_str[STR_SIZE];
	char policy_str[STR_SIZE];
	
	if (seaudit_app->log_store->log != NULL) {
		g_assert(seaudit_app->audit_log_file->str);
		snprintf(log_str, STR_SIZE, "[Log file: %s]", (const char*)seaudit_app->audit_log_file->str);
	} else {
		snprintf(log_str, STR_SIZE, "[Log file: No Log]");
	}
	
	if (seaudit_app->cur_policy != NULL) {
		snprintf(policy_str, STR_SIZE, "[Policy file: %s]", (const char*)seaudit_app->policy_file->str);
	} else {
		snprintf(policy_str, STR_SIZE, "[Policy file: No Policy]");
	}
	snprintf(str, STR_SIZE, "seAudit - %s %s", log_str, policy_str);	
	gtk_window_set_title(seaudit_app->top_window, (gchar*) str);
}

void update_status_bar(void *user_data)
{	
	
	char str[STR_SIZE];
	char *ver_str = NULL;
	int num_log_msgs, num_filtered_log_msgs;
	char old_time[TIME_SIZE], recent_time[TIME_SIZE];
	
	GtkLabel *v_status_bar = (GtkLabel *) glade_xml_get_widget(seaudit_app->top_window_xml, "PolicyVersionLabel");
	GtkLabel *l_status_bar = (GtkLabel *) glade_xml_get_widget(seaudit_app->top_window_xml, "LogNumLabel");
	GtkLabel *d_status_bar = (GtkLabel *) glade_xml_get_widget(seaudit_app->top_window_xml, "LogDateLabel");
			
	if (seaudit_app->cur_policy == NULL) {
		ver_str = "Policy Version: No policy";
		gtk_label_set_text(v_status_bar, ver_str);
	} else {
		switch (seaudit_app->cur_policy->version) 
		{
			case POL_VER_PRE_11:
				ver_str = POL_VER_STRING_PRE_11;
				break;
			case POL_VER_11: /* same as POL_VER_12 */
				ver_str = POL_VER_STRING_11;
				break;
			case POL_VER_15:
				ver_str = POL_VER_STRING_15;
				break;
		#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
			case POL_VER_16:   /* conditional policy extensions */
				ver_str = POL_VER_STRING_16;
				break;
			case POL_VER_COND:
				ver_str = POL_VER_STRING_16;
				break;
		#endif
			default:
				ver_str = "Unknown";
				break;
		}
		snprintf(str, STR_SIZE, "Policy Version: %s", ver_str);
		gtk_label_set_text(v_status_bar, str);
	}

	if (seaudit_app->log_store->log == NULL) {
		snprintf(str, STR_SIZE, "Log Messages: No log");
		gtk_label_set_text(l_status_bar, str);
		snprintf(str, STR_SIZE, "Dates: No log");
		gtk_label_set_text(d_status_bar, str);
	} else {
		num_log_msgs = seaudit_app->log_store->log->num_msgs;
		num_filtered_log_msgs = seaudit_app->log_store->log->num_fltr_msgs;
		snprintf(str, STR_SIZE, "Log Messages: %d/%d", num_filtered_log_msgs, num_log_msgs);
		gtk_label_set_text(l_status_bar, str);
		if (num_log_msgs > 0) {
			strftime(old_time, TIME_SIZE, "%b %d %H:%M:%S" , seaudit_app->log_store->log->msg_list[0]->date_stamp);
			strftime(recent_time, TIME_SIZE, "%b %d %H:%M:%S", seaudit_app->log_store->log->msg_list[num_log_msgs-1]->date_stamp);
			snprintf(str, STR_SIZE, "Dates: %s - %s", old_time, recent_time);
			gtk_label_set_text(d_status_bar, str);
		} else {
			snprintf(str, STR_SIZE, "Dates: No messages");
			gtk_label_set_text(d_status_bar, str);
		}
	}
}

static gint callback_compare(gconstpointer a, gconstpointer b)
{
	/* Order in the list does not matter, we just need to be able to know if
	 * two items are equal.  So if they are not equal, a is greater that b. */
	registered_callback_t *ca = (registered_callback_t*)a;
	registered_callback_t *cb = (registered_callback_t*)b;
	
	if (ca->function == cb->function && ca->user_data == cb->user_data && ca->type == cb->type)
		return 0;
	else 
		return 1;
}

/* Register a callback on an event signal */
int seaudit_callback_register(seaudit_callback_t function, void *user_data, unsigned int type)
{
	registered_callback_t *callback=NULL;

	callback = (registered_callback_t*)malloc(sizeof(registered_callback_t));
	if (!callback)
		return -1;
	callback->function = function;
	callback->user_data = user_data;
	callback->type = type;
	seaudit_app->callbacks = g_list_append(seaudit_app->callbacks, callback);
	return 0;
}

static void seaudit_callback_signal_emit_1(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *)data;
	unsigned int type = *(unsigned int*)user_data;
	if (callback->type == type) {
		callback->function(callback->user_data);
	}
	return;
}

/* the signal emit function executes each function registered with 
 * seaudit_callback_register() */
void seaudit_callback_signal_emit(unsigned int type)
{
	g_list_foreach(seaudit_app->callbacks, &seaudit_callback_signal_emit_1, &type);
	return;
}

static void free_elem_data(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t*)data;
	if (callback)
		free(callback);
	return;
}

/* we need to be able to remove these callbacks for example, when a window
 * is destroyed and no longer exists. */
void seaudit_callback_remove(seaudit_callback_t function, void *user_data, unsigned int type)
{
	GList *elem;
	registered_callback_t callback;

	callback.function = function;
	callback.user_data = user_data;
	callback.type = type;
	elem = g_list_find_custom(seaudit_app->callbacks, &callback, &callback_compare);
	if (elem == NULL)
		return;
	seaudit_app->callbacks = g_list_remove_link(seaudit_app->callbacks, elem);
	free_elem_data(elem->data, NULL);
	g_list_free_1(elem);
	return;
}

/* on exit of main program we can make sure all registered callbacks are removed
 * regardless of whether the caller removed them correctly. */
void seaudit_callbacks_free(void)
{
	g_list_foreach(seaudit_app->callbacks, &free_elem_data, NULL);
	g_list_free(seaudit_app->callbacks);
	seaudit_app->callbacks = NULL;
	return;
}

void exit_seaudit_app()
{
	save_seaudit_conf_file(&(seaudit_app->seaudit_conf));
	seaudit_destroy(seaudit_app);
	gtk_main_quit();
}

void on_TopWindow_destroy(GtkWidget *widget)
{
	exit_seaudit_app();
}

void on_FileQuit_activate(GtkWidget *widget, gpointer user_data)
{
	exit_seaudit_app();
	return;
}

void policy_file_open_from_recent_menu(GtkWidget *widget, gpointer user_data)
{
	const char *filename = (const char*)user_data;
	seaudit_open_policy(seaudit_app, filename);
}

static void get_dialog_response(GtkDialog *dialog, gint id, gpointer response);

/* 
 * when the user clicks on open policy from the file menu call this */
void on_PolicyFileOpen_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;

	file_selector = gtk_file_selection_new("Open Policy");
	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (seaudit_app->seaudit_conf.default_policy_file != NULL)
		gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), seaudit_app->seaudit_conf.default_policy_file);

	g_signal_connect(GTK_OBJECT(file_selector), "response", 
			 G_CALLBACK(get_dialog_response), &response);
	while (1) {
		gtk_dialog_run(GTK_DIALOG(file_selector));
		if (response != GTK_RESPONSE_OK) {
			gtk_widget_destroy(file_selector);
			return;
		}
		filename = gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_selector));
		if (g_file_test(filename, G_FILE_TEST_EXISTS) && !g_file_test(filename, G_FILE_TEST_IS_DIR))
			break;
		if (g_file_test(filename, G_FILE_TEST_IS_DIR))
			gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), filename);
	}
	seaudit_open_policy(seaudit_app, filename);
	gtk_widget_destroy(file_selector);
	return;
}

void log_file_open_from_recent_menu(GtkWidget *widget, gpointer user_data)
{
	const char *filename = (const char*)user_data;
	seaudit_open_log_file(seaudit_app, filename);
}

/*
 * when the user clicks on Open Audit Log from the file menu call this */
void on_LogFileOpen_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;

	file_selector = gtk_file_selection_new("Open Log");
	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (seaudit_app->seaudit_conf.default_log_file != NULL)
		gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), seaudit_app->seaudit_conf.default_log_file);

	g_signal_connect(GTK_OBJECT(file_selector), "response", 
			 G_CALLBACK(get_dialog_response), &response);
	while (1) {
		gtk_dialog_run(GTK_DIALOG(file_selector));
		if (response != GTK_RESPONSE_OK) {
			gtk_widget_destroy(file_selector);
			return;
		}
		filename = gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_selector));
		if (g_file_test(filename, G_FILE_TEST_EXISTS) && !g_file_test(filename, G_FILE_TEST_IS_DIR))
			break;
		if (g_file_test(filename, G_FILE_TEST_IS_DIR))
			gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), filename);
	}
	gtk_widget_destroy(file_selector);
	seaudit_open_log_file(seaudit_app, filename);
	return;
}

/* 
 * when the user clicks on About seaudit from the help menu call this */
void on_about_seaudit_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	GtkWidget *dialog;
	GString *str;
	
	str = g_string_new("");
	g_string_assign(str, "Audit Log Analysis Tool for Security \nEnhanced Linux");
        g_string_append(str, "\n\nCopyright (c) 2003\nTresys Technology, LLC\nwww.tresys.com/selinux");
	g_string_append(str, "\n\nGUI version ");
	g_string_append(str, SEAUDIT_GUI_VERSION_STRING);
	g_string_append(str, "\nlibseaudit version ");
	g_string_append(str, LIBSEAUDIT_VERSION_STRING);
	g_string_append(str, "\nlibapol version ");
	g_string_append(str, VERSION_STRING); /* the libapol version */
	
	dialog = gtk_message_dialog_new(seaudit_app->top_window,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_INFO,
					GTK_BUTTONS_CLOSE,
					str->str);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_string_free(str, TRUE);
	return;
}

/* allocate a buffer with contents of the file.  the caller must free
 * the buffer afterwards. */
#define BUF_SIZE 1024
static int read_file_to_buffer(const char *fname, char **buf, int *len)
{
	FILE *file = NULL;
	size_t size = 0, r;
	char *bufp;
	
	g_assert(*buf == NULL);
	g_assert(len);
	*len = 0;
	while (1) {
		size += BUF_SIZE;
		r = 0;
		*buf = (char*)realloc(*buf, size * sizeof(char));
		if (!*buf) {
			if (file)
				fclose(file);
			return -1;
		}
		if (!file) {
			file = fopen(fname, "r");
			if (!file) {
				return -1;
			}
		}
		bufp = &((*buf)[size - BUF_SIZE]);
		r = fread(bufp, sizeof(char), BUF_SIZE, file);
		*len += r;
		if (r < BUF_SIZE) {
			if (feof(file)) {
				fclose(file);
				break;
			} else {
				message_display(seaudit_app->top_window, GTK_MESSAGE_ERROR, strerror(ferror(file)));
				fclose(file);
				return -1;
			}
		}
	}
	return 0;
}

/*
 * when the user clicks on help from the help menu call this */
void on_seaudit_help_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
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
	gtk_window_set_title(GTK_WINDOW(window), "seAudit Help");
	gtk_window_set_default_size(GTK_WINDOW(window), 480, 300);
	gtk_container_add(GTK_CONTAINER(window), scroll);
	gtk_container_add(GTK_CONTAINER(scroll), text_view);
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));	
	dir = find_file("seaudit_help.txt");
	if (!dir) {
		string = g_string_new("");
		g_string_assign(string, "Can not find help file");
		message_display(seaudit_app->top_window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return;
	}
	string = g_string_new(dir);
	free(dir);
	g_string_append(string, "/seaudit_help.txt");
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
static gboolean real_time_update_log(gpointer callback_data);

void on_prefer_window_ok_button_clicked(GtkWidget *widget, gpointer user_data)
{
	GtkWidget *tree_view, *prefer_window;
	GList *columns;
	GtkTreeViewColumn *col = NULL;
	GladeXML *xml = (GladeXML*)user_data;
	GtkEntry *log_entry, *pol_entry;

	prefer_window = glade_xml_get_widget(xml, "PreferWindow");
	g_assert(widget);
	log_entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultLogEntry"));
	if( strcmp(gtk_entry_get_text(log_entry), "") != 0) {
		if( !g_file_test(gtk_entry_get_text(log_entry), G_FILE_TEST_EXISTS) ||
		    g_file_test(gtk_entry_get_text(log_entry), G_FILE_TEST_IS_DIR)) {
			message_display(GTK_WINDOW(prefer_window), GTK_MESSAGE_ERROR, 
					"invalid filename in default log entry");
			return;
		}
	}
	pol_entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultPolicyEntry"));
	if (strcmp(gtk_entry_get_text(pol_entry), "") != 0) {
		if (!g_file_test(gtk_entry_get_text(pol_entry), G_FILE_TEST_EXISTS) ||
		    g_file_test(gtk_entry_get_text(pol_entry), G_FILE_TEST_IS_DIR)) {
			message_display(GTK_WINDOW(prefer_window), GTK_MESSAGE_ERROR, 
					"invalid filename in default policy entry");
			return;
		}
	}
	set_seaudit_conf_default_log(&(seaudit_app->seaudit_conf),
				     gtk_entry_get_text(log_entry));
	set_seaudit_conf_default_policy(&(seaudit_app->seaudit_conf),
					gtk_entry_get_text(pol_entry));
	save_seaudit_conf_file(&(seaudit_app->seaudit_conf));

	/* set up a timeout function to update the log */
	if (seaudit_app->seaudit_conf.timeout_key)
		gtk_timeout_remove(seaudit_app->seaudit_conf.timeout_key);
	if (seaudit_app->seaudit_conf.real_time_log)
		seaudit_app->seaudit_conf.timeout_key = 
			gtk_timeout_add(LOG_UPDATE_INTERVAL, &real_time_update_log, NULL);

	/* set the updated visibility if needed */
	if (!seaudit_app->column_visibility_changed)
		return;
	tree_view = glade_xml_get_widget(seaudit_app->top_window_xml, "LogListView");
	g_assert(tree_view);
	columns = gtk_tree_view_get_columns(GTK_TREE_VIEW(tree_view));
	while (columns != NULL) {
		col = GTK_TREE_VIEW_COLUMN(columns->data);
		gtk_tree_view_column_set_visible(col, seaudit_app->seaudit_conf.column_visibility[
						 gtk_tree_view_column_get_sort_column_id(col)]);
		columns = g_list_next(columns);
	}
	seaudit_app->column_visibility_changed = FALSE;
	gtk_widget_destroy(prefer_window);
}

void on_browse_log_button_clicked(GtkWidget *widget, gpointer user_data)
{
	GladeXML *xml = (GladeXML*)user_data;
	GtkEntry *entry;
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultLogEntry"));
	g_assert(entry);
	file_selector = gtk_file_selection_new("Select Default Log");
	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (seaudit_app->seaudit_conf.default_policy_file != NULL)
		gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), gtk_entry_get_text(GTK_ENTRY(entry)));
	g_signal_connect(GTK_OBJECT(file_selector), "response", 
			 G_CALLBACK(get_dialog_response), &response);
	while (1) {
		gtk_dialog_run(GTK_DIALOG(file_selector));
		if (response != GTK_RESPONSE_OK) {
			gtk_widget_destroy(file_selector);
			return;
		}
		filename = gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_selector));
		if (g_file_test(filename, G_FILE_TEST_EXISTS) && !g_file_test(filename, G_FILE_TEST_IS_DIR)) 
			break;
		if (g_file_test(filename, G_FILE_TEST_IS_DIR))
			gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), filename);
	}
	gtk_entry_set_text(GTK_ENTRY(entry), filename);
	gtk_widget_destroy(file_selector);
}

void on_browse_policy_button_clicked(GtkWidget *widget, gpointer user_data)
{
	GladeXML *xml = (GladeXML*)user_data;
	GtkEntry *entry;
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultPolicyEntry"));
	g_assert(entry);
	file_selector = gtk_file_selection_new("Select Default Policy");
	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (seaudit_app->seaudit_conf.default_policy_file != NULL)
		gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), gtk_entry_get_text(GTK_ENTRY(entry)));
	g_signal_connect(GTK_OBJECT(file_selector), "response", 
			 G_CALLBACK(get_dialog_response), &response);
	while (1) {
		gtk_dialog_run(GTK_DIALOG(file_selector));
		if (response != GTK_RESPONSE_OK) {
			gtk_widget_destroy(file_selector);
			return;
		}
		filename = gtk_file_selection_get_filename(GTK_FILE_SELECTION(file_selector));
		if (g_file_test(filename, G_FILE_TEST_EXISTS) && !g_file_test(filename, G_FILE_TEST_IS_DIR))
			break;
		if (g_file_test(filename, G_FILE_TEST_IS_DIR))
			gtk_file_selection_complete(GTK_FILE_SELECTION(file_selector), filename);
	}
	gtk_entry_set_text(GTK_ENTRY(entry), filename);
	gtk_widget_destroy(file_selector);
}

void on_preference_toggled(GtkToggleButton *toggle, gpointer user_data)
{
	if (!strcmp("MessageCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_MSG_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;
	} else if (!strcmp("DateCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[DATE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("OtherCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_MISC_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("SourceUserCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_SRC_USER_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("SourceRoleCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_SRC_ROLE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("SourceTypeCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_SRC_TYPE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("TargetUserCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_TGT_USER_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("TargetRoleCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_TGT_ROLE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("TargetTypeCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_TGT_TYPE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("ObjectClassCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_OBJ_CLASS_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("PermissionCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_PERM_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("ExecutableCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_EXE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("PIDCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_PID_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("InodeCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_INODE_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("PathCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[AVC_PATH_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("HostCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.column_visibility[HOST_FIELD] = gtk_toggle_button_get_active(toggle);
		seaudit_app->column_visibility_changed = TRUE;

	} else if (!strcmp("RealTimeCheck", gtk_widget_get_name(GTK_WIDGET(toggle)))) {
		seaudit_app->seaudit_conf.real_time_log = gtk_toggle_button_get_active(toggle);
	}

}

void on_preferences_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	GladeXML *xml;
	GtkWidget *button, *window;
	GtkEntry *entry;
	GtkToggleButton *toggle = NULL;
	GString *path;
	char *dir;

	dir = find_file("prefer_window.glade");
	if (!dir){
		fprintf(stderr, "could not find prefer_window.glade\n");
		return;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/prefer_window.glade");
	xml = glade_xml_new(path->str, NULL, NULL);
	g_string_free(path, TRUE);
	window = glade_xml_get_widget(xml, "PreferWindow");
	g_assert(window);

	entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultLogEntry"));
	g_assert(entry);
	if (seaudit_app->seaudit_conf.default_log_file)
		gtk_entry_set_text(entry, seaudit_app->seaudit_conf.default_log_file);
	
	entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultPolicyEntry"));
	g_assert(entry);
	if (seaudit_app->seaudit_conf.default_policy_file)
		gtk_entry_set_text(entry, seaudit_app->seaudit_conf.default_policy_file);

	button = glade_xml_get_widget(xml, "OkButton");
	g_assert(button);
	g_signal_connect (GTK_OBJECT (button),
			  "clicked",
			  G_CALLBACK (on_prefer_window_ok_button_clicked),
			  (gpointer) xml);	

	button = glade_xml_get_widget(xml, "BrowseLogButton");
	g_assert(widget);
	g_signal_connect (GTK_OBJECT (button),
			  "clicked",
			  G_CALLBACK (on_browse_log_button_clicked),
			  (gpointer) xml);
	
	button = glade_xml_get_widget(xml, "BrowsePolicyButton");
	g_assert(widget);
	g_signal_connect (GTK_OBJECT (button),
			  "clicked",
			  G_CALLBACK (on_browse_policy_button_clicked),
			  (gpointer) xml);

	glade_xml_signal_connect(xml, "on_preference_toggled", G_CALLBACK(on_preference_toggled));

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "MessageCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_MSG_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "DateCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[DATE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "OtherCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_MISC_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "SourceUserCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_SRC_USER_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "SourceRoleCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_SRC_ROLE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "SourceTypeCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_SRC_TYPE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "TargetUserCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_TGT_USER_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "TargetRoleCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_TGT_ROLE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "TargetTypeCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_TGT_TYPE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "ObjectClassCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_OBJ_CLASS_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "PermissionCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_PERM_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "ExecutableCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_EXE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "PIDCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_PID_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "InodeCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_INODE_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "PathCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[AVC_PATH_FIELD]);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "RealTimeCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.real_time_log);

	toggle = GTK_TOGGLE_BUTTON(glade_xml_get_widget(xml, "HostCheck"));
	g_assert(toggle);
	gtk_toggle_button_set_active(toggle, seaudit_app->seaudit_conf.column_visibility[HOST_FIELD]);
	return;
}

/* 
 * when the user clicks on filter log call this */
void on_edit_filter_activate(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	if (seaudit_app->cur_policy == NULL) {
		message_display(seaudit_app->top_window, GTK_MESSAGE_ERROR, "There is no policy loaded");
		return;
	}
	if (seaudit_app->log_store->log == NULL) {
			message_display(seaudit_app->top_window, GTK_MESSAGE_ERROR, "There is no audit log loaded.");
		return;
	}
	if (seaudit_app->filters->window != NULL) {
		gtk_window_present(seaudit_app->filters->window); 
		return;
	}
	/* Display filters window */
	filters_display(seaudit_app->filters);
	return;
}

/*
 * when the user clicks on query policy call this */
void on_top_window_query_button_clicked(GtkWidget *widget, GdkEvent *event, gpointer callback_data)
{
	query_window_create();
	return;
}

void on_audit_log_row_activated(GtkTreeView *treeview, GtkTreePath *path, GtkTreeViewColumn *col, gpointer user_data)
{
	on_top_window_query_button_clicked(NULL, NULL, NULL);
}

/*
 * Idle function used to keep the log up to date */
static gboolean real_time_update_log(gpointer callback_data)
{
	#define MSG_SIZE 64 /* should be big enough */

	/* simply return if the log is not open or 
	 * we don't want real time updates */
	if (!seaudit_app->seaudit_conf.real_time_log || !seaudit_app->log_file_ptr)
		return TRUE;

	seaudit_log_store_refresh(seaudit_app->log_store, seaudit_app->log_file_ptr);
	log_filtered_signal_emit();
	return TRUE;
}

static int read_policy_conf(const char *fname)
{
	char *buf = NULL;
	int len, rt;

	rt = read_file_to_buffer(fname, &buf, &len);
	if (rt != 0) {
		if (buf)
			free(buf);
		return -1;
	}
	
	seaudit_app->policy_text = gtk_text_buffer_new(NULL);
	gtk_text_buffer_set_text(seaudit_app->policy_text, buf, len);
	free(buf);
	return 0;
}

static GtkTreeViewColumn *create_column(GtkTreeView *view, const char *name,
					GtkCellRenderer *renderer, int field,
					int max_width)
{
	GtkTreeViewColumn *column;

	column = gtk_tree_view_column_new_with_attributes(name, renderer, "text", field, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_clickable (column, TRUE);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sort_column_id(column, field);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_fixed_width(column, max_width);
	gtk_tree_view_column_set_visible(column, seaudit_app->seaudit_conf.column_visibility[field]);

	return column;
}

static int create_list(GtkTreeView *view)
{
	SEAuditLogStore *list;
	GtkCellRenderer *renderer;
	PangoLayout *layout;
	GtkTreeViewColumn *column;
	int width;

	list = seaudit_log_store_create();
	gtk_tree_view_set_model(view, GTK_TREE_MODEL(list));
	g_object_unref(G_OBJECT(list));
	
	gtk_tree_view_set_rules_hint(view, TRUE);
	renderer = gtk_cell_renderer_text_new();
	g_object_set(G_OBJECT(renderer), "xpad", 8, NULL);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Hostname");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Hostname", renderer, HOST_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Message");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Message", renderer, AVC_MSG_FIELD, width);
	
	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Sep 16 10:51:20");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Date", renderer, DATE_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Source");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Source\nUser", renderer, AVC_SRC_USER_FIELD, width);
	create_column(view, "Source\nRole", renderer, AVC_SRC_ROLE_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "unlabeled_t");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Source\nType", renderer, AVC_SRC_TYPE_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Source");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Target\nUser", renderer, AVC_TGT_USER_FIELD, width);
	create_column(view, "Target\nRole", renderer, AVC_TGT_ROLE_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "unlabeled_t");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Target\nType", renderer, AVC_TGT_TYPE_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Object  ");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Object\nClass", renderer, AVC_OBJ_CLASS_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "Permission");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Permission", renderer, AVC_PERM_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "/usr/bin/cat");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Executable", renderer, AVC_EXE_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "12345");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "PID", renderer, AVC_PID_FIELD, width);

	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "123456");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Inode", renderer, AVC_INODE_FIELD, width);
	
	layout = gtk_widget_create_pango_layout(GTK_WIDGET(view), "/home/username/foo");
	pango_layout_get_pixel_size(layout, &width, NULL);
	g_object_unref(G_OBJECT(layout));
	width += 12;
	create_column(view, "Path", renderer, AVC_PATH_FIELD, width);

	column = gtk_tree_view_column_new_with_attributes("Other", renderer, "text", AVC_MISC_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_clickable (column, FALSE);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_GROW_ONLY);
	gtk_tree_view_column_set_sort_column_id(column, AVC_MISC_FIELD );
	gtk_tree_view_column_set_sort_indicator(column, FALSE);
	gtk_tree_view_column_set_visible(column, seaudit_app->seaudit_conf.column_visibility[AVC_MISC_FIELD]);

	return 0;
}


static void set_seaudit_conf_default_policy(seaudit_conf_t *conf, const char *filename)
{
	if (conf->default_policy_file)
		free(conf->default_policy_file);
	if (filename) {
		conf->default_policy_file = (char*)malloc(sizeof(char) * (1 + strlen(filename)));
		strcpy(conf->default_policy_file, filename);
	} else 
		conf->default_policy_file = NULL;
}

static void set_seaudit_conf_default_log(seaudit_conf_t *conf, const char *filename)
{
	if (conf->default_log_file)
		free(conf->default_log_file);

	if (filename) {
		conf->default_log_file = (char*)malloc(sizeof(char) * (1 + strlen(filename)));
		strcpy(conf->default_log_file, filename);
	} else
		conf->default_log_file = NULL;
}

static int load_seaudit_conf_file(seaudit_conf_t *conf)
{
  	FILE *file;
	int i, size, index;
	GString *path;
	char *value, **list, *dir;

	if (conf == NULL)
		return -1;

	dir = find_user_config_file(".seaudit");
	if (!dir) {
		dir = find_file("dot_seaudit");
		if (!dir)
			return -1;
		else {
			path = g_string_new(dir);
			free(dir);
			g_string_append(path, "/dot_seaudit");
		}
	} else {
		path = g_string_new(dir);
		free(dir);
		g_string_append(path, "/.seaudit");
	}
	file = fopen(path->str, "r");
	g_string_free(path, TRUE);
	if (!file)
		return -1; 
	value = get_config_var("DEFAULT_LOG_FILE", file);
	set_seaudit_conf_default_log(conf, value);
	if (value)
		free(value);
	value = get_config_var("DEFAULT_POLICY_FILE", file);
	set_seaudit_conf_default_policy(conf, value);
	if (value)
		free(value);
	list = get_config_var_list("RECENT_LOG_FILES", file, &size);
	if (list) {
		for (i = 0; i < size; i++) {
			add_path_to_recent_log_files(list[i], conf);
			free(list[i]);
		}
		free(list);
	} else 
		conf->recent_log_files = NULL;
	conf->num_recent_log_files = size;
	list = get_config_var_list("RECENT_POLICY_FILES", file, &size);
	if (list) {
		for (i = 0; i < size; i++) {
			add_path_to_recent_policy_files(list[i], conf);
			free(list[i]);
		}
		free(list);
	} else
		conf->recent_policy_files = NULL;
	conf->num_recent_policy_files = size;
	for (i = 0; i < NUM_FIELDS; i++)
		conf->column_visibility[i] = TRUE;
	list = get_config_var_list("LOG_COLUMNS_HIDDEN", file, &size);
	if (list) {
		for (i = 0; i < size; i++) {
			assert(list[i]);
			index = audit_log_field_strs_get_index(list[i]);
			if (index >= 0)
				conf->column_visibility[index] = FALSE;
			free(list[i]);
		}
		free(list);
	}
	value = get_config_var("REAL_TIME_LOG_MONITORING", file);
	if (!value) {
		conf->real_time_log = FALSE;
		conf->timeout_key = 0;
	} else  {
		conf->real_time_log = atoi(value);
		if (conf->real_time_log)
			conf->timeout_key = g_timeout_add(LOG_UPDATE_INTERVAL, 
							  &real_time_update_log, NULL);
		else 
			conf->timeout_key = 0;
		free(value);
	}
	fclose(file);
	return 0;
}

static void add_path_to_recent_log_files(const char *path, seaudit_conf_t *conf_file)
{
	int i;

	if (path == NULL || conf_file == NULL)
		return;

	/* make sure we don't add duplicates */
	for (i = 0; i < conf_file->num_recent_log_files; i++)
		if (strcmp(path, conf_file->recent_log_files[i]) == 0)
			return;
	if (conf_file->num_recent_log_files >= 5) {
		free(conf_file->recent_log_files[0]);
		for (i = 1; i < conf_file->num_recent_log_files; i++)
			conf_file->recent_log_files[i-1] = conf_file->recent_log_files[i];
		conf_file->recent_log_files[conf_file->num_recent_log_files-1] = (char *)malloc(sizeof(char)*(strlen(path) + 1));
		strcpy(conf_file->recent_log_files[conf_file->num_recent_log_files-1], path);
		return;

	} else {
		conf_file->recent_log_files = (char**)realloc( conf_file->recent_log_files, sizeof(char*)*(conf_file->num_recent_log_files+1));
		conf_file->recent_log_files[conf_file->num_recent_log_files] = (char *)malloc(sizeof(char)*(strlen(path) + 1));
		strcpy(conf_file->recent_log_files[conf_file->num_recent_log_files], path);	
		conf_file->num_recent_log_files++;
		return;
	}
}

static void add_path_to_recent_policy_files(const char *path, seaudit_conf_t *conf_file)
{
	int i;

	if (path == NULL || conf_file == NULL)
		return;

	/* make sure we don't add duplicates */
	for (i = 0; i < conf_file->num_recent_policy_files; i++)
		if (strcmp(path, conf_file->recent_policy_files[i]) == 0)
			return;
	if (conf_file->num_recent_policy_files >= 5) {
		free(conf_file->recent_policy_files[0]);
		for (i = 1; i < conf_file->num_recent_policy_files; i++)
			conf_file->recent_log_files[i-1] = conf_file->recent_log_files[i];
		conf_file->recent_policy_files[conf_file->num_recent_policy_files-1] = (char *)malloc(sizeof(char)*(strlen(path) + 1));
		strcpy(conf_file->recent_policy_files[conf_file->num_recent_policy_files-1], path);
		return;
	} else {
		conf_file->recent_policy_files = (char**)realloc(conf_file->recent_policy_files, 							  
							 sizeof(char*)*(conf_file->num_recent_policy_files+1));
		conf_file->recent_policy_files[conf_file->num_recent_policy_files] = (char *)malloc(sizeof(char)*(strlen(path) + 1));
		strcpy(conf_file->recent_policy_files[conf_file->num_recent_policy_files], path);
		conf_file->num_recent_policy_files++;
		return;
	}
}

static int save_seaudit_conf_file(seaudit_conf_t *conf)
{
	FILE *file;
	int i, num_hiden = 0;
	char *value = NULL, *home;
	const char **hiden_columns = NULL;
	GString *path;

	/* we need to open ~/.seaudit */
	home = getenv("HOME");
	if (!home)
		return -1;
	path = g_string_new(home);
	g_string_append(path, "/.seaudit");
	file = fopen(path->str, "w");
	g_string_free(path, TRUE);
	if (!file)
		return -1;

	fprintf(file, "# configuration file for seaudit - an audit log tool for Security Enhanced Linux.\n");
	fprintf(file, "# this file is auto-generated\n\n");
	
	fprintf(file, "DEFAULT_LOG_FILE");
	if (conf->default_log_file)
		fprintf(file, " %s\n", conf->default_log_file);
	else 
		fprintf(file, "\n");
	fprintf(file, "DEFAULT_POLICY_FILE");
	if (conf->default_policy_file)
		fprintf(file, " %s\n", conf->default_policy_file);
	else 
		fprintf(file, "\n");
	fprintf(file, "RECENT_LOG_FILES");
	value = config_var_list_to_string((const char**)conf->recent_log_files, conf->num_recent_log_files);
	if (value) {
		fprintf(file, " %s\n", value);
		free(value);
	} else 
		fprintf(file, "\n");
	fprintf(file, "RECENT_POLICY_FILES");
	value = config_var_list_to_string((const char**)conf->recent_policy_files, conf->num_recent_policy_files);
	if (value) {
		fprintf(file, " %s\n", value);
		free(value);
	} else 
		fprintf(file, "\n");
	fprintf(file, "LOG_COLUMNS_HIDDEN");
	for (i = 0; i < NUM_FIELDS; i++)
		if (conf->column_visibility[i] == FALSE) {
			num_hiden++;
			hiden_columns = (const char**)realloc(hiden_columns, sizeof(char*) * num_hiden);
			if (!hiden_columns) {
				fprintf(stderr, "out of memory");
				return -1;
			}
			/* we can do a shallow copy from the static strings array */
			hiden_columns[num_hiden-1] = audit_log_field_strs[i];
		}
	if (hiden_columns) {
		value = config_var_list_to_string(hiden_columns, num_hiden);
		free(hiden_columns);
		if (value) {
			fprintf(file, " %s\n", value);
			free(value);
		} else {
			fprintf(file, "\n");
		}
	}
		
	fprintf(file, "\nREAL_TIME_LOG_MONITORING %d\n", conf->real_time_log);
	fclose(file);
	return 0;
}

static void free_seaudit_conf(seaudit_conf_t *conf_file)
{
	int i;
	if (conf_file->recent_log_files) {
		for (i = 0; i < conf_file->num_recent_log_files; i++)
			if (conf_file->recent_log_files[i])
				free(conf_file->recent_log_files[i]);
		free(conf_file->recent_log_files);
	}
	if (conf_file->recent_policy_files) {
		for (i = 0; i < conf_file->num_recent_policy_files; i++)
			if (conf_file->recent_policy_files[i])
				free(conf_file->recent_policy_files[i]);
		free(conf_file->recent_policy_files);
	}
	if (conf_file->default_log_file)
		free(conf_file->default_log_file);
	if (conf_file->default_policy_file)
		free(conf_file->default_policy_file);	
	return;
}

static void set_recent_logs_submenu(seaudit_conf_t *conf_file)
{
	GtkWidget *submenu, *submenu_item;
	GtkMenuItem *recent;
	int i;

	recent = GTK_MENU_ITEM(glade_xml_get_widget(seaudit_app->top_window_xml, "OpenRecentLog"));
	g_assert(recent);
	gtk_menu_item_remove_submenu(recent);
	submenu = gtk_menu_new();
	for (i = 0; i < conf_file->num_recent_log_files; i++) {
		submenu_item = gtk_menu_item_new_with_label(conf_file->recent_log_files[i]);
		gtk_menu_shell_prepend(GTK_MENU_SHELL(submenu), submenu_item);
		gtk_widget_show(submenu_item);
		g_signal_connect(G_OBJECT(submenu_item), "activate", G_CALLBACK(log_file_open_from_recent_menu), 
				 conf_file->recent_log_files[i]);
	}
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(recent), submenu);
	return;
}

static void set_recent_policys_submenu(seaudit_conf_t *conf_file)
{
	GtkWidget *submenu, *submenu_item;
	GtkMenuItem *recent;
	int i;

	recent = GTK_MENU_ITEM(glade_xml_get_widget(seaudit_app->top_window_xml, "OpenRecentPolicy"));
	g_assert(recent);
	submenu = gtk_menu_new();
	for (i = 0; i < conf_file->num_recent_policy_files; i++) {
		submenu_item = gtk_menu_item_new_with_label(conf_file->recent_policy_files[i]);
		gtk_menu_shell_prepend(GTK_MENU_SHELL(submenu), submenu_item);
		gtk_widget_show(submenu_item);
		g_signal_connect(G_OBJECT(submenu_item), "activate", G_CALLBACK(policy_file_open_from_recent_menu), 
				 conf_file->recent_policy_files[i]);
	}
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(recent), submenu);
	return;
}

/* seaudit object */

seaudit_t* seaudit_init(void)
{
	seaudit_t *seaudit;
	GString *path; 
	char *dir;

	dir = find_file("seaudit.glade");
	if (!dir){
		fprintf(stderr, "could not find seaudit.glade\n");
		return NULL;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/seaudit.glade");
	seaudit = (seaudit_t*)malloc(sizeof(seaudit_t));
	if (!seaudit) {
		fprintf(stderr, "memory error\n");
		return NULL;
	}
	memset(seaudit, 0, sizeof(seaudit_t));
	seaudit->top_window_xml = glade_xml_new(path->str, NULL, NULL);
	g_string_free(path, TRUE);

	g_assert(seaudit->top_window_xml);
	seaudit->top_window = GTK_WINDOW(glade_xml_get_widget(seaudit->top_window_xml, "TopWindow"));
	g_assert(seaudit->top_window);
	seaudit->filters = filters_create();
	if (!seaudit->filters) {
		return NULL;
	}
	seaudit->policy_file = g_string_new("");
	seaudit->audit_log_file = g_string_new("");
	
	return seaudit;
}

void seaudit_destroy(seaudit_t *seaudit_app)
{
	if (seaudit_app->cur_policy)
		close_policy(seaudit_app->cur_policy);
	seaudit_log_store_close_log(seaudit_app->log_store);
	filters_destroy(seaudit_app->filters);
	seaudit_callbacks_free();
	if (seaudit_app->log_file_ptr)
		fclose(seaudit_app->log_file_ptr);
	free_seaudit_conf(&(seaudit_app->seaudit_conf));
	g_string_free(seaudit_app->policy_file, TRUE);
	g_string_free(seaudit_app->audit_log_file, TRUE);
	free(seaudit_app);
	seaudit_app = NULL;
}

static void get_dialog_response(GtkDialog *dialog, gint id, gpointer response)
{
	*((gint*)response) = id;
	return;
}

int seaudit_open_policy(seaudit_t *seaudit, const char *filename)
{
	unsigned int opts;
	FILE *file;
	policy_t *tmp_policy = NULL;
	int rt;
	const int SEAUDIT_STR_SZ = 128;
	GString *msg;
	GtkWidget *dialog;
	gint response;

	if (filename == NULL)
		return -1;

	show_wait_cursor(GTK_WIDGET(seaudit_app->top_window));
	if (seaudit->cur_policy != NULL) {
		dialog = gtk_message_dialog_new(seaudit->top_window,
						GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
						GTK_MESSAGE_WARNING,
						GTK_BUTTONS_YES_NO,
						"Opening a new policy will close all \"Query Policy\" windows\n"
						"and may also change the current log filter.\n"
						"Do you wish to continue anyway?");
		g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(get_dialog_response), &response);
		gtk_dialog_run(GTK_DIALOG(dialog));
		gtk_widget_destroy(dialog);
		if (response != GTK_RESPONSE_YES) {
			clear_wait_cursor(GTK_WIDGET(seaudit_app->top_window));
			return 0;
		}
	}
	if (g_file_test(filename, G_FILE_TEST_IS_DIR)) {
		msg = g_string_new("Error opening file: File is a directory!\n");
		message_display(seaudit->top_window, GTK_MESSAGE_ERROR, msg->str);
		g_string_free(msg, TRUE);
		gdk_window_set_cursor(GTK_WIDGET(seaudit_app->top_window)->window, NULL);
		return -1;
	}
	
	file = fopen(filename, "r");
	if (!file) {
		msg = g_string_new("Error opening file: ");
		if (strlen(filename) > SEAUDIT_STR_SZ) {
			char *tmp = NULL;
			tmp = g_strndup(filename, SEAUDIT_STR_SZ);
			g_string_append(msg, tmp);
			g_string_append(msg, "...");
			g_free(tmp);
		} else {
			g_string_append(msg, filename);
		}
		g_string_append(msg, "!\n");
		g_string_append(msg, strerror(errno));
		message_display(seaudit->top_window, GTK_MESSAGE_ERROR, msg->str);
		g_string_free(msg, TRUE);
		gdk_window_set_cursor(GTK_WIDGET(seaudit_app->top_window)->window, NULL);
		return -1;
	} else 
		fclose(file);
	
	opts = POLOPT_AV_RULES | POLOPT_USERS | POLOPT_ROLES;
	opts = validate_policy_options(opts);
	rt = open_partial_policy(filename, opts, &tmp_policy);
	if (rt != 0) {
		if (tmp_policy)
			close_policy(tmp_policy);
		msg = g_string_new("");
		g_string_append(msg, "The specified file does not appear to be a valid\nSE Linux Policy\n\n");
		g_string_append(msg, "WARNING: This program has a bug which will cause it to\n");
		g_string_append(msg, "work improperly once an invalid policy was opened.\n");
		g_string_append(msg, "Therefore, seaudit WILL NOW EXIT so you can restart it.");
		message_display(seaudit->top_window, GTK_MESSAGE_ERROR, msg->str);
		gdk_window_set_cursor(GTK_WIDGET(seaudit_app->top_window)->window, NULL);
		exit(1);
	}
	if (seaudit->cur_policy)
		close_policy(seaudit->cur_policy);
	seaudit->cur_policy = tmp_policy;
	g_string_assign(seaudit->policy_file, filename);
	read_policy_conf(filename);
	policy_load_signal_emit();

	add_path_to_recent_policy_files(filename, &(seaudit_app->seaudit_conf));
	set_recent_policys_submenu(&(seaudit_app->seaudit_conf));
	save_seaudit_conf_file(&(seaudit_app->seaudit_conf));

	clear_wait_cursor(GTK_WIDGET(seaudit_app->top_window));

	return 0;
}

static void on_log_store_rows_reordered(GtkTreeModel *model, GtkTreePath *arg1, GtkTreeIter *arg2, 
					gpointer arg3, gpointer user_data);

int seaudit_open_log_file(seaudit_t *seaudit, const char *filename)
{
	SEAuditLogStore *store;
	FILE *tmp_file;
	int rt;
	GString *msg = NULL;
	GtkWidget *widget;

	if (filename == NULL)
		return -1;
	show_wait_cursor(GTK_WIDGET(seaudit_app->top_window));
    	tmp_file = fopen(filename, "r");
	if (!tmp_file) {
		msg = g_string_new("Error opening file ");
		g_string_append(msg, filename);
		g_string_append(msg, "!\n");
		g_string_append(msg, strerror(errno));
	   		message_display(seaudit_app->top_window, 
				GTK_MESSAGE_ERROR, 
				msg->str);		
		goto dont_load_log;
	}
	store = seaudit_log_store_create();
	rt = seaudit_log_store_open_log(store, tmp_file);
	if (rt == PARSE_MEMORY_ERROR) {
		message_display(seaudit->top_window, 
				GTK_MESSAGE_ERROR, 
				PARSE_MEMORY_ERROR_MSG);
		goto dont_load_log;
	}
	else if (rt == PARSE_NO_SELINUX_ERROR) {
		message_display(seaudit->top_window, 
				GTK_MESSAGE_ERROR, 
				PARSE_NO_SELINUX_ERROR_MSG);
		goto dont_load_log;
	}
	else if (rt == PARSE_INVALID_MSG_WARN) {
		message_display(seaudit->top_window, 
				GTK_MESSAGE_WARNING, 
				PARSE_INVALID_MSG_WARN_MSG);
		goto load_log;
	}
	else if (rt == PARSE_MALFORMED_MSG_WARN) {
		message_display(seaudit->top_window, 
				GTK_MESSAGE_WARNING, 
				PARSE_MALFORMED_MSG_WARN_MSG);
		goto load_log;
	}
	else if (rt == PARSE_BOTH_MSG_WARN) {
		message_display(seaudit->top_window, 
				GTK_MESSAGE_WARNING, 
				PARSE_BOTH_MSG_WARN_MSG);
		goto load_log;
	}
	else if (rt == PARSE_SUCCESS)
		goto load_log;
	
 dont_load_log:
	if (tmp_file)
		fclose(tmp_file);
	if (msg)
		g_string_free(msg, TRUE);
	gdk_window_set_cursor(GTK_WIDGET(seaudit_app->top_window)->window, NULL);
	return -1;

 load_log:
	widget = glade_xml_get_widget(seaudit_app->top_window_xml, "LogListView");
	g_signal_handlers_disconnect_by_func(G_OBJECT(seaudit_app->log_store), (gpointer)on_log_store_rows_reordered, widget);
	/* close out the old log */
	seaudit_log_store_close_log(seaudit_app->log_store);
	/* open up the new log */
	gtk_tree_view_set_model(GTK_TREE_VIEW(widget), GTK_TREE_MODEL(store));
	seaudit_app->log_store = store;
	seaudit_app->log_file_ptr = tmp_file;
	g_string_assign(seaudit_app->audit_log_file, filename);
	g_signal_connect(G_OBJECT(seaudit_app->log_store), "rows_reordered", 
			 G_CALLBACK(on_log_store_rows_reordered),
			 widget);
	seaudit_log_store_do_filter(seaudit_app->log_store);
	add_path_to_recent_log_files(filename, &(seaudit->seaudit_conf));
	set_recent_logs_submenu(&(seaudit->seaudit_conf));
	save_seaudit_conf_file(&(seaudit_app->seaudit_conf));
	log_load_signal_emit();
	clear_wait_cursor(GTK_WIDGET(seaudit_app->top_window));
	return 0;
}

/* When a row is selected and then log sorted, scroll to the selected row */
static void on_log_store_rows_reordered(GtkTreeModel *model, GtkTreePath *arg1, GtkTreeIter *arg2, 
					gpointer arg3, gpointer user_data)
{
	GtkTreeSelection *selection;
	GList *selected_rows;
	GtkTreePath *path;
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(user_data));
	selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
	if (selected_rows == NULL)
		return;
	path = selected_rows->data;
	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(user_data), 
				     path, NULL, FALSE, 0.0, 0.0);
}

/*
 * We don't want to do the heavy work of loading and displaying the log
 * and policy before the main loop has started because it will freeze
 * the gui for too long. To solve this, the function is called from an
 * idle callback set-up in main.
 */
typedef struct filename_data {
	GString *log_filename;
	GString *policy_filename;
} filename_data_t;

gboolean delayed_main(gpointer data)
{
	filename_data_t *filenames = (filename_data_t*)data;

	if (filenames->log_filename) {
		seaudit_open_log_file(seaudit_app, filenames->log_filename->str);
		g_string_free(filenames->log_filename, TRUE);
	}
	if (filenames->policy_filename) {
		seaudit_open_policy(seaudit_app, filenames->policy_filename->str);
		g_string_free(filenames->policy_filename, TRUE);
	}
	return FALSE;
}

static void print_version_info(void)
{
	printf("Audit Log analysis tool for Security Enhanced Linux\n\n");
	printf("   GUI version %s\n", SEAUDIT_GUI_VERSION_STRING);
	printf("   libapol version %s\n", VERSION_STRING);
	printf("   libseaudit version %s\n\n", LIBSEAUDIT_VERSION_STRING);
}

static void usage(const char *program_name, bool_t brief)
{
	printf("Usage:%s [options]\n", program_name);
	if (brief) {
		printf("\tTry %s --help for more help.\n", program_name);
		return;
	}
	printf("Audit Log analysis tool for Security Enhanced Linux\n\n");
	printf("   -l FILE, --log FILE     open log file named FILE\n");
	printf("   -p FILE, --policy FILE  open policy file named FILE\n");
	printf("   -h, --help              display this help and exit\n");
	printf("   -v, --version           display version information\n\n");
	return;
}

void parse_command_line(int argc, char **argv, GString **policy_filename, GString **log_filename)
{
	int optc;
	bool_t help, ver;

	help = ver = FALSE;
	g_assert(*log_filename == NULL);
	g_assert(*policy_filename == NULL);
	while ( (optc = getopt_long(argc, argv, "l:p:hv", opts, NULL)) != -1)
	{
		switch(optc) {
		case 'l':
			*log_filename = g_string_new("");
			g_string_assign(*log_filename, optarg);
			break;
		case 'p':
			*policy_filename = g_string_new("");
			g_string_assign(*policy_filename, optarg);
			break;
		case '?': /* unrecognized argument give full usage */
			usage(argv[0], FALSE);
			goto exit_main;
		case 'h':
			help = TRUE;
			break;
		case 'v':
			ver = TRUE;
			break;
		default:
			break;
		}
	}
	if (help || ver) {
		if (help)
			usage(argv[0], FALSE);
		if (ver)
			print_version_info();
		goto exit_main;
	}
	if (optind < argc) { /* trailing non-options */
		printf("non-option arguments: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		goto exit_main;
	}
	return;

 exit_main:
	if (*log_filename)
		g_string_free(*log_filename, TRUE);
	if (*policy_filename)
		g_string_free(*policy_filename, TRUE);
	exit(1);
}

int main(int argc, char **argv)
{
	GtkWidget *widget;
	filename_data_t filenames;

	filenames.policy_filename = filenames.log_filename = NULL; 			
	parse_command_line(argc, argv, &filenames.policy_filename, &filenames.log_filename);
	gtk_init(&argc, &argv);
	glade_init();

	seaudit_app = seaudit_init();
	if (!seaudit_app)
		exit(1);

	load_seaudit_conf_file(&(seaudit_app->seaudit_conf));
	set_recent_policys_submenu(&(seaudit_app->seaudit_conf));
	set_recent_logs_submenu(&(seaudit_app->seaudit_conf));

	/* if no files were given on the command line then use the 
         * current user-saved default filenames */
	if (filenames.log_filename == NULL)
		if (seaudit_app->seaudit_conf.default_log_file)
			filenames.log_filename = g_string_new(seaudit_app->seaudit_conf.default_log_file);
	if (filenames.policy_filename == NULL)
		if (seaudit_app->seaudit_conf.default_policy_file)
			filenames.policy_filename = g_string_new(seaudit_app->seaudit_conf.default_policy_file);

	widget = glade_xml_get_widget(seaudit_app->top_window_xml, "LogListView");
	create_list(GTK_TREE_VIEW(widget));
	seaudit_app->log_store = (SEAuditLogStore*)gtk_tree_view_get_model(GTK_TREE_VIEW(widget));
	update_status_bar(NULL);
	update_title_bar(NULL);
	
	policy_load_callback_register(&update_status_bar, NULL);
	log_load_callback_register(&update_status_bar, NULL);
	policy_load_callback_register(&update_title_bar, NULL);
	log_load_callback_register(&update_title_bar, NULL);
	log_filtered_callback_register(&update_status_bar, NULL);
	/* finish loading later */
	g_idle_add(&delayed_main, &filenames);

	/* connect signal handlers */
	glade_xml_signal_autoconnect(seaudit_app->top_window_xml);

	/* go */
	gtk_main();

	return 0;
}

void show_wait_cursor(GtkWidget *widget)
{
	GdkCursor *cursor = NULL;

	/* set the cursor to a watch */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(widget->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();
}

/*
 * WARNING: this is sort of a hack
 *
 * If we reset the pointer at the end of a callback, it
 * gets reset too soon (i.e. before all of the pending events have
 * been processed. To avoid this, this function is put in an idle
 * handler by clear_wait_cursor.
 */
static gboolean pointer_reset(gpointer data)
{
	gdk_window_set_cursor(GTK_WIDGET(data)->window, NULL);
	return FALSE;
}

void clear_wait_cursor(GtkWidget *widget)
{
	g_idle_add(&pointer_reset, widget);
}

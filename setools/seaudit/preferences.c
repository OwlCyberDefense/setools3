/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * Date: December 31, 2003
 */

#include "preferences.h"
#include "utilgui.h"
#include "seaudit.h"

extern seaudit_t *seaudit_app;

/* static functions called only if preferences window is open */
static void on_preference_toggled(GtkToggleButton *toggle, gpointer user_data);
static void on_browse_policy_button_clicked(GtkWidget *widget, gpointer user_data);
static void on_browse_log_button_clicked(GtkWidget *widget, gpointer user_data);


void set_seaudit_conf_default_policy(seaudit_conf_t *conf, const char *filename)
{
	if (conf->default_policy_file)
		free(conf->default_policy_file);
	if (filename) {
		conf->default_policy_file = (char*)malloc(sizeof(char) * (1 + strlen(filename)));
		strcpy(conf->default_policy_file, filename);
	} else 
		conf->default_policy_file = NULL;
}

void set_seaudit_conf_default_log(seaudit_conf_t *conf, const char *filename)
{
	if (conf->default_log_file)
		free(conf->default_log_file);

	if (filename) {
		conf->default_log_file = (char*)malloc(sizeof(char) * (1 + strlen(filename)));
		strcpy(conf->default_log_file, filename);
	} else
		conf->default_log_file = NULL;
}

int load_seaudit_conf_file(seaudit_conf_t *conf)
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
	if (!value)
		conf->real_time_log = FALSE;
	else  {
		conf->real_time_log = atoi(value);
		free(value);
	}
	fclose(file);
	return 0;
}

void add_path_to_recent_log_files(const char *path, seaudit_conf_t *conf_file)
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

void add_path_to_recent_policy_files(const char *path, seaudit_conf_t *conf_file)
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

int save_seaudit_conf_file(seaudit_conf_t *conf)
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

void free_seaudit_conf(seaudit_conf_t *conf_file)
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

void update_column_visibility(seaudit_filtered_view_t *view, gpointer user_data)
{
	GList *columns;
	GtkTreeViewColumn *col = NULL;

	columns = gtk_tree_view_get_columns(view->tree_view);
	while (columns != NULL) {
		col = GTK_TREE_VIEW_COLUMN(columns->data);
		gtk_tree_view_column_set_visible(col, seaudit_app->seaudit_conf.column_visibility[
						 gtk_tree_view_column_get_sort_column_id(col)]);
		columns = g_list_next(columns);
	}	
}

void on_prefer_window_ok_button_clicked(GtkWidget *widget, gpointer user_data)
{
	GtkWidget *prefer_window;
	GladeXML *xml = (GladeXML*)user_data;
	GtkEntry *log_entry, *pol_entry;

	prefer_window = glade_xml_get_widget(xml, "PreferWindow");
	g_assert(widget);
	log_entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultLogEntry"));
	g_assert(log_entry);
	pol_entry = GTK_ENTRY(glade_xml_get_widget(xml, "DefaultPolicyEntry"));
	g_assert(pol_entry);
	set_seaudit_conf_default_log(&(seaudit_app->seaudit_conf),
				     gtk_entry_get_text(log_entry));
	set_seaudit_conf_default_policy(&(seaudit_app->seaudit_conf),
					gtk_entry_get_text(pol_entry));
	save_seaudit_conf_file(&(seaudit_app->seaudit_conf));

	/* set the updated visibility if needed */
	if (!seaudit_app->column_visibility_changed)
		return;
	g_list_foreach(seaudit_app->window->views, (GFunc)update_column_visibility, NULL);
	seaudit_app->column_visibility_changed = FALSE;
	gtk_widget_destroy(prefer_window);
}

static void on_browse_log_button_clicked(GtkWidget *widget, gpointer user_data)
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

static void on_browse_policy_button_clicked(GtkWidget *widget, gpointer user_data)
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

static void on_preference_toggled(GtkToggleButton *toggle, gpointer user_data)
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

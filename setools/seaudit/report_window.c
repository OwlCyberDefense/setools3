/* Copyright (C) 2004-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information 
 *
 * Author: Don Patterson <don.patterson@tresys.com>
 * Date: December 01, 2004
 *
 */
 
#include "report_window.h"
#include "filtered_view.h"
#include "utilgui.h"
#include <string.h>
#include <assert.h>

/* Initializes the dialog widgets when it is displayed */
static void initialize(report_window_t *report_window)
{
	GtkWidget *widget;
	
	gtk_window_set_title(report_window->window, report_window->window_title->str);
	
	/* Configure checkbuttons and their state (i.e. enabled or disabled). Please
	 * note that all checkbuttons must be initially set ON before this function is 
	 * called, in order for initialization to work correctly. */		
	widget = glade_xml_get_widget(report_window->xml, "check_button_malformed_msgs");
	g_assert(widget);
	if (report_window->report_info->malformed)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), FALSE);
		
	if (report_window->report_info->html) {
		widget = glade_xml_get_widget(report_window->xml, "radiobutton_html_format");
		g_assert(widget);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		widget = glade_xml_get_widget(report_window->xml, "checkbutton_use_stylesheet");
		gtk_widget_set_sensitive(widget, TRUE);	
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		gtk_widget_set_sensitive(widget, TRUE);	
		widget = glade_xml_get_widget(report_window->xml, "browse_css_button");
		gtk_widget_set_sensitive(widget, TRUE);
	} else {
		widget = glade_xml_get_widget(report_window->xml, "radiobutton_plaintext_format");
		g_assert(widget);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		widget = glade_xml_get_widget(report_window->xml, "checkbutton_use_stylesheet");
		gtk_widget_set_sensitive(widget, FALSE);	
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		gtk_widget_set_sensitive(widget, FALSE);	
		widget = glade_xml_get_widget(report_window->xml, "browse_css_button");
		gtk_widget_set_sensitive(widget, FALSE);
	}
	
	widget = glade_xml_get_widget(report_window->xml, "checkbutton_use_stylesheet");
	g_assert(widget);
	if (report_window->report_info->use_stylesheet) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		gtk_widget_set_sensitive(widget, TRUE);	
		widget = glade_xml_get_widget(report_window->xml, "browse_css_button");
		gtk_widget_set_sensitive(widget, TRUE);
	} else {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), FALSE);	
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		gtk_widget_set_sensitive(widget, FALSE);	
		widget = glade_xml_get_widget(report_window->xml, "browse_css_button");
		gtk_widget_set_sensitive(widget, FALSE);		
	}
	
	/* Configure radiobuttons and their state */
	if (report_window->use_entire_log) {
		widget = glade_xml_get_widget(report_window->xml, "radiobutton_entire_log");
		g_assert(widget);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	} else {
		widget = glade_xml_get_widget(report_window->xml, "radiobutton_current_view");
		g_assert(widget);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), TRUE);
	}

	if (report_window->report_info->configPath != NULL) {
		widget = glade_xml_get_widget(report_window->xml, "entry_report_config");
		g_assert(widget);
		gtk_entry_set_text(GTK_ENTRY(widget), report_window->report_info->configPath);
	}

	if (report_window->report_info->stylesheet_file != NULL) {
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		g_assert(widget);
		gtk_entry_set_text(GTK_ENTRY(widget), report_window->report_info->stylesheet_file);
	}
}

static void hide_window(report_window_t *report_window)
{
	if (report_window->window) {
		gtk_widget_destroy(GTK_WIDGET(report_window->window));
		report_window->window = NULL;
	}
}

void on_cancel_activate(GtkButton *button, gpointer user_data)
{
	report_window_t *report_window = (report_window_t*)user_data;
	hide_window(report_window);
}

static void on_destroy(GtkWidget *widget, GdkEvent *event, report_window_t *report_window)
{
	hide_window(report_window);
}

static void on_change_log_radio_button(GtkToggleButton *button, gpointer user_data) 
{
	report_window_t *report_window = (report_window_t*)user_data;
	GtkWidget *widget;
	
	if (strcmp("radiobutton_entire_log", gtk_widget_get_name(GTK_WIDGET(button))) == 0) {
		report_window->use_entire_log = TRUE;
		widget = glade_xml_get_widget(report_window->xml, "check_button_malformed_msgs");
		gtk_widget_set_sensitive(widget, TRUE);	
	}
	else if (strcmp("radiobutton_current_view", gtk_widget_get_name(GTK_WIDGET(button))) == 0) {
		report_window->use_entire_log = FALSE;
		widget = glade_xml_get_widget(report_window->xml, "check_button_malformed_msgs");
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(widget), FALSE);
		gtk_widget_set_sensitive(widget, FALSE);	
	}
}

static void on_change_format_radio_button(GtkToggleButton *button, gpointer user_data) 
{
	report_window_t *report_window = (report_window_t*)user_data;
	GtkWidget *widget;
	
	if (strcmp("radiobutton_plaintext_format", gtk_widget_get_name(GTK_WIDGET(button))) == 0) {
		report_window->report_info->html = FALSE;
		widget = glade_xml_get_widget(report_window->xml, "checkbutton_use_stylesheet");
		gtk_widget_set_sensitive(widget, FALSE);	
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		gtk_widget_set_sensitive(widget, FALSE);	
		widget = glade_xml_get_widget(report_window->xml, "browse_css_button");
		gtk_widget_set_sensitive(widget, FALSE);	
	} else if (strcmp("radiobutton_html_format", gtk_widget_get_name(GTK_WIDGET(button))) == 0) {
		report_window->report_info->html = TRUE;
		widget = glade_xml_get_widget(report_window->xml, "checkbutton_use_stylesheet");
		gtk_widget_set_sensitive(widget, TRUE);	
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		gtk_widget_set_sensitive(widget, TRUE);	
		widget = glade_xml_get_widget(report_window->xml, "browse_css_button");
		gtk_widget_set_sensitive(widget, TRUE);		
	}
}

static void on_click_stylesheet_checkbutton(GtkToggleButton *button, gpointer user_data) 
{
	report_window_t *report_window = (report_window_t*)user_data;
	GtkWidget *widget;
	
	if (gtk_toggle_button_get_active(button)) {
		report_window->report_info->use_stylesheet = TRUE;
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		gtk_widget_set_sensitive(widget, TRUE);	
		widget = glade_xml_get_widget(report_window->xml, "browse_css_button");
		gtk_widget_set_sensitive(widget, TRUE);
	} else if (strcmp("radiotutton_html_format", gtk_widget_get_name(GTK_WIDGET(button))) == 0) {
		report_window->report_info->use_stylesheet = FALSE;	
		widget = glade_xml_get_widget(report_window->xml, "entry_stylesheet");
		gtk_widget_set_sensitive(widget, FALSE);	
		widget = glade_xml_get_widget(report_window->xml, "browse_css_button");
		gtk_widget_set_sensitive(widget, FALSE);		
	}
}

static void on_create_report_button_clicked(GtkButton *button, gpointer user_data)
{
	report_window_t *report_window = (report_window_t*)user_data;
	GString *filename = NULL;
	GString *msg;
	seaudit_filtered_view_t *filtered_view;
	audit_log_view_t *log_view;
	GtkEntry *entry;
	const gchar *file_path = NULL;
			
	assert(report_window != NULL);
	filename = get_filename_from_user("Save Report to File", NULL, report_window->window, TRUE);
	if (filename == NULL)
		return;
	
	if (report_window->report_info->outFile)
		free(report_window->report_info->outFile);
	if (seaudit_report_add_outFile_path(filename->str, report_window->report_info) != 0)
		return;
		
	filtered_view = seaudit_window_get_current_view(report_window->parent);
	if (filtered_view == NULL)
		return;
	if (filtered_view->store == NULL)
		return;
	log_view = filtered_view->store->log_view;
						
	/* Set reference to the entire log */
	report_window->report_info->log = log_view->my_log;
			
	/* Set the global view for the report generation to use. */	
	if (!report_window->use_entire_log) {
		report_window->report_info->log_view = log_view;
	}
	
	entry = GTK_ENTRY(glade_xml_get_widget(report_window->xml, "entry_stylesheet"));
	g_assert(entry);
	if (report_window->report_info->stylesheet_file) {
		free(report_window->report_info->stylesheet_file);
		report_window->report_info->stylesheet_file = NULL;
	}
	file_path = gtk_entry_get_text(GTK_ENTRY(entry));
	if (!str_is_only_white_space(file_path))
		seaudit_report_add_stylesheet_path(file_path, report_window->report_info);
	
	entry = GTK_ENTRY(glade_xml_get_widget(report_window->xml, "entry_report_config"));
	g_assert(entry);
	if (report_window->report_info->configPath) {
		free(report_window->report_info->configPath);
		report_window->report_info->configPath = NULL;
	}
	file_path = gtk_entry_get_text(GTK_ENTRY(entry));
	if (!str_is_only_white_space(file_path))
		seaudit_report_add_configFile_path(file_path, report_window->report_info);
		
	/* Generate the report */
	if (seaudit_report_generate_report(report_window->report_info) != 0) {
		msg = g_string_new("Error generating report!\n");
		message_display(report_window->parent->window, GTK_MESSAGE_ERROR, msg->str);
		g_string_free(msg, TRUE);
	} else {
		msg = g_string_new("Report generated successfully.\n");
		message_display(report_window->parent->window, GTK_MESSAGE_INFO, msg->str);
		g_string_free(msg, TRUE);
		/* if everything worked correctly hide the report window */
		hide_window(report_window);
	}
	report_window->report_info->log_view = NULL;
	report_window->report_info->log = NULL;
}

static void on_incl_malformed_check_button_toggled(GtkToggleButton *button, gpointer user_data)
{
	report_window_t *report_window = (report_window_t*)user_data;

	if (gtk_toggle_button_get_active(button)) {
		report_window->report_info->malformed = TRUE;
	} else {
		report_window->report_info->malformed = FALSE;
	}	
}

static void on_browse_report_config_button_clicked(GtkButton *button, gpointer user_data)
{
	report_window_t *report_window = (report_window_t*)user_data;
	GtkEntry *entry;
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;

	entry = GTK_ENTRY(glade_xml_get_widget(report_window->xml, "entry_report_config"));
	g_assert(entry);
	file_selector = gtk_file_selection_new("Select Alternate Config File");
	/* set this window to be transient on the report window, so that when it pops up it gets centered on it */
	gtk_window_set_transient_for(GTK_WINDOW(file_selector), report_window->window);

	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (report_window->report_info->configPath != NULL)
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

static void on_browse_report_css_button_clicked(GtkButton *button, gpointer user_data)
{
	report_window_t *report_window = (report_window_t*)user_data;
	GtkEntry *entry;
	GtkWidget *file_selector;
	gint response;
	const gchar *filename;

	entry = GTK_ENTRY(glade_xml_get_widget(report_window->xml, "entry_stylesheet"));
	g_assert(entry);
	file_selector = gtk_file_selection_new("Select Alternate Stylesheet");
	/* set this window to be transient on the report window, so that when it pops up it gets centered on it */
	gtk_window_set_transient_for(GTK_WINDOW(file_selector), report_window->window);
	gtk_file_selection_hide_fileop_buttons(GTK_FILE_SELECTION(file_selector));
	if (report_window->report_info->stylesheet_file != NULL)
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

/* All arguments are optional; NULL can be passed instead. */
report_window_t *report_window_create(seaudit_window_t *parent, seaudit_conf_t *seaudit_conf, const char *title)
{
	report_window_t *report_window = NULL;
	
	report_window = (report_window_t *)malloc(sizeof(report_window_t));
	if (report_window == NULL) {
		fprintf(stderr, "Out of memory.");
		return NULL;
	}
	memset(report_window, 0, sizeof(report_window_t));

	report_window->window = NULL;
	report_window->xml = NULL;
	if (parent) 
		report_window->parent = parent;
	if (title) 
		report_window->window_title = g_string_new(title);
	else
		report_window->window_title = g_string_new("");
		
	report_window->report_info = seaudit_report_create();
	if (!report_window->report_info) {
		goto err;
	}
	
	/* Set report default config and css file paths from the seaudit_conf file. */
	if (seaudit_conf != NULL) {
		if (seaudit_report_add_stylesheet_path(seaudit_conf->default_seaudit_report_css_file, 
				report_window->report_info) != 0)
	  				goto err;
	  	if (seaudit_report_add_configFile_path(seaudit_conf->default_seaudit_report_config_file, 
	  			report_window->report_info) != 0)
	  				goto err;	  			
	}
	
	return report_window;
err:
	report_window_destroy(report_window);
	return NULL;
}

void report_window_destroy(report_window_t *report_window)
{
	if (report_window == NULL)
		return;
	
	if (report_window->window_title)
		g_string_free(report_window->window_title, TRUE);
	if (report_window->window != NULL)
		gtk_widget_destroy(GTK_WIDGET(report_window->window));
	if (report_window->xml != NULL)
		g_object_unref(G_OBJECT(report_window->xml));
		
	/* Destroy the report info object associated with the dialog. 
	 * This holds the info used to generate the report. */
	seaudit_report_destroy(report_window->report_info);
			
	free(report_window);		
}

void report_window_display(report_window_t *report_window)
{
	GladeXML *xml;
	GtkWindow *window;
	GtkWidget *widget;
	GString *path;
	char *dir;

	if (!report_window)
		return;

	if (report_window->window) {
		gtk_window_present(report_window->window);
		return;
	}
	dir = find_file("report_window.glade");
	if (!dir){
		fprintf(stderr, "Error: Could not find report_window.glade!\n");
		return;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append(path, "/report_window.glade");
	xml = glade_xml_new(path->str, "window_standard_report", NULL);
	g_string_free(path, TRUE);
	g_assert(xml);
	
	window = GTK_WINDOW(glade_xml_get_widget(xml, "window_standard_report"));
	g_assert(window);
	/* set this window to be transient on the report window, so that when it pops up it gets centered on it */
	/* however to have it "appear" to be centered we have to hide and then show */
	gtk_window_set_transient_for(window, report_window->parent->window);
	gtk_window_set_position(window, GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_widget_hide(GTK_WIDGET(window));
	gtk_window_present(window);
		
	report_window->window = window;
	report_window->xml = xml;

	g_signal_connect(G_OBJECT(window), "delete_event", 
			 G_CALLBACK(on_destroy), report_window);
	
	glade_xml_signal_connect_data(xml, "on_radiobutton_log_changed", 
				      G_CALLBACK(on_change_log_radio_button),
				      report_window);
				     
	glade_xml_signal_connect_data(xml, "on_radiobutton_format_changed", 
				      G_CALLBACK(on_change_format_radio_button),
				      report_window);
				      
	glade_xml_signal_connect_data(xml, "on_checkbutton_use_stylesheet_clicked", 
				      G_CALLBACK(on_click_stylesheet_checkbutton),
				      report_window);
				      
	widget = glade_xml_get_widget(xml, "browse_config_button");
	gtk_signal_connect(GTK_OBJECT(widget), "clicked", GTK_SIGNAL_FUNC(on_browse_report_config_button_clicked), report_window);
	widget = glade_xml_get_widget(xml, "browse_css_button");
	gtk_signal_connect(GTK_OBJECT(widget), "clicked", GTK_SIGNAL_FUNC(on_browse_report_css_button_clicked), report_window);
	widget = glade_xml_get_widget(xml, "create_report_button");
	gtk_signal_connect(GTK_OBJECT(widget), "clicked", GTK_SIGNAL_FUNC(on_create_report_button_clicked), report_window);
	widget = glade_xml_get_widget(xml, "cancel_button");
	gtk_signal_connect(GTK_OBJECT(widget), "clicked", GTK_SIGNAL_FUNC(on_cancel_activate), report_window);
	
	
	widget = glade_xml_get_widget(xml, "check_button_malformed_msgs");
	gtk_signal_connect(GTK_OBJECT(widget), "toggled", GTK_SIGNAL_FUNC(on_incl_malformed_check_button_toggled), report_window);

	/* Restore previous values and selections for the filter dialog */
	initialize(report_window);
}

/* Copyright (C) 2005-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Brandon Whalen <bwhalen@tresys.com>
 * Date: August 8, 2005
 */
#include "sediff_find_window.h"
#include "utilgui.h"

/* hide we don't actually destroy the widget we just hide it */
static void sediff_find_window_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_hide(widget);
}

/* hide the find window */
static void sediff_find_close_button_clicked(GtkButton *button, gpointer user_data)
{
	sediff_find_window_t *find_window;

	find_window = (sediff_find_window_t*)user_data;
	gtk_widget_hide(GTK_WIDGET(find_window->window));
}

/* highlight text between to iters in the text buffer txt */
static void sediff_scroll_and_highlight_iters(GtkTextView *view, GtkTextBuffer *txt, 
					      GtkTextIter *start, GtkTextIter *end)
{
	gtk_text_view_scroll_to_iter(view, start, 0.0, FALSE, 0.0, 0.5);			
	gtk_text_view_set_cursor_visible(view, TRUE);
	gtk_text_buffer_place_cursor(txt, start);
	/* highlight */
	gtk_text_buffer_select_range(txt,start,end);
}

/* This function gets the value stored in the GtkEntry(entry) and searches the 
   current text buffer visible to the user for that string, then highlights the 
   items found */
static void sediff_find_search_buffer(gpointer user_data)
{
	GtkTextBuffer *gui_txt = NULL;
	sediff_find_window_t *find_window = NULL;
	GtkEntry *entry = NULL;
	GtkToggleButton *fwd = NULL;
	GtkTextIter start,end;
	GtkTextView *view = NULL;
	GString *string;

	/* grab the find window */
	find_window = (sediff_find_window_t*)user_data;
	/* get the current textview displayed to the user */
	view = sediff_get_current_view(find_window->sediff_app);
	if (view != NULL) {
		gui_txt = gtk_text_view_get_buffer(view);
	} else {
		return;
	}
	/* user our stored offsets to move to the last position in the view,
	   these are reset when we switch users by the gui */
	gtk_text_buffer_get_iter_at_offset(gui_txt,&start,find_window->start_offset);
	gtk_text_buffer_get_iter_at_offset(gui_txt,&end,find_window->end_offset);		
	sediff_scroll_and_highlight_iters(view,gui_txt,&start,&end);

	/* now we actually search for the text  */
	fwd = GTK_TOGGLE_BUTTON(glade_xml_get_widget(find_window->xml, FIND_FORWARD_ID));
	entry = GTK_ENTRY(glade_xml_get_widget(find_window->xml, FIND_ENTRY_ID));
	/* find out which radio button is selected */
	if (gtk_toggle_button_get_active (fwd)) {
		if (gtk_text_iter_forward_search(&end,gtk_entry_get_text(entry),
						   GTK_TEXT_SEARCH_VISIBLE_ONLY,&start,&end,NULL)){
			sediff_scroll_and_highlight_iters(view,gui_txt,&start,&end);
			find_window->start_offset = gtk_text_iter_get_offset(&start);
			find_window->end_offset = gtk_text_iter_get_offset(&end);
		} else {
			string = g_string_new("");
			g_string_printf(string,"Text \"%s\" not found.",gtk_entry_get_text(entry));
			message_display(find_window->window,GTK_MESSAGE_INFO,string->str);
			g_string_free(string,TRUE);
		}
	} else {
		if (gtk_text_iter_backward_search(&start,gtk_entry_get_text(entry),
						   GTK_TEXT_SEARCH_VISIBLE_ONLY,&start,&end,NULL)){
			sediff_scroll_and_highlight_iters(view,gui_txt,&start,&end);
			find_window->start_offset = gtk_text_iter_get_offset(&start);
			find_window->end_offset = gtk_text_iter_get_offset(&end);
		} else {
			string = g_string_new("");
			g_string_printf(string,"Text \"%s\" not found.",gtk_entry_get_text(entry));
			message_display(find_window->window,GTK_MESSAGE_INFO,string->str);
			g_string_free(string,TRUE);
		}
	}

}

/* This function is called when the user presses enter in the GtkEntry */
static void  on_sediff_find_entry_activated(GtkEntry *entry, gpointer user_data)
{
	if (user_data == NULL)
		return;
	sediff_find_search_buffer(user_data);
}


/* called when the find button is clicked */
static void sediff_find_button_clicked(GtkButton *button, gpointer user_data)
{
	if (user_data == NULL)
		return;
	sediff_find_search_buffer(user_data);
}

/* function to create a find window */
static int sediff_find_window_init(sediff_find_window_t *find_window)
{
	GtkButton *button = NULL;
	GString *path = NULL;
	char *dir=NULL;
	GtkEntry *entry = NULL;

	if (find_window == NULL)
		return -1;

	dir = find_file(GLADEFILE);
	if (!dir){
		fprintf(stderr, "Could not find %s!", GLADEFILE);
		return -1;
	}
	path = g_string_new(dir);
	free(dir);
	g_string_append_printf(path, "/%s", GLADEFILE);

	/* get the xml */
	find_window->xml = glade_xml_new(path->str, FIND_DIALOG_ID, NULL);
	g_assert(find_window->xml);
	g_string_free(path, TRUE);

	/* get a window reference from xml*/
	find_window->window = GTK_WINDOW(glade_xml_get_widget(find_window->xml, FIND_DIALOG_ID));
	g_assert(find_window->window);
	gtk_window_set_transient_for(find_window->window, find_window->sediff_app->window);
	gtk_window_set_position(find_window->window, GTK_WIN_POS_CENTER_ON_PARENT);

        /* connect to the window delete event */
	g_signal_connect(G_OBJECT(find_window->window), "delete_event", 
			 G_CALLBACK(sediff_find_window_dialog_on_window_destroy), find_window);
	glade_xml_signal_autoconnect(find_window->xml);

	/* connect the button events */
	button = GTK_BUTTON(glade_xml_get_widget(find_window->xml, "sediff_find_close_button"));
	g_signal_connect(G_OBJECT(button), "clicked", 
			 G_CALLBACK(sediff_find_close_button_clicked), find_window);
	button = GTK_BUTTON(glade_xml_get_widget(find_window->xml, "sediff_find_button"));
	g_signal_connect(G_OBJECT(button), "clicked", 
			 G_CALLBACK(sediff_find_button_clicked), find_window);

	/* connect the text entry callback events */
	entry = GTK_ENTRY(glade_xml_get_widget(find_window->xml, "sediff_find_text_entry"));
	g_signal_connect(G_OBJECT(entry), "activate", 
			 G_CALLBACK(on_sediff_find_entry_activated), find_window);

	return 0;
}

sediff_find_window_t *sediff_find_window_new(struct sediff_app *sediff_app) 
{
	sediff_find_window_t *find = NULL;

	find = (sediff_find_window_t *)malloc(sizeof(sediff_find_window_t));
	if (find == NULL) {
		fprintf(stderr,"out of memory");
		return NULL;
	}
	memset(find,0,sizeof(sediff_find_window_t));
	find->sediff_app = sediff_app;
	return find;
}

void sediff_find_window_display(sediff_find_window_t *find_window)
{
	if (find_window == NULL)
		return;
	if (find_window->xml == NULL)
		sediff_find_window_init(find_window);

	gtk_window_present(find_window->window);
}

void sediff_find_window_reset_idx(sediff_find_window_t *find_window)
{
	if (find_window != NULL ) {
		find_window->start_offset = 0;
		find_window->end_offset = 0;
	}
}





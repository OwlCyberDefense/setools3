#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"



void
on_open1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
  GtkWidget *window2;
  window2 = create_dialog1 ();
  gtk_widget_show (window2);

}

void
on_quit1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
gtk_main_quit();
}


void
on_about1_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}

void
on_Help_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_cancelbutton1_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_widget_destroy(gtk_widget_get_toplevel((GtkWidget *)button));
}


void
on_Diff_clicked                        (GtkButton       *button,
                                        gpointer         user_data)
{

}


void
on_browsep1_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{

  	GtkWidget *window;
  	window = create_filechooserdialog1();
  	gtk_widget_show (window);
}


void
on_browsep2_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *window;	
	window = create_filechooserdialog2();
	gtk_widget_show(window);
}


void
on_browsep1_cancel_clicked             (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_widget_destroy(gtk_widget_get_toplevel((GtkWidget *)button));
}


void
on_browsep1_open_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	gchar *filename;
	filename = gtk_file_chooser_get_filename((GtkFileChooser *)gtk_widget_get_toplevel((GtkWidget *)button));
}


void
on_browsep2_cancel_clicked             (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_widget_destroy(gtk_widget_get_toplevel((GtkWidget *)button));
}


void
on_browsep2_open_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{

	gchar *filename;
	GtkWidget *e4;
	filename = gtk_file_chooser_get_filename((GtkFileChooser*)gtk_widget_get_toplevel((GtkWidget *)button));
	e4 = lookup_widget(gtk_widget_get_toplevel((GtkWidget *)button),("dialog_vbox3"));
}



#include "auditlog.h"
#include <stdio.h>
#include "appstruct.h"
#include "auditlogmodel.h"
#include <gtk/gtk.h> 
#include <glade/glade.h> 

/* Global Variable contains the policy and auditlog */
app_t *app_struct;

//int create_log_list_widget(GtkTreeView *view, audit_log_t *log)
int create_log_list_widget(audit_log_t *log)
{
	SEAuditLogStore *list;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkWidget *widget; 
	GtkTreeView *view;

       	widget = glade_xml_get_widget(app_struct->xml, "audit_log_treeview"); 
	view = GTK_TREE_VIEW(widget);

	list = seaudit_log_store_create(log);
	gtk_tree_view_set_model(view, GTK_TREE_MODEL(list));
	g_object_unref(G_OBJECT(list));
	
	gtk_tree_view_set_rules_hint(view, TRUE);
	renderer = gtk_cell_renderer_text_new();

	column = gtk_tree_view_column_new_with_attributes("date", renderer, "text", DATE_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("message", renderer, "text", AVC_MSG_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("object", renderer, "text", AVC_OBJ_CLASS_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("perm", renderer, "text", AVC_PERM_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("usr src", renderer, "text", AVC_SRC_USER_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("role src", renderer, "text", AVC_SRC_ROLE_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("type src", renderer, "text", AVC_SRC_TYPE_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("usr tgt", renderer, "text", AVC_TGT_USER_FIELD, NULL);
	gtk_tree_view_append_column(view, column);	
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("role tgt", renderer, "text", AVC_TGT_ROLE_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("type tgt", renderer, "text", AVC_TGT_TYPE_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("exe", renderer, "text", AVC_EXE_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);
	gtk_tree_view_column_set_sort_column_id(column, 1);
	//gtk_tree_sortable_set_sort_column();

	column = gtk_tree_view_column_new_with_attributes("path", renderer, "text", AVC_PATH_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);

	column = gtk_tree_view_column_new_with_attributes("misc", renderer, "text", AVC_MISC_FIELD, NULL);
	gtk_tree_view_append_column(view, column);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);
	return 0;
}



int main (int argc, char **argv) 
{
	int i = 5, num_results;
	
	gtk_init(&argc, &argv); 
	app_struct = app_struct_create();
	app_struct_xml_load(app_struct, "seaudit.glade");
	app_struct_audit_log_load(app_struct, "msg");
	app_struct_policy_load(app_struct, "policy.conf");

	create_log_list_widget(app_struct->log);
       	glade_xml_signal_autoconnect(app_struct->xml);

	/* start the main event loop */
	gtk_main();
      	app_struct_destroy(app_struct);
	return 0; 
} 

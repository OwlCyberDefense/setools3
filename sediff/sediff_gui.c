/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: Don Patterson <don.patterson@tresys.com>
 * Author: Brandon Whalen <bwhalen@tresys.com>
 * Date: January 31, 2005
 */

#include "sediff_gui.h"
#include "sediff_treemodel.h"
#include "utilgui.h"

/* libapol */
#include <policy.h>
#include <policy-io.h>
#include <poldiff.h>
#include <render.h>
#include <binpol/binpol.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <time.h>

/* The following should be defined in the make environment */
#ifndef SEDIFF_GUI_VERSION_NUM
	#define SEDIFF_GUI_VERSION_NUM "UNKNOWN"
#endif

#ifndef COPYRIGHT_INFO
        #define COPYRIGHT_INFO "Copyright (C) 2004-2005 Tresys Technology, LLC"
#endif
#define SEDIFF_GUI_PROG	"sediffx"


#define GLADEFILE 	"sediff.glade"
#define MAIN_WINDOW_ID 	"sediff_main_window"
#define OPEN_DIALOG_ID 	"sediff_dialog"
#define LOADING_DIALOG_ID "sediff_loading"
#define MAXMYFILELEN     100
#define TABSIZE          4


sediff_app_t *sediff_app = NULL;

gboolean toggle = TRUE;
gint curr_option = OPT_CLASSES; 


static struct option const longopts[] =
{
  {"classes", no_argument, NULL, 'c'},
  {"types", no_argument, NULL, 't'},
  {"roles", no_argument, NULL, 'r'},
  {"users", no_argument, NULL, 'u'},
  {"booleans", no_argument, NULL, 'b'},
  {"initialsids", no_argument, NULL, 'i'},
  {"terules", no_argument, NULL, 'T'},
  {"rbacrules", no_argument, NULL, 'R'},
  {"conds", no_argument, NULL, 'C'},
  {"stats", no_argument, NULL, 's'},
  {"gui", no_argument, NULL, 'X'},
  {"quiet", no_argument, NULL, 'q'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};



/* Generic function prototype for getting policy components */
typedef int(*get_iad_name_fn_t)(int idx, char **name, policy_t *policy);
typedef void(*sediff_callback_t)(void *user_data);

typedef struct registered_callback {
	GSourceFunc function; 	/* gboolean (*GSourceFunc)(gpointer data); */
	void *user_data;
	unsigned int type;

/* callback types */
#define LISTBOX_SELECTED_CALLBACK   0
#define LISTBOX_SELECTED_SIGNAL     LISTBOX_SELECTED_CALLBACK
} registered_callback_t;

#define row_selected_signal_emit() sediff_callback_signal_emit(LISTBOX_SELECTED_SIGNAL)

static void sediff_callback_signal_emit(unsigned int type);
static void txt_view_populate_buffers(apol_diff_t *stuff_removed,
				     apol_diff_t *stuff_added,
				     policy_t *policy_old,
				     policy_t *policy_new);

/* internal fcns */
static void txt_view_switch_buffer(GtkTextView *textview,gint option,gint policy_option);
static int sediff_diff_and_load_policies(const char *p1_file,const char *p2_file, bool_t new_files);
static void sediff_populate_buffer_hdrs();
static void sediff_update_status_bar();
static void sediff_rename_policy_tabs(const char *p1,const char *p2) ;
static void txt_buffer_insert_summary_results();
static char *sediff_get_tab_spaces(int numspaces);
static void sediff_loading_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data);
void sediff_menu_on_reload_clicked(GtkMenuItem *menuitem, gpointer user_data);


void usage(const char *program_name, int brief)
{
	printf("%s (sediff ver. %s)\n\n", COPYRIGHT_INFO, SEDIFF_VERSION_NUM);
	printf("Usage: %s [OPTIONS]\n", program_name);
	printf("Usage: %s [POLICY1 POLICY2]\n",program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Semantically differentiate two policies.  The policies can be either source\n\
or binary policy files, version 15 or later.  By default, all supported\n\
policy elements are examined.  The following diff options are available:\n\
", stdout);
	fputs("\n\
  -h, --help       display this help and exit\n\
  -v, --version    output version information and exit\n\n\
", stdout);
	return;
}



/* allocate a string that creates a "tab" of numspaces
   user in charge of freeing */
static char *sediff_get_tab_spaces(int numspaces)
{
	char *c;
	int i;

	c = (char *)malloc(sizeof(char)*(numspaces+1));
	for (i = 0; i<numspaces; i++) {
		c[i] = ' ';
	}
	c[numspaces] = '\0'; 

	return c;
}

static void sediff_clear_text_buffer(GtkTextBuffer *txt)
{
	GtkTextIter start,end;
	
	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	gtk_text_buffer_delete(txt, &start, &end);
}

static void sediff_callback_signal_emit_1(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t *)data;
	unsigned int type = *(unsigned int*)user_data;
	if (callback->type == type) {
		gpointer data = &callback->user_data;
		g_idle_add_full(G_PRIORITY_HIGH_IDLE+10, callback->function, &data, NULL);
	}
	return;
}

/* the signal emit function executes each function registered with 
 * sediff_callback_register() */
void sediff_callback_signal_emit(unsigned int type)
{

	g_list_foreach(sediff_app->callbacks, &sediff_callback_signal_emit_1, &type);
	return;
}

static int print_iad_element(GtkTextBuffer *txt, GtkTextIter *txt_iter, GString *string,
			     GtkTextTag *tag,int_a_diff_t *diff,policy_t *policy,bool_t added,
			     char *adescrp,get_iad_name_fn_t get_a_name)
{
	int i;
	char *tmp;
	int rt;
	for (i = 0; i < diff->numa; i++) {
		rt = (*get_a_name)(diff->a[i], &tmp, policy);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, diff->a[i]);
			return -1;
		}
		if (added)
			g_string_printf(string, "\t\t\t+ %s\n", tmp);
		else
			g_string_printf(string, "\t\t\t- %s\n", tmp);
		gtk_text_buffer_insert_with_tags(txt, txt_iter, string->str, 
							 -1, tag, NULL);
		gtk_text_buffer_get_end_iter(txt, txt_iter);		
		free(tmp);
	}
	return 0;
}


static int get_iad_buffer(GtkTextBuffer *txt, GtkTextIter *txt_iter,GString *string, 
			  int id, int_a_diff_t *iad_removed, int_a_diff_t *iad_added, 
			  policy_t *p_old, policy_t *p_new,summary_node_t *summary_node)
{
	get_iad_name_fn_t get_name, get_a_name;
	char *name, *name2, *descrp = NULL, *adescrp = NULL;
	int rt, num_new, num_old,num_added,num_removed,num_changed;
	int_a_diff_t *t,*u;
	bool_t missing;
	GtkTextTag *added_tag, *removed_tag, *changed_tag;
	GtkTextTag *header_added_tag,*header_removed_tag,*header_changed_tag,*header_tag;		
	GtkTextTagTable *table;

	GtkTextMark *mark;


	/* create a mark that always goes to the left..urr top */ 	
	mark = gtk_text_buffer_get_mark(txt,"mark");
	if (!mark)
		mark = gtk_text_buffer_create_mark (txt,"added-mark",txt_iter,TRUE);
	gtk_text_buffer_get_iter_at_mark(txt,txt_iter,mark);



	/* create the tags so we can add color to our buffer */
	table = gtk_text_buffer_get_tag_table(txt);
	added_tag = gtk_text_tag_table_lookup(table, "added-tag");
	if (!added_tag) {
		added_tag = gtk_text_buffer_create_tag(txt, "added-tag",
						      "family", "monospace",
						      "foreground", "dark green", 
						      NULL);
	      
	}
	removed_tag = gtk_text_tag_table_lookup(table, "removed-tag");
	if (!removed_tag) {
		removed_tag = gtk_text_buffer_create_tag(txt, "removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 NULL);
	}
	changed_tag = gtk_text_tag_table_lookup(table, "changed-tag");
	if (!changed_tag) {
		changed_tag = gtk_text_buffer_create_tag(txt, "changed-tag",
						       "family", "monospace",
						       "foreground", "dark blue",
						       NULL);
	}
	header_removed_tag = gtk_text_tag_table_lookup(table, "header-removed-tag");
	if(!header_removed_tag) {
		header_removed_tag = gtk_text_buffer_create_tag (txt, "header-removed-tag",
						      "family", "monospace",
								 "foreground", "red",
								 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_added_tag = gtk_text_tag_table_lookup(table, "header-added-tag");
	if(!header_added_tag) {
		header_added_tag = gtk_text_buffer_create_tag (txt, "header-added-tag",
						      "family", "monospace",
							       "foreground", "dark green",
							       "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_changed_tag = gtk_text_tag_table_lookup(table, "header-changed-tag");
	if(!header_changed_tag) {
		header_changed_tag = gtk_text_buffer_create_tag (txt, "header-changed-tag",
						      "family", "monospace",
								 "foreground", "dark blue",
								 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
						      "family", "monospace",
							 "weight", PANGO_WEIGHT_BOLD,
							 "underline", PANGO_UNDERLINE_SINGLE,
							 NULL); 
	}
	
	assert(string != NULL && p_old != NULL && p_new != NULL);
	assert((id & (IDX_TYPE|IDX_ATTRIB|IDX_ROLE|IDX_USER|IDX_OBJ_CLASS|IDX_COMMON_PERM|IDX_PERM)) != 0);

	/* reset counters */
	num_added = num_removed = num_changed = 0;
	summary_node->added = 0;
	summary_node->removed = 0;
	summary_node->changed = 0;
	
	switch(id) {
	case IDX_ROLE|IDX_PERM:
		get_name = &get_role_name;
		get_a_name = &get_role_name;
		descrp = "Role Allows";
		adescrp = "Role Allows";
		num_new = p_new->num_roles;
		num_old = p_old->num_roles;
		break;
	case IDX_TYPE:
		get_name = &get_type_name;
		get_a_name = &get_attrib_name;
		descrp = "Types";
		adescrp = "Attributes";
		num_new = p_new->num_types;
		num_old = p_old->num_types;
		break;
	case IDX_ATTRIB:
		get_name = &get_attrib_name;
		get_a_name = &get_type_name;
		descrp = "Attributes";
		adescrp = "Types";
		num_new = p_new->num_attribs;
		num_old = p_old->num_attribs;
		break;
	case IDX_ROLE:
		get_name = &get_role_name;
		get_a_name = &get_type_name;
		descrp = "Roles";
		adescrp = "Types";
		num_new = p_new->num_roles;
		num_old = p_old->num_roles;
		break;
	case IDX_USER:
		get_name = &get_user_name2;
		get_a_name = &get_role_name;
		descrp = "Users";
		adescrp = "Roles";
		num_new = p_new->num_users;
		num_old = p_old->num_users;
		break;
	case IDX_OBJ_CLASS:
		get_name = &get_obj_class_name;
		get_a_name = &get_perm_name;
		descrp = "Classes";
		adescrp = "Permissions";
		num_new = p_new->num_obj_classes;
		num_old = p_old->num_obj_classes;
		break;
	case IDX_COMMON_PERM:
		get_name = &get_common_perm_name;
		get_a_name = &get_perm_name;
		descrp = "Commons";
		adescrp = "Permissions";
		num_new = p_new->num_common_perms;
		num_old = p_old->num_common_perms;
		break;
	default:
		g_return_val_if_reached(-1);
		break;
	}


	/* Handle changes */
	/* iad_added and iad_removed our linked lists ordered by their "names" 
	   so we walk down the lists comparing names, placing the diffs in alpha
	   order.  We do this so we can more easily find nodes with like names and 
	   present them correctly to the user */
	/* set the iterator up at the current mark, don't reassign iterator until done adding */
	gtk_text_buffer_get_iter_at_mark(txt,txt_iter,mark);
	/* did we add anything? */
	if (iad_added != NULL) {
		t = iad_added;
		/* did we remove anything ? */
		if (iad_removed != NULL) {
			u = iad_removed;
			while (u != NULL || t != NULL) {
				/* do we still have items on both lists */
				if (t != NULL && u != NULL) {
					rt = (*get_name)(t->idx, &name, p_new);
					if (rt < 0) {
						fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
						return -1;
					}
					rt = (*get_name)(u->idx, &name2, p_old);
					if (rt < 0) {
						fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
						return -1;
					}
					rt = strcmp(name,name2);
					/* do both items have the same name(i.e. are they the same) */
					if (rt == 0){
						/* if the item is not missing, which would mean its in both policies */
						missing = (t->a == NULL);
						if (!missing) {
							summary_node->changed += 1;
							num_changed +=1 ;
							g_string_printf(string, "\t\t* %s (%d Added, %d Removed %s)\n", name,t->numa,u->numa, adescrp);
							gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
											 -1, "changed-tag", NULL);

							rt = print_iad_element(txt,txt_iter,string,added_tag,t,p_new,TRUE,adescrp,get_a_name);
							if (rt < 0)
								return -1;
							rt = print_iad_element(txt,txt_iter,string,removed_tag,u,p_old,FALSE,adescrp,get_a_name);
							if (rt < 0)
								return -1;
						}
						u = u->next;
						t = t->next;
					}
					/* new goes first */
					else if ( rt < 0 ) {
						missing = (t->a == NULL);
						if (!missing) {
							summary_node->changed += 1;
							num_changed +=1 ;
							g_string_printf(string, "\t\t* %s (%d Added %s)\n", name, t->numa, adescrp);
							gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
											 -1, "changed-tag", NULL);
							rt = print_iad_element(txt,txt_iter,string,added_tag,t,p_new,TRUE,adescrp,get_a_name);
							if (rt < 0)
								return -1;
						}
						t = t->next;
					}
					/* old goes first */
					else {
						missing = (u->a == NULL);
						/* This means that the item exists in the new policy, so we indicate whether it has been changed. */
						if (!missing) {
							summary_node->changed += 1;
							num_changed +=1 ;
							g_string_printf(string, "\t\t* %s (%d Removed %s)\n", name2, u->numa, adescrp);
							gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
												 -1, "changed-tag", NULL);
							rt = print_iad_element(txt,txt_iter,string,removed_tag,u,p_old,FALSE,adescrp,get_a_name);
							if (rt < 0)
								return -1;
						}						
						u = u->next;
					}					
					
				}
				/* do we only have additions left? */
				else if (t != NULL) {
					rt = (*get_name)(t->idx, &name, p_new);
					if (rt < 0) {
						fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
						return -1;
					}
					missing = (t->a == NULL);
					if (!missing) {
						summary_node->changed += 1;
						num_changed +=1 ;
						g_string_printf(string, "\t\t* %s (%d Added %s)\n", name, t->numa, adescrp);
						gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
											 -1, "changed-tag", NULL);
						rt = print_iad_element(txt,txt_iter,string,added_tag,t,p_new,TRUE,adescrp,get_a_name);
						if (rt < 0)
							return -1;
					}
					free(name);
					t = t->next;
				}
				/* do we only have removes left? */
				else {
					rt = (*get_name)(u->idx, &name, p_old);
					if (rt < 0) {
						fprintf(stderr, "Problem getting name for %s %d\n", descrp, u->idx);
						return -1;
					}
					missing = (u->a == NULL);
					/* This means that the item exists in the new policy, so we indicate whether it has been changed. */
					if (!missing) {
						summary_node->changed += 1;
						num_changed +=1 ;
						g_string_printf(string, "\t\t* %s (%d Removed %s)\n", name, u->numa, adescrp);
						gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
											 -1, "changed-tag", NULL);
						rt = print_iad_element(txt,txt_iter,string,removed_tag,u,p_old,FALSE,adescrp,get_a_name);
						if (rt < 0)
							return -1;
					}
					free(name);
					u = u->next;
				}
			}
		}
		/* we have no removes just put in additions */
	        else {
			for (t = iad_added; t != NULL; t = t->next) {
				rt = (*get_name)(t->idx, &name, p_new);
				if (rt < 0) {
					fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
					return -1;
				}
				missing = (t->a == NULL);
				if (!missing) {
					summary_node->changed += 1;
					num_changed +=1 ;
					g_string_printf(string, "\t\t* %s (%d Added %s)\n", name, t->numa, adescrp);
					gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
										 -1, "changed-tag", NULL);
					rt = print_iad_element(txt,txt_iter,string,added_tag,t,p_new,TRUE,adescrp,get_a_name);
					if (rt < 0)
						return -1;

				}
			}

		}
			
	}
	/* did we only remove  ? */
	else if (iad_removed != NULL) {
		for (u = iad_removed; u != NULL; u = u->next) {
			rt = (*get_name)(u->idx, &name, p_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, u->idx);
				return -1;
			}
			missing = (u->a == NULL);
			/* This means that the item exists in the new policy, so we indicate whether it has been changed.  */
			if (!missing) {
				summary_node->changed += 1;
				num_changed +=1 ;
				g_string_printf(string, "\t\t* %s (%d Removed %s)\n", name, u->numa, adescrp);
				gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
									 -1, "changed-tag", NULL);
				rt = print_iad_element(txt,txt_iter,string,removed_tag,u,p_old,FALSE,adescrp,get_a_name);
				if (rt < 0)
					return -1;

			}
			free(name);
		}

	}
	g_string_printf(string,"\n");
	gtk_text_buffer_insert(txt,txt_iter,string->str,-1);

	/* put the changed header on */
	gtk_text_buffer_get_iter_at_mark(txt,txt_iter,mark);
	g_string_printf(string, "\tChanged %s: %d\n",descrp,summary_node->changed);
	gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
						 -1, "header-changed-tag", NULL);




	/* Handle only removed items */
	/* set the iterator up at the current mark, don't reassign iterator until done adding */
	gtk_text_buffer_get_iter_at_mark(txt,txt_iter,mark);
	if (iad_removed != NULL) {
		for (t = iad_removed; t != NULL; t = t->next) {
			rt = (*get_name)(t->idx, &name, p_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
				return -1;
			}
			missing = (t->a == NULL);
			if (missing){
				summary_node->removed += 1;
				num_removed += 1;
				g_string_printf(string, "\t\t- %s\n", name);
				gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
									 -1, "removed-tag", NULL);
			     				 
			}
		}
		free(name);
	}
	/* Put in removed header */
	gtk_text_buffer_get_iter_at_mark(txt,txt_iter,mark);
	g_string_printf(string, "\tRemoved %s: %d\n",descrp,summary_node->removed);
	gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
						 -1, "header-removed-tag", NULL);


	/* Handle added items */
	gtk_text_buffer_get_iter_at_mark(txt,txt_iter,mark);
	/* Looking for items that are not in the old policy, hence indicating it was ADDED */
	if (iad_added != NULL) {
		/* Here we only take care of added items */
		for (t = iad_added; t != NULL; t = t->next) {
			rt = (*get_name)(t->idx, &name, p_new);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, t->idx);
				return -1;
			}
			missing = (t->a == NULL);
			/* This means that the item exists only in the new policy */
			if (missing) {
				summary_node->added++;
				num_added += 1;
				g_string_printf(string, "\t\t+ %s\n", name);
				gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
									 -1, "added-tag", NULL);
			}	
			free(name);
		}
	}
	/* Put added header on */
	gtk_text_buffer_get_iter_at_mark(txt,txt_iter,mark);
	g_string_printf(string, "\tAdded %s: %d\n",descrp,summary_node->added);
	gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
						 -1, "header-added-tag", NULL);



	/* Put the Major header on */
	gtk_text_buffer_get_iter_at_mark(txt,txt_iter,mark);
	g_string_printf(string, "%s\n",descrp);
	gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
						 -1, "header-tag", NULL);


	gtk_text_buffer_delete_mark(txt,mark);
	return 0;
}



/* returns true if policy is binary */
static bool_t fn_is_binpol(const char *fn)
{
	FILE *fp;
	bool_t rt;
	
	g_assert(fn != NULL);
	fp = fopen(fn, "r");
	if (fp == NULL)
		return FALSE;
	if (ap_is_file_binpol(fp)) 
		rt = TRUE;
	else
		rt = FALSE;
	fclose(fp);
	return rt;
}

/* returns a binary policy version */
static int fn_binpol_ver(const char *fn)
{
	FILE *fp;
	int rt;
	
	g_assert(fn != NULL);
	fp = fopen(fn, "r");
	if (fp == NULL) 
		return -1;
	
	if (!ap_is_file_binpol(fp)) 
		rt = -1;
	else 
		rt = ap_binpol_version(fp);
	fclose(fp);
	return rt;
}


static void sediff_rename_policy_tabs(const char *p1,const char *p2) 
{
	const char *fname1; 
	const char *fname2; 
	GtkNotebook *notebook;
	GtkWidget *p1_label,*p2_label;
	GString *string = g_string_new("");

	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));

	if (rindex(p1,'/')) {
		fname1 = rindex(p1,'/')+1;
		g_string_printf(string,"Policy 1: %s",fname1);
		p1_label = gtk_label_new (string->str);
		gtk_widget_show (p1_label);
		gtk_notebook_set_tab_label (notebook, gtk_notebook_get_nth_page (notebook, 1), p1_label);
	}

	if (rindex(p2,'/')) {
		fname2 = rindex(p2,'/')+1;
		g_string_printf(string,"Policy 2: %s",fname2);
		p2_label = gtk_label_new (string->str);
		gtk_widget_show (p2_label);
		gtk_notebook_set_tab_label (notebook, gtk_notebook_get_nth_page (notebook, 2), p2_label);
	}
	g_string_free(string,TRUE);
}

/* 
   returns the result of diffing p1_file and p2_file 2 policy files 
   also sets up the buffers used in gui so we can switch faster
*/
static apol_diff_result_t *sediff_diff_policies(const char *p1_file, const char *p2_file, bool_t new_files)
{
	policy_t *p1 = NULL, *p2 = NULL;
	apol_diff_result_t *diff = NULL;
	unsigned int opts = POLOPT_ALL;
	int rt;
	GdkCursor *cursor = NULL;
	GString *string = g_string_new("");
	

	/* attempt to open the policies */
	if (fn_is_binpol(p1_file) && fn_binpol_ver(p1_file) < 15) {
		g_string_printf(string,"Policy 1:  Binary policies are only supported for version 15 or higher.");
		message_display(sediff_app->window,GTK_MESSAGE_ERROR,string->str);
		goto err;
	}
	if (fn_is_binpol(p2_file) && fn_binpol_ver(p2_file) < 15 ) {
		g_string_printf(string,"Policy 2:  Binary policies are only supported for version 15 or higer.");
		message_display(sediff_app->window,GTK_MESSAGE_ERROR,string->str);
		goto err;
	}	

	rt = open_partial_policy(p1_file, opts, &p1);
	if (rt != 0) {
		g_string_printf(string,"Problem opening first policy file: %s",p1_file);
		message_display(sediff_app->window,GTK_MESSAGE_ERROR,string->str);
		goto err;
	}
	if (get_policy_version_id(p1) < POL_VER_12) {
		g_string_printf(string,"Policy 1:  Unsupport version: Supported versions are Source (12 and higher), Binary (15 and higher).");
		message_display(sediff_app->window,GTK_MESSAGE_ERROR,string->str);
		goto err;
	}

	rt = open_partial_policy(p2_file, opts, &p2);
	if (rt != 0) {
		g_string_printf(string,"Problem opening second policy file: %s",p2_file);
		message_display(sediff_app->window,GTK_MESSAGE_ERROR,string->str);
		goto err;
	}
	if (get_policy_version_id(p2) < POL_VER_12 ) {
		g_string_printf(string,"Policy 2:  Unsupport version: Supported versions are Source (12 and higher), Binary (15 and higher).");
		message_display(sediff_app->window,GTK_MESSAGE_ERROR,string->str);
		goto err;
	}
	
	/* diff and display requested info */
	diff = apol_diff_policies(opts, p1, p2);
	if (diff == NULL) {
		g_string_printf(string,"Error differentiating policies");
		message_display(sediff_app->window,GTK_MESSAGE_ERROR,string->str);
		goto err;
	}
	/* Store reference to the policy structs so we can free later. */
	sediff_app->policy1 = p1;
	sediff_app->policy2 = p2;
	
	if (new_files) {
		/* now that the diff worked lets keep these files */
		if (sediff_app->p1_filename)
			g_string_free(sediff_app->p1_filename,TRUE);
		if (sediff_app->p2_filename) 
			g_string_free(sediff_app->p2_filename,TRUE);
		
		sediff_app->p1_filename = g_string_new(p1_file);
		sediff_app->p2_filename = g_string_new(p2_file);
	}

	/* load up the buffers */
	txt_view_populate_buffers(diff->diff1,diff->diff2,diff->p1,diff->p2);

	/* rename the policy tabs */
	sediff_rename_policy_tabs(p1_file,p2_file);

	g_string_free(string,TRUE);
	
	return diff;
err:
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	if (sediff_app->window != NULL)
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();
	g_string_free(string,TRUE);
	if (p1)
		close_policy(p1);
	if (p2)
		close_policy(p2);
	p1 = p2 = NULL;
	return NULL;
}


static int get_boolean_diff(GtkTextBuffer *txt, GtkTextIter *txt_iter,
			    GString *string, bool_diff_t *bools_removed, bool_diff_t *bools_added,
			    policy_t *policy_old, policy_t *policy_new,summary_node_t *summary_node)
{
	bool_diff_t *t;
	int rt;
	char *name;
	bool_t state;
	int num_added,num_removed,num_changed;
	GtkTextTag *added_tag, *removed_tag, *changed_tag;
	GtkTextTag *header_added_tag,*header_removed_tag,*header_changed_tag,*header_tag;		
	GtkTextTagTable *table;

	
	if (policy_old == NULL || policy_new == NULL)
		return -1;
		

	/* reset the counters */
	num_added = num_removed = num_changed = 0;
	summary_node->added = 0; 
	summary_node->removed = 0;
	summary_node->changed = 0;

	/* create the tags so we can add color to our buffer */
	table = gtk_text_buffer_get_tag_table(txt);
	added_tag = gtk_text_tag_table_lookup(table, "added-tag");
	if (!added_tag) {
		added_tag = gtk_text_buffer_create_tag(txt, "added-tag",
						      "family", "monospace",
						      "foreground", "dark green", 
						      NULL);
	      
	}
	removed_tag = gtk_text_tag_table_lookup(table, "removed-tag");
	if (!removed_tag) {
		removed_tag = gtk_text_buffer_create_tag(txt, "removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 NULL);
	}
	changed_tag = gtk_text_tag_table_lookup(table, "changed-tag");
	if (!changed_tag) {
		changed_tag = gtk_text_buffer_create_tag(txt, "changed-tag",
						       "family", "monospace", 
						       "foreground", "dark blue",
						       NULL);
	}
	header_removed_tag = gtk_text_tag_table_lookup(table, "header-removed-tag");
	if(!header_removed_tag) {
		header_removed_tag = gtk_text_buffer_create_tag (txt, "header-removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_added_tag = gtk_text_tag_table_lookup(table, "header-added-tag");
	if(!header_added_tag) {
		header_added_tag = gtk_text_buffer_create_tag (txt, "header-added-tag",
							 "family", "monospace",
							 "foreground", "dark green",
							 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_changed_tag = gtk_text_tag_table_lookup(table, "header-changed-tag");
	if(!header_changed_tag) {
		header_changed_tag = gtk_text_buffer_create_tag (txt, "header-changed-tag",
							 "family", "monospace",
							 "foreground", "dark blue",
							 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
							 "weight", PANGO_WEIGHT_BOLD, 
							 "family", "monospace",
							 "underline", PANGO_UNDERLINE_SINGLE,NULL); 
	}

	/* Changed booleans */
	gtk_text_buffer_get_start_iter(txt, txt_iter);
	if (bools_removed != NULL) {
		for (t = bools_removed; t != NULL; t = t->next) {
			rt = get_cond_bool_name(t->idx, &name, policy_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
				return -1;
			}
			if (t->state_diff) {
				summary_node->changed += 1;
				num_changed += 1;
				g_string_printf(string, "\t\t* %s (changed", name);
				rt = get_cond_bool_default_val_idx(t->idx, &state, policy_old);
				if (rt < 0) {
					fprintf(stderr, "Problem getting boolean state for %s\n", name);
					free(name);
					return -1;
				}
				g_string_append_printf(string, " from %s to %s)\n", (state ? "TRUE" : "FALSE"), (state ? "FALSE" : "TRUE") );
				gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
							 -1, "changed-tag", NULL);
			}
			free(name);
		}
	}
	/* Changed Booleans header */
	gtk_text_buffer_get_end_iter(txt, txt_iter);
	g_string_printf(string, "\tChanged Booleans: %d\n",summary_node->changed);
	gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
						 -1, "header-changed-tag", NULL);



	/* removed booleans */
	gtk_text_buffer_get_start_iter(txt, txt_iter);
	if (bools_removed != NULL) {
		for (t = bools_removed; t != NULL; t = t->next) {
			rt = get_cond_bool_name(t->idx, &name, policy_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
				return -1;
			}
			if (!t->state_diff) {
				summary_node->removed += 1;
				num_removed += 1;
				g_string_printf(string, "\t\t- %s\n", name);
				gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
							 -1, "removed-tag", NULL);
			}
			free(name);
		}
	}
	/* removed booleans header */
	gtk_text_buffer_get_start_iter(txt, txt_iter);
	g_string_printf(string, "\tRemoved Booleans: %d\n",summary_node->removed);
	gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
						 -1, "header-removed-tag", NULL);


	/* added booleans */
	gtk_text_buffer_get_start_iter(txt, txt_iter);
	if (bools_added != NULL) {
		for (t = bools_added; t != NULL; t = t->next) {
			rt = get_cond_bool_name(t->idx, &name, policy_new);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", t->idx);
				return -1;
			}
			if (!t->state_diff) {
				summary_node->added += 1;
				num_added += 1;
				g_string_printf(string, "\t\t+ %s\n", name);
				gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
							 -1, "added-tag", NULL);

			}
			free(name);
		}
	}
	gtk_text_buffer_get_start_iter(txt, txt_iter);	
	g_string_printf(string, "\tAdded Booleans: %d\n",summary_node->added);
	gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
						 -1, "header-added-tag", NULL);


	gtk_text_buffer_get_start_iter(txt, txt_iter);
	g_string_printf(string,"\nBooleans\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
						 -1, "header-tag", NULL);



	return 0;
}

/* raise the correct policy tab on the gui, and go to the line clicked by the user */
static void txt_view_raise_policy_tab_goto_line(unsigned long line, int whichview)
{
	GtkNotebook *main_notebook,*tab_notebook;
	GtkTextBuffer *buffer;
	GtkTextIter iter,end_iter;
	GtkTextView *text_view = NULL;
	GtkTextTagTable *table = NULL;
	GtkLabel *lbl;
	GString *string = g_string_new("");

	main_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));
	g_assert(main_notebook);

	if (whichview == 1) {
		gtk_notebook_set_current_page(main_notebook, 1);
		text_view = (GtkTextView *)(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text"));
		tab_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook1"));
		g_assert(tab_notebook);
		gtk_notebook_set_current_page(tab_notebook, 1);
	}
	else { 
		gtk_notebook_set_current_page(main_notebook, 2);
		text_view = (GtkTextView *)(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text"));
		tab_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook2"));
		g_assert(tab_notebook);
		gtk_notebook_set_current_page(tab_notebook, 1);
	}

	buffer = gtk_text_view_get_buffer(text_view);
	g_assert(buffer);

	table = gtk_text_buffer_get_tag_table(buffer);

	gtk_text_buffer_get_start_iter(buffer, &iter);
	gtk_text_iter_set_line(&iter, line);
	gtk_text_buffer_get_start_iter(buffer, &end_iter);
	gtk_text_iter_set_line(&end_iter, line);
	while (!gtk_text_iter_ends_line(&end_iter))	
		gtk_text_iter_forward_char(&end_iter);

	gtk_text_view_scroll_to_iter(text_view, &iter, 0.0, TRUE, 0.0, 0.5);

	gtk_text_view_set_cursor_visible(text_view, TRUE);
	gtk_text_buffer_place_cursor(buffer, &iter);
	gtk_text_buffer_select_range(buffer,&iter,&end_iter);

	gtk_container_set_focus_child(GTK_CONTAINER(tab_notebook),
					 GTK_WIDGET(text_view));

	g_string_printf(string,"Line: %d",gtk_text_iter_get_line(&iter)+1);
	lbl = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
	gtk_label_set_text(lbl, string->str);
	g_string_free(string,TRUE);
	
	return;
}

/* 
   returns true when user clicks line number we are able to get it, and 
   raise the correct tab 
*/
static gboolean txt_view_on_policy1_link_event(GtkTextTag *tag, GObject *event_object, 
					      GdkEvent *event, const GtkTextIter *iter, 
					      gpointer user_data)
{
	int offset;
	unsigned long line;
	GtkTextBuffer *buffer;
	GtkTextIter *start, *end;

	if (event->type == GDK_BUTTON_PRESS) {
		buffer = gtk_text_iter_get_buffer(iter);
		start = gtk_text_iter_copy(iter);
		offset = gtk_text_iter_get_line_offset(start);

		/* testing a new way */
		while (!gtk_text_iter_starts_word(start))
			gtk_text_iter_backward_char(start);
		end = gtk_text_iter_copy(start);
		while (!gtk_text_iter_ends_word(end))
			gtk_text_iter_forward_char(end);
				
		/* the line # in policy starts with 1, in the buffer it 
		   starts at 0 */
		line = atoi(gtk_text_iter_get_slice(start, end)) - 1;

		txt_view_raise_policy_tab_goto_line(line,1);
		return TRUE;
	}

	return FALSE;
}

/* 
   returns true when user clicks line number we are able to get it, and 
   raise the correct tab 
*/
static gboolean txt_view_on_policy2_link_event(GtkTextTag *tag, GObject *event_object, 
					      GdkEvent *event, const GtkTextIter *iter, 
					      gpointer user_data)
{
	int offset;
	unsigned long line;
	GtkTextBuffer *buffer;
	GtkTextIter *start, *end;

	if (event->type == GDK_BUTTON_PRESS) {
		buffer = gtk_text_iter_get_buffer(iter);
		start = gtk_text_iter_copy(iter);
		offset = gtk_text_iter_get_line_offset(start);

		/* testing a new way */
		while (!gtk_text_iter_starts_word(start))
			gtk_text_iter_backward_char(start);
		end = gtk_text_iter_copy(start);
		while (!gtk_text_iter_ends_word(end))
			gtk_text_iter_forward_char(end);
				
		/* the line # in policy starts with 1, in the buffer it 
		   starts at 0 */
		line = atoi(gtk_text_iter_get_slice(start, end)) - 1;

		txt_view_raise_policy_tab_goto_line(line,2);
		return TRUE;
	}

	return FALSE;
}

/* set the cursor to a hand when user scrolls over a line number in when displaying te diff */
gboolean txt_view_on_text_view_motion(GtkWidget *widget, GdkEventMotion *event, gpointer user_data)
{
	GtkTextBuffer *buffer;
 	GtkTextView *tree_view;
	GdkCursor *cursor;
	GtkTextIter iter;
	GSList *tags,*tagp;
	gint x, ex, ey, y;
	bool_t hovering = FALSE;
	
	tree_view = GTK_TEXT_VIEW(widget);

	if (event->is_hint) {	
		gdk_window_get_pointer(event->window, &ex, &ey, NULL);
	} else {
		ex = event->x;
		ey = event->y;
	}

	gtk_text_view_window_to_buffer_coords(tree_view, GTK_TEXT_WINDOW_WIDGET,
					       ex, ey, &x, &y);

	buffer = gtk_text_view_get_buffer(tree_view);
	gtk_text_view_get_iter_at_location(tree_view, &iter, x, y);
	tags = gtk_text_iter_get_tags(&iter);
	for (tagp = tags;  tagp != NULL;  tagp = tagp->next)
	{
		GtkTextTag *tag = tagp->data;
		gint page = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (tag), "page"));

		if (page != 0) 
		{
			hovering = TRUE;
			break;
		}
	}	

	if (hovering) {
		cursor = gdk_cursor_new(GDK_HAND2);
		gdk_window_set_cursor(event->window, cursor);
		gdk_cursor_unref(cursor);
		gdk_flush();
	} else {
		gdk_window_set_cursor(event->window, NULL);	
	}
	g_slist_free(tags);
	return FALSE;
}

static int sediff_add_hdr(GtkTextBuffer *txt,GString *string)
{
	GtkTextTag *header_tag;
	GtkTextTagTable *table;
	GtkTextIter iter;

	table = gtk_text_buffer_get_tag_table(txt);
	header_tag = gtk_text_tag_table_lookup(table, "main-header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "main-header-tag",
							 "family", "monospace",
							 "style", PANGO_STYLE_ITALIC,
							 "weight", PANGO_WEIGHT_BOLD, 
							 NULL); 
	}
	gtk_text_buffer_get_start_iter(txt, &iter);
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "main-header-tag", NULL);

	return 0;
}


static void sediff_populate_key_buffer()
{
	GtkTextView *txt_view;
	GtkTextBuffer *txt;
	GString *string = g_string_new("");
	GtkTextTag *added_tag,*removed_tag,*changed_tag,*mono_tag,*header_tag;
	GtkTextTagTable *table;
	GtkTextIter iter;

	txt_view = GTK_TEXT_VIEW((glade_xml_get_widget(sediff_app->window_xml, "sediff_key_txt_view")));
	txt = gtk_text_view_get_buffer(txt_view);
	sediff_clear_text_buffer(txt);
	gtk_text_buffer_get_iter_at_offset (txt, &iter, 0);
	

	table = gtk_text_buffer_get_tag_table(txt);
	added_tag = gtk_text_tag_table_lookup(table, "added-tag");
	if (!added_tag) {
		added_tag = gtk_text_buffer_create_tag(txt, "added-tag",
						       "family", "monospace",
						       "foreground", "dark green", 
						       NULL);
	      
	}
	removed_tag = gtk_text_tag_table_lookup(table, "removed-tag");
	if (!removed_tag) {
		removed_tag = gtk_text_buffer_create_tag(txt, "removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 NULL);
	}
	changed_tag = gtk_text_tag_table_lookup(table, "changed-tag");
	if (!changed_tag) {
		changed_tag = gtk_text_buffer_create_tag(txt, "changed-tag",
							 "family", "monospace", 
							 "foreground", "dark blue",
							 NULL);
	}
	mono_tag = gtk_text_tag_table_lookup(table, "mono-tag");
	if (!mono_tag) {
		mono_tag = gtk_text_buffer_create_tag(txt, "mono-tag",
						      "family", "monospace", 
						      NULL);
	}
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
							 "family", "monospace",
							 "weight", PANGO_WEIGHT_BOLD, 
							 "underline", PANGO_UNDERLINE_SINGLE,NULL); 
	}


	gtk_text_buffer_get_start_iter(txt,&iter);
	g_string_printf(string," Added(+):\n  Items added\n  in policy 2.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "added-tag", NULL);

	g_string_printf(string," Removed(-):\n  Items removed\n  in policy 2.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "removed-tag", NULL);
	g_string_printf(string," Changed(*):\n  Items changed\n  in policy 2.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "changed-tag", NULL);
	g_string_printf(string," T:\n  A TRUE\n  conditional \n  TE rule.\n\n F:\n  A FALSE\n  conditional\n  TE rule.\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "mono-tag", NULL);


	g_string_free(string, TRUE);
}

/* populate the status bar with summary info of our diff */
static void sediff_update_status_bar()
{
	GtkLabel *statusbar;
	GString *string = g_string_new("");

	statusbar = (GtkLabel *)(glade_xml_get_widget(sediff_app->window_xml, "label_stats"));
	g_assert(statusbar);
	g_string_printf(string,"Classes & Perms: %d "
			"Types: %d Attributes: %d Roles: %d Users: %d Booleans: %d "
			"TE Rules: %d Rbac: %d",
			(sediff_app->summary.classes.added + sediff_app->summary.classes.removed + sediff_app->summary.classes.changed +
			sediff_app->summary.permissions.added + sediff_app->summary.permissions.removed + sediff_app->summary.permissions.changed +
			 sediff_app->summary.commons.added + sediff_app->summary.commons.removed + sediff_app->summary.commons.changed),
			(sediff_app->summary.types.added + sediff_app->summary.types.removed + sediff_app->summary.types.changed),
			(sediff_app->summary.attributes.added + sediff_app->summary.attributes.removed + sediff_app->summary.attributes.changed),
			(sediff_app->summary.roles.added + sediff_app->summary.roles.removed + sediff_app->summary.roles.changed),
			(sediff_app->summary.users.added + sediff_app->summary.users.removed + sediff_app->summary.users.changed),
			(sediff_app->summary.booleans.added + sediff_app->summary.booleans.removed + sediff_app->summary.booleans.changed),	       
			(sediff_app->summary.te_rules.added + sediff_app->summary.te_rules.removed + sediff_app->summary.te_rules.changed),	       
			(sediff_app->summary.rbac.added + sediff_app->summary.rbac.removed + sediff_app->summary.rbac.changed));
	gtk_label_set_text(statusbar, string->str);
	g_string_free(string, TRUE);
}

static void sediff_populate_buffer_hdrs()
{
	GString *string = g_string_new("");
	
	/* permissions */
	g_string_printf(string, "Permissions (%d Added, %d Removed)\n\n",sediff_app->summary.permissions.added,
			sediff_app->summary.permissions.removed);
	sediff_add_hdr(sediff_app->classes_buffer,string);
	/* commons */
	g_string_printf(string, "Commons (%d Added, %d Removed, %d Changed)\n",sediff_app->summary.commons.added,
			sediff_app->summary.commons.removed, sediff_app->summary.commons.changed);
	sediff_add_hdr(sediff_app->classes_buffer,string);
	/* classes */
	g_string_printf(string, "Classes (%d Added, %d Removed, %d Changed)\n",sediff_app->summary.classes.added,
			sediff_app->summary.classes.removed, sediff_app->summary.classes.changed);
	sediff_add_hdr(sediff_app->classes_buffer,string);
	/* types */
	g_string_printf(string, "Types (%d Added, %d Removed, %d Changed)\n\n",sediff_app->summary.types.added,
			sediff_app->summary.types.removed, sediff_app->summary.types.changed);
	sediff_add_hdr(sediff_app->types_buffer,string);
	/* attributes */
	g_string_printf(string, "Attributes (%d Added, %d Removed, %d Changed)\n\n",sediff_app->summary.attributes.added,
			sediff_app->summary.attributes.removed, sediff_app->summary.attributes.changed);
	sediff_add_hdr(sediff_app->attribs_buffer,string);
	/* users */
	g_string_printf(string, "Users (%d Added, %d Removed, %d Changed)\n\n",sediff_app->summary.users.added,
			sediff_app->summary.users.removed, sediff_app->summary.users.changed);
	sediff_add_hdr(sediff_app->users_buffer,string);
	/* roles */
	g_string_printf(string, "Roles (%d Added, %d Removed, %d Changed)\n\n",sediff_app->summary.roles.added,
			sediff_app->summary.roles.removed, sediff_app->summary.roles.changed);
	sediff_add_hdr(sediff_app->roles_buffer,string);
	/* booleans */
	g_string_printf(string, "Booleans (%d Added, %d Removed, %d Changed)\n",sediff_app->summary.booleans.added,
			sediff_app->summary.booleans.removed, sediff_app->summary.booleans.changed);
	sediff_add_hdr(sediff_app->booleans_buffer,string);
	/* rbac */
	g_string_printf(string, "Role Allows (%d Added, %d Removed, %d Changed)\n\n",sediff_app->summary.rbac.added,
			sediff_app->summary.rbac.removed, sediff_app->summary.rbac.changed);
	sediff_add_hdr(sediff_app->rbac_buffer,string);
	/* te rules */
	g_string_printf(string, "TE Rules (%d Added, %d Removed, %d Changed)\n",sediff_app->summary.te_rules.added,
			sediff_app->summary.te_rules.removed, sediff_app->summary.te_rules.changed);
	sediff_add_hdr(sediff_app->te_buffer,string);

}


static int txt_buffer_insert_type_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					  GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	gtk_text_buffer_get_end_iter(txt, txt_iter);
	rt = get_iad_buffer(txt,txt_iter,string, IDX_TYPE, stuff_removed->types, 
			    stuff_added->types, policy_old, policy_new,&sediff_app->summary.types);
	if (rt < 0) {
		fprintf(stderr, "Problem printing types for policy.\n");
		return -1;
	}
	return 0;
}

static int txt_buffer_insert_attrib_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					    GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	    policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	gtk_text_buffer_get_end_iter(txt, txt_iter);

	rt = get_iad_buffer(txt,txt_iter,string, IDX_ATTRIB, stuff_removed->attribs, 
			    stuff_added->attribs, policy_old, policy_new,&sediff_app->summary.attributes);
	if (rt < 0) {
		fprintf(stderr, "Problem printing attributes.\n");
		return -1;
	}
	return 0;
}

static int txt_buffer_insert_role_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					  GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	gtk_text_buffer_get_end_iter(txt, txt_iter);
	rt = get_iad_buffer(txt,txt_iter,string, IDX_ROLE, stuff_removed->roles, 
			    stuff_added->roles, policy_old, policy_new,&sediff_app->summary.roles);
	if (rt < 0) {
		fprintf(stderr, "Problem printing roles.\n");
		return -1;
	}
	
	return 0;
}

static int txt_buffer_insert_user_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					  GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	gtk_text_buffer_get_end_iter(txt, txt_iter);
	rt = get_iad_buffer(txt,txt_iter,string, IDX_USER, stuff_removed->users, stuff_added->users, 
			    policy_old, policy_new,&sediff_app->summary.users);
	if (rt < 0) {
		fprintf(stderr, "Problem printing users.\n");
		return -1;
	}

	return 0;
}

static int txt_buffer_insert_boolean_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					     GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	     policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	gtk_text_buffer_get_end_iter(txt, txt_iter);
	rt = get_boolean_diff(txt,txt_iter,string,stuff_removed->booleans,stuff_added->booleans, policy_old, 
			      policy_new,&sediff_app->summary.booleans);
	if(rt < 0){
		fprintf(stderr, "Problem printing booleans.\n");
		return -1;
	}
	
	return 0;
}

static int txt_buffer_insert_classes_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					     GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	     policy_t *policy_old, policy_t *policy_new)
{
	int rt;
	
	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	rt = get_iad_buffer(txt,txt_iter,string, IDX_OBJ_CLASS, stuff_removed->classes, 
			    stuff_added->classes, policy_old, policy_new,&sediff_app->summary.classes);
	if (rt < 0){
		fprintf(stderr, "Problem printing classes.\n");
		return -1;
	}
	return 0;	
}

static int txt_buffer_insert_common_perms_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
						  GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	     	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;

	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	gtk_text_buffer_get_end_iter(txt, txt_iter);
	rt = get_iad_buffer(txt,txt_iter,string, IDX_COMMON_PERM, stuff_removed->common_perms, stuff_added->common_perms, 
		policy_old, policy_new,&sediff_app->summary.commons);
	if (rt < 0) {
		fprintf(stderr, "Problem printing common permissions.\n");
		return -1;
	}
	return 0;	
}

static int txt_buffer_insert_perms_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					   GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	   policy_t *policy_old, policy_t *policy_new)
{
	int rt, i;
	char *name;
	GtkTextTag *added_tag, *removed_tag, *header_added_tag, *header_removed_tag,*header_tag;		
	GtkTextTagTable *table;

       	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);


	
	sediff_app->summary.permissions.added = stuff_added->num_perms;
	sediff_app->summary.permissions.removed = stuff_removed->num_perms;
	
	/* create the tags so we can add color to our buffer */
	table = gtk_text_buffer_get_tag_table(txt);
	added_tag = gtk_text_tag_table_lookup(table, "added-tag");
	if (!added_tag) {
		added_tag = gtk_text_buffer_create_tag(txt, "added-tag",
						      "family", "monospace",
						      "foreground", "dark green", 
						      NULL);
	      
	}
	removed_tag = gtk_text_tag_table_lookup(table, "removed-tag");
	if (!removed_tag) {
		removed_tag = gtk_text_buffer_create_tag(txt, "removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 NULL);
	}
	header_removed_tag = gtk_text_tag_table_lookup(table, "header-removed-tag");
	if(!header_removed_tag) {
		header_removed_tag = gtk_text_buffer_create_tag (txt, "header-removed-tag",
								 "family", "monospace",
								 "foreground", "red",
								 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_added_tag = gtk_text_tag_table_lookup(table, "header-added-tag");
	if(!header_added_tag) {
		header_added_tag = gtk_text_buffer_create_tag (txt, "header-added-tag",
							       "family", "monospace",
							       "foreground", "dark green",
							       "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
							 "family", "monospace",
							 "weight", PANGO_WEIGHT_BOLD, 
							 "underline", PANGO_UNDERLINE_SINGLE,NULL); 
	}

	g_string_printf(string,"Permissions\n");
	gtk_text_buffer_insert_with_tags_by_name(txt,txt_iter,string->str,-1,"header-tag",NULL);


	g_string_printf(string,"\tAdded Permissions: %d\n",stuff_added->num_perms);
	gtk_text_buffer_insert_with_tags_by_name(txt,txt_iter,string->str,-1,"header-added-tag",NULL);
	for (i = 0; i < stuff_added->num_perms; i++) {
		rt = get_perm_name(stuff_added->perms[i], &name, policy_new);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d\n", stuff_added->perms[i]);
			return -1;
		}
		g_string_printf(string, "\t\t+ %s\n", name);
		gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
							 -1, "added-tag", NULL);
		gtk_text_buffer_get_end_iter(txt, txt_iter);
		free(name);
	}

	g_string_printf(string,"\tRemoved Permissions: %d\n",stuff_removed->num_perms);
	gtk_text_buffer_insert_with_tags_by_name(txt,txt_iter,string->str,-1,"header-removed-tag",NULL);
	for (i = 0; i < stuff_removed->num_perms; i++) {
		rt = get_perm_name(stuff_removed->perms[i], &name, policy_old);
		if(rt < 0) {
			fprintf(stderr, "Problem getting name for Permission %d\n", stuff_removed->perms[i]);
			return -1;
		}
		g_string_printf(string, "\t\t- %s\n", name);
		gtk_text_buffer_insert_with_tags_by_name(txt, txt_iter, string->str, 
							 -1, "removed-tag", NULL);

		gtk_text_buffer_get_end_iter(txt, txt_iter);
		free(name);
	}

	return 0;	
}

/* insert a full te rule line, with colors, and spacing */
static int txt_buffer_insert_te_line(GtkTextBuffer *txt, GtkTextIter *iter, 
				     GString *string,avh_node_t *cur,policy_t *policy,
				     GtkTextTag *colortag,GtkTextTag *linktag,
				     GtkTextTag *pangotag, const char *str)
{
	char *fulltab = sediff_get_tab_spaces(TABSIZE);
	char *condtab = sediff_get_tab_spaces(TABSIZE-2);
	char *rule = NULL;
	gchar **split_line_array = NULL;
	int j;

	/* are there conditionals */
	if (cur->flags & AVH_FLAG_COND) {
		rule = re_render_avh_rule_cond_state(cur,policy);
		g_string_printf(string,"%s%s",rule,condtab);
		free(rule);
	}
	else
		g_string_printf(string,"%s",fulltab);
	gtk_text_buffer_insert_with_tags(txt, iter, string->str, -1, pangotag, NULL);  

	
	/* print the rule */
	rule = re_render_avh_rule(cur, policy); 
	if (rule == NULL) { 
		g_return_val_if_reached(-1); 
	} 
	g_string_printf(string, "%s%s", str,rule); 
	gtk_text_buffer_insert_with_tags(txt, iter, string->str, -1, colortag, NULL);  
	
	free(rule); 
	
	
	/* get the line # */
	rule = re_render_avh_rule_linenos(cur, policy); 
	if (rule != NULL) { 
		j = 0; 
		split_line_array = g_strsplit((const gchar*)rule, " ", 0);   
		while (split_line_array[j] != NULL) {   
			gtk_text_buffer_insert_with_tags(txt, iter, "(", -1, pangotag, NULL); 
			g_string_printf(string, "%s", split_line_array[j]); 
			if (!is_binary_policy(policy)) { 
				gtk_text_buffer_insert_with_tags(txt, iter, string->str, -1, linktag, NULL); 
			} 
			gtk_text_buffer_insert_with_tags(txt, iter, ")", -1, pangotag, NULL); 
			j++; 
		} 
		free(rule); 
		g_strfreev(split_line_array); 
	} 		
	/* get the conditional expression */
	if (cur->flags & AVH_FLAG_COND) {
		rule = re_render_avh_rule_cond_expr(cur,policy);
		gtk_text_buffer_insert_with_tags(txt, iter, rule, -1, colortag, NULL); 		
		free(rule);
	}
       	gtk_text_buffer_insert(txt, iter, "\n", -1); 

	return 0;
	
}


static int txt_buffer_insert_te_results(GtkTextBuffer *txt, GtkTextIter *txt_iter, 
				    	 GString *string, apol_diff_t *diff1, apol_diff_t *diff2,
					 policy_t *policy1,policy_t *policy2)
{
	int i, j;
	avh_node_t *cur;
	avh_node_t *cur2;
	avh_node_t *diffcur1;
	avh_node_t *diffcur2;
	avh_key_t p2key,p1key;
	char cond_on[TABSIZE+1];
	char cond_off[TABSIZE+1];
	char cond_none[TABSIZE+1];
	char *fulltab = sediff_get_tab_spaces(TABSIZE);
	char *condtab = sediff_get_tab_spaces(TABSIZE-2);

	GtkTextMark *added_mark = NULL, *changed_mark = NULL, *holder_mark = NULL;
	GtkTextIter added_iter,changed_iter, holder_iter;
	GtkTextTag *link1_tag,*link2_tag, *rules_tag,*added_tag,*changed_tag,*removed_tag,*header_tag;
	GtkTextTagTable *table;
	char *name = NULL;
	bool_t inverse,matched,polmatched;

	snprintf(cond_on,TABSIZE,"D:\t");
	snprintf(cond_off,TABSIZE,"E:\t");
	snprintf(cond_none,TABSIZE,"\t");
	cond_on[TABSIZE] = '\0';
	cond_off[TABSIZE] = '\0';
	cond_none[TABSIZE] = '\0';

	/* reset the te summary counters */
	sediff_app->summary.te_rules.added = 0;
	sediff_app->summary.te_rules.removed = 0;
	sediff_app->summary.te_rules.changed = 0;

	g_return_val_if_fail(diff1 != NULL,-11);
	table = gtk_text_buffer_get_tag_table(txt);
	link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
	link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");

	if (!is_binary_policy(policy1)) {
		if (!link1_tag) {
			link1_tag = gtk_text_buffer_create_tag(txt, "policy1-link-tag",
							      "family", "monospace",
							      "foreground", "blue", 
							      "underline", PANGO_UNDERLINE_SINGLE, NULL);
		}
	}
	if (!is_binary_policy(policy2)) {
		if (!link2_tag) {
			link2_tag = gtk_text_buffer_create_tag(txt, "policy2-link-tag",
							      "family", "monospace",
							      "foreground", "blue", 
							      "underline", PANGO_UNDERLINE_SINGLE, NULL);
		}
 	}
	added_tag = gtk_text_tag_table_lookup(table, "added-tag");	
	if (!added_tag) {
		added_tag = gtk_text_buffer_create_tag(txt, "added-tag",
						      "family", "monospace",
						      "foreground", "dark green", 
						      NULL);
	      
	}
	changed_tag = gtk_text_tag_table_lookup(table, "changed-tag");
	if (!changed_tag) {
		changed_tag = gtk_text_buffer_create_tag(txt, "changed-tag",
							 "family", "monospace",
							 "foreground", "dark blue",
							 NULL);
	}
	removed_tag = gtk_text_tag_table_lookup(table, "removed-tag");
	if (!removed_tag) {
		removed_tag = gtk_text_buffer_create_tag(txt, "removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 NULL);
	}
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
							 "weight", PANGO_WEIGHT_BOLD,
							 "underline", PANGO_UNDERLINE_SINGLE,
							 NULL); 
	}
	rules_tag = gtk_text_tag_table_lookup(table, "rules-tag");
	if (!rules_tag) {
		rules_tag = gtk_text_buffer_create_tag(txt, "rules-tag",
						       "family", "monospace", NULL);
	}
	


	/* 
	   In order to place the results in the appropriate place in the buffer, and
	   to cut down on code runtime we print out the te diff like this:
	   --We want our buffer to go added->removed->changes
	   1.  Create 2 marks, one that goes left as you insert(added_mark), and one
	   that goes right as you insert(changed_mark)
	   2.  Insert the missing te rules first.  This will cause both marks to go
	   in opposite directions for our later use.
	   3. Go through the added te rules and check to see if this is a changed rule
	   if it is than just append it to the end, if its not that use our added_mark
	   to insert this rule above the missing and changed rules already inserted.
	*/


	/* keep 2 iterators one that goes left as you add, one that goes right, 
	   first loop through diff1.  If you find an item in diff1 that is only
	   in policy1 and not in policy 2, get the left moving iterator, and add
	   the rule to where that location is.  If you find a rule that is in policy2,
	   but not diff2, then get the right iterator, and add it there.  This will 
	   allow changes to stay on the bottom 
	*/

	gtk_text_buffer_get_end_iter(txt, txt_iter);
	changed_mark = gtk_text_buffer_get_mark(txt,"changed-mark");
	if (changed_mark == NULL)
		changed_mark = gtk_text_buffer_create_mark (txt,"changed-mark",txt_iter,FALSE);
	added_mark = gtk_text_buffer_get_mark(txt,"added-mark");
	if (added_mark == NULL)
		added_mark = gtk_text_buffer_create_mark (txt,"added-mark",txt_iter,TRUE);
	gtk_text_buffer_get_iter_at_mark(txt,&added_iter,added_mark);
	gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);

	polmatched = FALSE;


 	/* find removed */
 	for (i = 0; i < AVH_SIZE; i++) { 
 		for (diffcur1 = diff1->te.tab[i];diffcur1 != NULL; diffcur1 = diffcur1->next) { 
			gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);
 
 			/* make the p1 key */
 			make_p2_key(&diffcur1->key,&p2key,policy1,policy2); 

			/* search for the key/cond in p2, */			
			matched = FALSE;
			cur2 = avh_find_first_node(&policy2->avh, &p2key);
			while (cur2 != NULL && does_cond_match(diffcur1,policy1,cur2,policy2,&inverse) == FALSE)
				cur2 = avh_find_next_node(cur2);
			/* the rule is in policy 2 */
			if (cur2 != NULL) {
				/* is the rule in diff2, if so then it will be handled in the adds,
				   if not that we need to treat this as a change now */
				diffcur2 = avh_find_first_node(&diff2->te, &p2key);
				while (diffcur2 != NULL && does_cond_match(diffcur1,policy1,diffcur2,policy2,&inverse) == FALSE)
					diffcur2 = avh_find_next_node(diffcur2);
				if (diffcur2 == NULL) {
					/* update counter */
					sediff_app->summary.te_rules.changed += 1;

					/* find the complete rule in p1 */
					cur = avh_find_first_node(&policy1->avh, &diffcur1->key);
					while (cur != NULL && does_cond_match(diffcur1,policy1,cur,policy1,&inverse) == FALSE)
						cur = avh_find_next_node(cur);
					if (cur == NULL)
						g_return_val_if_reached(-1);
					/* print the p1 rule */
					gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);
					txt_buffer_insert_te_line(txt, &changed_iter, string, cur, 
								  policy1, changed_tag,link1_tag,
								  rules_tag,"* Policy 1: ");
					/* print the p2 rule */
					txt_buffer_insert_te_line(txt, &changed_iter, string, cur2, 
								  policy2, changed_tag,link2_tag,
								  rules_tag,"* Policy 2: ");	
					/* now print the diffs */
					if (diffcur1->key.rule_type <= RULE_MAX_AV) {
						for (j = 0 ; j < diffcur1->num_data; j++) {
							if (get_perm_name(diffcur1->data[j],&name,policy1) == 0) {
								g_string_printf(string,"%s%s- %s\n",fulltab,fulltab,name);
								gtk_text_buffer_insert_with_tags_by_name(txt, &changed_iter, string->str, -1, "removed-tag", NULL);
								free(name);
							}
						}
					}
					else {
						if (diffcur1->num_data == 1) {
							if (get_type_name(diffcur1->data[0],&name,policy1) == 0) {
								g_string_printf(string,"%s%s- %s\n",fulltab,fulltab,name);
								gtk_text_buffer_insert_with_tags_by_name(txt, &changed_iter, string->str, -1, "removed-tag", NULL);
								free(name);
							}
						}
					}

					if (polmatched == FALSE) {

						gtk_text_buffer_get_iter_at_mark(txt,&holder_iter,added_mark);
						holder_mark = gtk_text_buffer_create_mark(txt,"holder-mark",&holder_iter,FALSE);
						polmatched = TRUE;
					}					
				}

			}
			/* if the rule is not in policy 2 at all */
			if (cur2 == NULL) {
				/* update the number removed */
				sediff_app->summary.te_rules.removed += 1;
				gtk_text_buffer_get_iter_at_mark(txt,&added_iter,added_mark);
				txt_buffer_insert_te_line(txt, &added_iter, string, 
							  diffcur1, policy1, removed_tag,link1_tag,
							  rules_tag,"- ");
				if (polmatched == FALSE) {
					gtk_text_buffer_get_iter_at_mark(txt,&holder_iter,changed_mark);
					holder_mark = gtk_text_buffer_create_mark (txt,"holder-mark",&holder_iter,TRUE);
					polmatched = TRUE;
				}

			}

 		} 
 	} 

	gtk_text_buffer_get_iter_at_mark(txt,&added_iter,added_mark);
	g_string_printf(string, "\nTE RULES REMOVED: %d\n",sediff_app->summary.te_rules.removed);
	gtk_text_buffer_insert_with_tags_by_name(txt, &added_iter, string->str,-1, "header-tag", NULL); 

	/* create a mark that goes after removed, but before changed */
	if (polmatched == FALSE) {
		gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);		
		holder_mark = gtk_text_buffer_create_mark (txt,"holder-mark",&changed_iter,TRUE);
	}
	/* find added and changed rules*/
	for (i = 0; i < AVH_SIZE; i++) {
		for (diffcur2 = diff2->te.tab[i];diffcur2 != NULL; diffcur2 = diffcur2->next) {
			gtk_text_buffer_get_iter_at_mark(txt,&added_iter,added_mark);

			/* make the p1 key */
			make_p2_key(&diffcur2->key,&p1key,policy2,policy1);
			/* now loop through list and find not only matching key but also matching 
			   conditional */
			matched = FALSE;
			cur = avh_find_first_node(&policy1->avh, &p1key);
			while (cur != NULL && does_cond_match(cur,policy1,diffcur2,policy2,&inverse) == FALSE)
				cur = avh_find_next_node(cur);

			/* if the rule is in policy 1 this is a changed rule*/
			if (cur != NULL) {
				sediff_app->summary.te_rules.changed += 1;
				/* get the entire rule from policy 2 */
				cur2 = avh_find_first_node(&policy2->avh, &diffcur2->key);
				while (cur2 != NULL && does_cond_match(cur2,policy2,diffcur2,policy2,&inverse) == FALSE)
					cur2 = avh_find_next_node(cur2);
				if (cur2 == NULL)
					return -1;

				/* try to find the key in diff1 */
				diffcur1 = avh_find_first_node(&diff1->te, &p1key);
				while (diffcur1 != NULL && does_cond_match(diffcur1,policy1,diffcur2,policy2,&inverse) == FALSE)
					diffcur1 = avh_find_next_node(diffcur1);

				gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);
				txt_buffer_insert_te_line(txt, &changed_iter, string, 
							  cur, policy1, changed_tag,link1_tag,
							  rules_tag,"* Policy 1: ");
				txt_buffer_insert_te_line(txt, &changed_iter, string, 
							  cur2, policy2, changed_tag,link2_tag,
							  rules_tag,"* Policy 2: ");


				/* now print the diffs */
				/* at this point we know that both diffcur1 and diffcur2 have the same key so we don't need
				   to check if diffcur1 is a type transition rule, we can just go with what diffcur2 is 
				*/
				if (diffcur2->key.rule_type <= RULE_MAX_AV) {
					for (j = 0 ; j < diffcur2->num_data; j++) {
						if (get_perm_name(diffcur2->data[j],&name,policy2) == 0) {
							g_string_printf(string,"%s%s+ %s\n",fulltab,fulltab,name);
							gtk_text_buffer_insert_with_tags_by_name(txt, &changed_iter, string->str, -1, "added-tag", NULL);
							gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);
							free(name);
						}
					}
					if (diffcur1) {
						for (j = 0 ; j < diffcur1->num_data; j++) {
							if (get_perm_name(diffcur1->data[j],&name,policy1) == 0) {
								g_string_printf(string,"%s%s- %s\n",fulltab,fulltab,name);
								gtk_text_buffer_insert_with_tags_by_name(txt, &changed_iter, string->str, -1, "removed-tag", NULL);
							gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);
							free(name);
							}
						}
					}
				}
				else {
					if (diffcur2->num_data == 1) {
						if (get_type_name(diffcur2->data[0],&name,policy2) == 0) {
							g_string_printf(string,"%s%s+ %s\n",fulltab,fulltab,name);
							gtk_text_buffer_insert_with_tags_by_name(txt, &changed_iter, string->str, -1, "added-tag", NULL);
							gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);
							free(name);
						}
					}
					if(diffcur1) {
						if (get_type_name(diffcur1->data[0],&name,policy1) == 0) {
							g_string_printf(string,"%s%s- %s\n",fulltab,fulltab,name);
							gtk_text_buffer_insert_with_tags_by_name(txt, &changed_iter, string->str, -1, "removed-tag", NULL);
							gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);
							free(name);
						}
					}
				}
				
				gtk_text_buffer_get_iter_at_mark(txt,&changed_iter,changed_mark);
		       
			}
			/* if the rule is not in policy 1 */
			else if (cur == NULL ) {
				sediff_app->summary.te_rules.added += 1;
				gtk_text_buffer_get_iter_at_mark(txt,&added_iter,added_mark);
				txt_buffer_insert_te_line(txt, &added_iter, string, 
							  diffcur2, policy2, added_tag,link2_tag,
							  rules_tag,"+ ");
			}

		}

	}

	gtk_text_buffer_get_start_iter(txt,&added_iter);
	g_string_printf(string, "\nTE RULES ADDED: %d\n",sediff_app->summary.te_rules.added);
	gtk_text_buffer_insert_with_tags_by_name(txt, &added_iter, string->str,-1, "header-tag", NULL); 

	gtk_text_buffer_get_iter_at_mark(txt,&added_iter,holder_mark);
	g_string_printf(string, "\nTE RULES CHANGED: %d \n",sediff_app->summary.te_rules.changed);
	gtk_text_buffer_insert_with_tags_by_name(txt, &added_iter, string->str,-1, "header-tag", NULL); 

	if (fulltab)
		free(fulltab);
	if (condtab)		
		free(condtab);
	return 0;


}

static int txt_buffer_insert_rbac_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					  GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{
	int rt;

	g_return_val_if_fail(stuff_removed != NULL, -1);
	g_return_val_if_fail(stuff_added != NULL, -1);
	gtk_text_buffer_get_end_iter(txt, txt_iter);
	rt = get_iad_buffer(txt,txt_iter,string, IDX_ROLE|IDX_PERM, stuff_removed->role_allow, 
			    stuff_added->role_allow, policy_old, policy_new,&sediff_app->summary.rbac);
	if (rt < 0) {
		fprintf(stderr, "Problem printing rbac for policy.\n");
		return -1;
	}

	return 0;
}

static int txt_buffer_insert_cond_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					  GString *string, apol_diff_t *stuff_removed, apol_diff_t *stuff_added,
				    	  policy_t *policy_old, policy_t *policy_new)
{

	g_string_printf(string,"This feature will be available in the upcoming releases\n");
	gtk_text_buffer_insert(txt,txt_iter,string->str,-1);

	
	return 0;
}

/*
static int txt_buffer_insert_sid_results(GtkTextBuffer *txt, GtkTextIter *txt_iter,
					 GString *string, apol_diff_t *diff, policy_t *policy)
{
	g_return_val_if_fail(diff != NULL, -1);
	
	return 0;
}
*/
/*
  clear the text buffers 
*/
static void sediff_free_stored_buffers()
{
	if (sediff_app->summary_buffer) {
		g_object_unref (G_OBJECT(sediff_app->summary_buffer)); 

	}
	if (sediff_app->classes_buffer) {
		g_object_unref (G_OBJECT(sediff_app->classes_buffer)); 

	}
	if (sediff_app->types_buffer) {
		g_object_unref (G_OBJECT(sediff_app->types_buffer)); 
	}
	if (sediff_app->roles_buffer) {
		g_object_unref (G_OBJECT(sediff_app->roles_buffer)); 
	}
	if (sediff_app->users_buffer) {
		g_object_unref (G_OBJECT(sediff_app->users_buffer)); 
	}
	if (sediff_app->booleans_buffer) {
		g_object_unref (G_OBJECT(sediff_app->booleans_buffer)); 
	}
	if (sediff_app->attribs_buffer) {
		g_object_unref (G_OBJECT(sediff_app->attribs_buffer)); 
	}
	if (sediff_app->te_buffer) {
		g_object_unref (G_OBJECT(sediff_app->te_buffer)); 
	}
	if (sediff_app->rbac_buffer) {
		g_object_unref (G_OBJECT(sediff_app->rbac_buffer)); 
	}
	if (sediff_app->conditionals_buffer) {
		g_object_unref (G_OBJECT(sediff_app->conditionals_buffer)); 
	}
	

	sediff_app->summary_buffer = NULL;
	sediff_app->classes_buffer = NULL;
	sediff_app->types_buffer = NULL;	
	sediff_app->roles_buffer = NULL;
	sediff_app->users_buffer = NULL;
	sediff_app->booleans_buffer = NULL;
	sediff_app->attribs_buffer = NULL;
	sediff_app->te_buffer = NULL;
	sediff_app->rbac_buffer = NULL;
	sediff_app->conditionals_buffer = NULL;

}


/*
  create the text buffers we use to display diff results 
*/
static void sediff_create_buffers()
{
	sediff_app->summary_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->summary_buffer)); 

	sediff_app->classes_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->classes_buffer)); 

	sediff_app->types_buffer = gtk_text_buffer_new(NULL);	
	g_object_ref (G_OBJECT(sediff_app->types_buffer)); 

	sediff_app->roles_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->roles_buffer)); 

	sediff_app->users_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->users_buffer)); 

	sediff_app->booleans_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->booleans_buffer)); 

	sediff_app->attribs_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->attribs_buffer)); 

	sediff_app->te_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->te_buffer)); 

	sediff_app->rbac_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->rbac_buffer)); 

	sediff_app->conditionals_buffer = gtk_text_buffer_new(NULL);
	g_object_ref (G_OBJECT(sediff_app->conditionals_buffer)); 
}

/* Insert the diff stats into the summary buffer */
static void txt_buffer_insert_summary_results()
{
	GtkTextBuffer *txt;
	GtkTextIter iter;
	GtkTextTagTable *table;
	GString *string = g_string_new("");
	GtkTextTag *header_tag, *header_removed_tag = NULL, *header_changed_tag = NULL;
	GtkTextTag *header_added_tag = NULL, *main_header_tag;

	
	txt = sediff_app->summary_buffer;

	/* Clear the buffer */
	sediff_clear_text_buffer(txt);

	table = gtk_text_buffer_get_tag_table(txt);
	header_tag = gtk_text_tag_table_lookup(table, "header-tag");	
	if(!header_tag) {
		header_tag = gtk_text_buffer_create_tag (txt, "header-tag",
						      "family", "monospace",
							 "weight", PANGO_WEIGHT_BOLD,
							 "underline", PANGO_UNDERLINE_SINGLE,
							 NULL); 
	}
	main_header_tag = gtk_text_tag_table_lookup(table, "main-header-tag");	
	if (!main_header_tag) {
	        main_header_tag = gtk_text_buffer_create_tag(txt, "main-header-tag",
							 "style", PANGO_STYLE_ITALIC,
							 "weight", PANGO_WEIGHT_BOLD, 
							NULL); 	      
	}
	header_removed_tag = gtk_text_tag_table_lookup(table, "header-removed-tag");
	if(!header_removed_tag) {
		header_removed_tag = gtk_text_buffer_create_tag (txt, "header-removed-tag",
							 "family", "monospace",
							 "foreground", "red",
							 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_added_tag = gtk_text_tag_table_lookup(table, "header-added-tag");
	if(!header_added_tag) {
		header_added_tag = gtk_text_buffer_create_tag (txt, "header-added-tag",
							 "family", "monospace",
							 "foreground", "dark green",
							 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	header_changed_tag = gtk_text_tag_table_lookup(table, "header-changed-tag");
	if(!header_changed_tag) {
		header_changed_tag = gtk_text_buffer_create_tag (txt, "header-changed-tag",
							 "family", "monospace",
							 "foreground", "dark blue",
							 "weight", PANGO_WEIGHT_BOLD, NULL); 
	}

	gtk_text_buffer_get_start_iter(txt,&iter);
	g_string_printf(string,"Policy Difference Statistics\n\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,main_header_tag,NULL);
	
	g_string_printf(string,"Policy Filenames:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tPolicy 1: %s\n",sediff_app->p1_filename->str);
	gtk_text_buffer_insert(txt,&iter,string->str,-1);
	g_string_printf(string,"\tPolicy 2: %s\n\n",sediff_app->p2_filename->str);
	gtk_text_buffer_insert(txt,&iter,string->str,-1);


	

	g_string_printf(string,"Classes:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.classes.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.classes.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.classes.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_printf(string,"Commons:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.commons.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.commons.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.commons.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_printf(string,"Permissions:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.permissions.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.permissions.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.permissions.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_printf(string,"Types:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.types.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.types.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.types.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_printf(string,"Attributes:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.attributes.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.attributes.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.attributes.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_printf(string,"Roles:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.roles.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.roles.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.roles.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_printf(string,"Users:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.users.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.users.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.users.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);


	g_string_printf(string,"Booleans:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.booleans.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.booleans.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.booleans.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_printf(string,"TE Rules:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.te_rules.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.te_rules.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.te_rules.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_printf(string,"RBAC:\n");
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_tag,NULL);
	g_string_printf(string,"\tAdded: %d\n",sediff_app->summary.rbac.added);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_added_tag,NULL);
	g_string_printf(string,"\tRemoved: %d\n",sediff_app->summary.rbac.removed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_removed_tag,NULL);
	g_string_printf(string,"\tChanged: %d\n",sediff_app->summary.rbac.changed);
	gtk_text_buffer_insert_with_tags(txt,&iter,string->str,-1,header_changed_tag,NULL);

	g_string_free(string,TRUE);
}


/*
  puts the diff results into the precreated text buffers
*/
static void txt_view_populate_buffers(apol_diff_t *stuff_removed,
				     apol_diff_t *stuff_added,
				     policy_t *policy_old,
				     policy_t *policy_new)
{
	gint rt;
	GString *string = g_string_new("");
	GtkTextIter end;

	sediff_free_stored_buffers();
	sediff_create_buffers();

  
	/* case OPT_CLASSES: */
	gtk_text_buffer_get_start_iter(sediff_app->classes_buffer, &end);
	rt = txt_buffer_insert_classes_results(sediff_app->classes_buffer, &end,
					       string, stuff_removed, 
					       stuff_added, policy_old, policy_new);

	rt = txt_buffer_insert_common_perms_results(sediff_app->classes_buffer, &end,
						    string, stuff_removed, stuff_added, 
						    policy_old, policy_new);

	gtk_text_buffer_get_end_iter(sediff_app->classes_buffer, &end);
	rt = txt_buffer_insert_perms_results(sediff_app->classes_buffer, &end,
					     string, stuff_removed, stuff_added, 
					     policy_old, policy_new);
	/* case OPT_TYPES: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->types_buffer, &end);
	rt = txt_buffer_insert_type_results(sediff_app->types_buffer, &end,
					    string, stuff_removed, stuff_added, 
					    policy_old, policy_new);


	/* case OPT_ROLES: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->roles_buffer, &end);
	rt = txt_buffer_insert_role_results(sediff_app->roles_buffer, &end,
					    string, stuff_removed, stuff_added, 
					    policy_old, policy_new);

	/* case OPT_USERS: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->users_buffer, &end);
	rt = txt_buffer_insert_user_results(sediff_app->users_buffer, &end,
					    string, stuff_removed, stuff_added, 
					    policy_old, policy_new);

	/* case OPT_BOOLEANS: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->booleans_buffer, &end);
	rt = txt_buffer_insert_boolean_results(sediff_app->booleans_buffer, &end,
					       string, stuff_removed, stuff_added, 
					       policy_old, policy_new);


	/* case OPT_TE_RULES: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->te_buffer, &end);
	txt_buffer_insert_te_results(sediff_app->te_buffer, &end, 
				     string, stuff_removed,stuff_added, policy_old,policy_new);

	/* case OPT_RBAC_RULES: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->rbac_buffer, &end);
	rt = txt_buffer_insert_rbac_results(sediff_app->rbac_buffer, &end,
					    string, stuff_removed, stuff_added, 
					    policy_old, policy_new);

	/* case OPT_ATTRIBS: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->attribs_buffer, &end);
	rt = txt_buffer_insert_attrib_results(sediff_app->attribs_buffer,&end,
					      string, stuff_removed, stuff_added, 
					      policy_old, policy_new);

	/* case CONDITIONALS: */
	g_string_truncate(string,0);
	gtk_text_buffer_get_end_iter(sediff_app->conditionals_buffer, &end);
	rt = txt_buffer_insert_cond_results(sediff_app->conditionals_buffer,&end,
					      string, stuff_removed, stuff_added, 
					      policy_old, policy_new);



	/* insert the diff summary */
	txt_buffer_insert_summary_results();

	/* load up the headers */
	sediff_populate_buffer_hdrs();	

	/* load up the status bar */
	sediff_update_status_bar();

	/* populate the key */
	sediff_populate_key_buffer();

	g_string_free(string, TRUE);
}

/*
  switches the currently displayed text buffer
*/
static void txt_view_switch_buffer(GtkTextView *textview,gint option,gint policy_option)
{
	GtkTextTag *link1_tag;
	GtkTextTag *link2_tag;
	GtkTextTagTable *table;
	GtkTextAttributes *attr;
	gint page = 1;
	gint size;
	PangoTabArray *tabs;

	attr = gtk_text_view_get_default_attributes(textview);
	if (attr->font != NULL) {
		size = pango_font_description_get_size(attr->font);
		tabs = pango_tab_array_new_with_positions (4,
					    FALSE,
					    PANGO_TAB_LEFT, 3*size,
					    PANGO_TAB_LEFT, 6*size,
					    PANGO_TAB_LEFT, 9*size,
					    PANGO_TAB_LEFT, 12*size);
		
		if (gtk_text_view_get_tabs(textview) == NULL)
			gtk_text_view_set_tabs(textview,tabs);


	}

	if (policy_option == 1) {
		switch (option) {
		case OPT_SUMMARY:
			gtk_text_view_set_buffer(textview,sediff_app->summary_buffer);
			break;
		case OPT_CLASSES:
			gtk_text_view_set_buffer(textview,sediff_app->classes_buffer);
			break;
		case OPT_TYPES:
			gtk_text_view_set_buffer(textview,sediff_app->types_buffer);
			break;
		case OPT_ROLES:
			gtk_text_view_set_buffer(textview,sediff_app->roles_buffer);
			break;
		case OPT_USERS:
			gtk_text_view_set_buffer(textview,sediff_app->users_buffer);
			break;
		case OPT_BOOLEANS:
			gtk_text_view_set_buffer(textview,sediff_app->booleans_buffer);
			break;
		case OPT_ATTRIBUTES:
			gtk_text_view_set_buffer(textview,sediff_app->attribs_buffer);
			break;
		case OPT_TE_RULES:
			table = gtk_text_buffer_get_tag_table(sediff_app->te_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy1_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (page));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy2_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (page));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_buffer);
			break;
		case OPT_RBAC_RULES:
			gtk_text_view_set_buffer(textview,sediff_app->rbac_buffer);
			break;
		case OPT_CONDITIONALS:
			gtk_text_view_set_buffer(textview,sediff_app->conditionals_buffer);
			break;
		default:
			fprintf(stderr, "Invalid list item %d!", option);
			break;
		};

	}

}

/* 
   callback used to switch our text buffer based on
   user input from the treeview
*/
static gboolean txt_buffer_insert_results(gpointer data)
{
	GValue gval = {0};
	GtkTreeIter iter;
	GtkTextView *textview1;
	gint option;
	apol_diff_result_t *diff_results = NULL;
	GtkTreeModel *tree_model;
	GtkTreeSelection *sel;
	GList *glist = NULL, *item = NULL;
	GtkTreePath *path = NULL;

	tree_model = gtk_tree_view_get_model((GtkTreeView*)sediff_app->tree_view);
	sel = gtk_tree_view_get_selection((GtkTreeView*)sediff_app->tree_view);
	glist = gtk_tree_selection_get_selected_rows(sel, &tree_model);
	if (glist == NULL) {
		return FALSE;
	}
	/* Only grab the top-most selected item */
	item = glist;
	path = item->data;
	
	/* if we can't get the iterator, then we need to just exit */
	if (!gtk_tree_model_get_iter(tree_model, &iter, path)) {
		if (glist) {	
			g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
			g_list_free(glist);			
		}	
		return FALSE;
	}
	if (glist) {	
		g_list_foreach(glist, (GFunc) gtk_tree_path_free, NULL);
		g_list_free(glist);			
	}
	
	option = GPOINTER_TO_INT(iter.user_data);
	gtk_tree_model_get_value(tree_model, &iter, SEDIFF_HIDDEN_COLUMN, &gval);	
	
	/* grab the text buffers for our text views */
	textview1 = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_p1_results_txt_view");
	g_assert(textview1);

	diff_results = (apol_diff_result_t *)g_value_get_pointer(&gval);
	g_return_val_if_fail(diff_results != NULL, FALSE);
	
	/* Configure text_view */
	gtk_text_view_set_editable(GTK_TEXT_VIEW (textview1), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview1), FALSE);

			
	txt_view_switch_buffer(textview1,option,1);

	g_value_unset(&gval);	
	
	return FALSE;
}


static void sediff_treeview_on_row_double_clicked(GtkTreeView *tree_view, 
						  GtkTreePath *path, 
						  GtkTreeViewColumn *col, 
						  gpointer user_data)
{
	/* Finish later */

	g_idle_add_full(G_PRIORITY_HIGH_IDLE, &txt_buffer_insert_results, NULL, NULL);	
	row_selected_signal_emit();

}


static gboolean sediff_treeview_on_row_selected(GtkTreeSelection *selection,
					    	GtkTreeModel     *model,
					    	GtkTreePath      *path,
					    	gboolean          path_currently_selected,
					    	gpointer          userdata)
{	

	/* if the row is not selected, then its about to be selected ! */
	/* we put in this toggle because for some reason if we have a previously selected path
	   then this callback is called like this
	   1  new_path is not selected
	   2  old_path is selected
	   3  new_path is not selected
	   This messes up our te rules stuff so I just put in a check to make sure we're not called
	   2 times when we are really only selected once 
	*/
	if (toggle && gtk_tree_selection_path_is_selected(selection,path) == FALSE) {
		g_idle_add_full(G_PRIORITY_HIGH_IDLE, &txt_buffer_insert_results, NULL, NULL);
		row_selected_signal_emit();
  
	}
	else
		toggle = !toggle;
	return TRUE; /* allow selection state to change */
}

static void sediff_callbacks_free_elem_data(gpointer data, gpointer user_data)
{
	registered_callback_t *callback = (registered_callback_t*)data;
	if (callback)
		free(callback);
	return;
}

static void sediff_destroy(sediff_app_t *sediff_app)
{
	g_assert(sediff_app != NULL);
	if (sediff_app->dummy_view) 
		gtk_widget_unref(sediff_app->dummy_view);
	if (sediff_app->tree_view != NULL) 
		gtk_widget_destroy(GTK_WIDGET(sediff_app->tree_view));
	if (sediff_app->window != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->window));
	if (sediff_app->open_dlg != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->open_dlg));
	if (sediff_app->loading_dlg != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->loading_dlg));
	if (sediff_app->window_xml != NULL)
		g_object_unref(G_OBJECT(sediff_app->window_xml));
	if (sediff_app->open_dlg_xml != NULL)
		g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	if (sediff_app->p1_filename) 
		g_string_free(sediff_app->p1_filename,TRUE);
	if (sediff_app->p2_filename) 
		g_string_free(sediff_app->p2_filename,TRUE);
	if (sediff_app->policy1) 
		close_policy(sediff_app->policy1);
	if (sediff_app->policy1) 
		close_policy(sediff_app->policy2);
	
	g_list_foreach(sediff_app->callbacks, &sediff_callbacks_free_elem_data, NULL);
	g_list_free(sediff_app->callbacks);

	free(sediff_app);
	sediff_app = NULL;
}

static void sediff_exit_app(sediff_app_t *sediff_app)
{
	sediff_destroy(sediff_app);
	gtk_main_quit();
}

static void on_sediff_main_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data) 
{
	sediff_exit_app(sediff_app);	
}

static GtkWidget *sediff_tree_view_create_from_store(SEDiffTreeViewStore *tree_store)
{
	GtkTreeViewColumn   *col;
	GtkCellRenderer     *renderer;
	GtkWidget           *tree_view = NULL;
	GtkTreeSelection    *selection;

	sediff_tree_store_populate(tree_store);	
	tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(tree_store));

	g_object_unref(tree_store); /* destroy store automatically with tree_view */
	
	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start (col, renderer, TRUE);
	gtk_tree_view_column_add_attribute (col, renderer, "text", SEDIFF_LABEL_COLUMN);

	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view),col);
	
	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();
	gtk_tree_view_column_pack_start (col, renderer, TRUE);
	gtk_tree_view_column_add_attribute (col, renderer, "text", SEDIFF_HIDDEN_COLUMN);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view),col);
	gtk_tree_view_column_set_visible(col, FALSE);
	gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(tree_view), FALSE);
	g_signal_connect(G_OBJECT(tree_view), "row-activated", 
			 G_CALLBACK(sediff_treeview_on_row_double_clicked), NULL);
	
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
        gtk_tree_selection_set_mode(selection,GTK_SELECTION_BROWSE);
	gtk_tree_selection_set_select_function(selection, sediff_treeview_on_row_selected, tree_view, NULL);


	return tree_view;
}

static void sediff_policy_stats_textview_populate(policy_t *p1, GtkTextView *textview,const char *filename)
{
	GtkTextBuffer *txt;
	GtkTextIter iter;
	gchar *contents = NULL;

	/* grab the text buffer for our tree_view */
	txt = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview));

	sediff_clear_text_buffer(txt);

	/* set some variables up */
	gtk_text_view_set_editable (GTK_TEXT_VIEW (textview), FALSE);
	gtk_text_view_set_cursor_visible (GTK_TEXT_VIEW (textview), FALSE);


	contents = g_strdup_printf("Filename: %s\n"
				   "Version: %s\n"
				   "Policy Type: %s\n\n"

				   "Number of Classes and Permissions:\n"
				   "\tObject Classes: %d\n"
				   "\tCommon Permissions: %d\n"
				   "\tPermissions: %d\n\n"

				   "Number of Types and Attributes:\n"
				   "\tTypes: %d\n"
				   "\tAttributes: %d\n\n"

				   "Number of Type Enforcement Rules:\n"
				   "\tallow: %d\n"
				   "\tneverallow: %d\n"
				   "\ttype_transition: %d\n"
				   "\ttype_change: %d\n"
				   "\tauditallow: %d\n"
				   "\tdontaudit %d\n\n"

				   "Number of Roles: %d\n\n"

				   
				   "Number of RBAC Rules:\n"
				   "\tallow: %d\n"
				   "\trole_transition %d\n\n"

				   "Number of Users: %d\n\n"

				   "Number of Booleans: %d\n\n",

				   filename,
				   get_policy_version_name(p1->version),
                                   is_binary_policy(p1) == 0 ? "source" : "binary", 
				   p1->num_obj_classes,
				   p1->num_common_perms,
				   p1->num_perms,
				   p1->num_types,
				   p1->num_attribs,
				   p1->rule_cnt[RULE_TE_ALLOW],
				   p1->rule_cnt[RULE_NEVERALLOW],
				   p1->rule_cnt[RULE_TE_TRANS],
				   p1->rule_cnt[RULE_TE_CHANGE],
				   p1->rule_cnt[RULE_AUDITALLOW],
				   p1->rule_cnt[RULE_DONTAUDIT],
				   p1->num_roles,
				   p1->rule_cnt[RULE_ROLE_ALLOW],
				   p1->rule_cnt[RULE_ROLE_TRANS],
				   p1->rule_cnt[RULE_USER],
				   p1->num_cond_bools
				   );
	gtk_text_buffer_get_iter_at_offset(txt, &iter, 0);
	gtk_text_buffer_insert(txt, &iter, contents,-1);
	g_free(contents);
}

static int sediff_policy_file_textview_populate(const char *filename,GtkTextView *textview)
{
        GtkTextBuffer *txt;
	GtkTextIter iter;
	gchar *contents = NULL;
	gsize length;
	GError *error;
	GString *string;
	GtkTextTag *mono_tag = NULL;
	GtkTextTagTable *table = NULL;

	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview));

	table = gtk_text_buffer_get_tag_table(txt);
	mono_tag = gtk_text_tag_table_lookup(table, "mono-tag");
	if (!mono_tag) {
		mono_tag = gtk_text_buffer_create_tag(txt, "mono-tag",
						      "style", PANGO_STYLE_NORMAL,
						      "weight", PANGO_WEIGHT_NORMAL, 
						      "family", "monospace", 
						      NULL);
	}
	sediff_clear_text_buffer(txt);
	gtk_text_buffer_get_iter_at_offset (txt, &iter, 0);

	/* set some variables up */
	gtk_text_view_set_editable (GTK_TEXT_VIEW (textview), FALSE);
	gtk_text_view_set_cursor_visible (GTK_TEXT_VIEW (textview), TRUE);

	/* if this is not a binary policy */
	if (!fn_is_binpol(filename)) {
		if (!g_file_get_contents(filename, &contents, &length, &error)){
			g_warning("Unable to read file %s\n",filename);
			return -1;
		}
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, contents, length,"mono-tag",NULL);
		gtk_text_buffer_set_modified(txt, TRUE);
	} else {
		string = g_string_new("");
		g_string_printf(string,"Policy File %s is a binary policy",filename);
		gtk_text_buffer_insert_with_tags_by_name(txt,&iter,string->str,-1,"mono-tag",NULL);
		g_string_free(string,TRUE);

	}
	
	return 0;
}

void sediff_menu_on_reload_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GString *p1 = NULL;
	GString *p2 = NULL;
	if (sediff_app->p1_filename && sediff_app->p2_filename) {
		p1 = g_string_new(sediff_app->p1_filename->str);
		p2 = g_string_new(sediff_app->p2_filename->str);		
		/* diff and load into GUI */ 
		sediff_diff_and_load_policies(p1->str, p2->str, FALSE);
		g_string_free(p1,TRUE);
		g_string_free(p2,TRUE);
	} else {
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, "A policy filename is empty! Could not reload.");	
	}
}

void sediff_open_dialog_on_p1browse_button_clicked(GtkButton *button, gpointer user_data)
{
	GtkEntry *entry = NULL;
	GString *filename= NULL;
	GtkEntry *entry2 = NULL;
	
	entry = (GtkEntry *)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry");
	entry2 = (GtkEntry *)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry");

	g_assert(entry);

	if ((g_ascii_strcasecmp(gtk_entry_get_text(entry),"") == 0) && (g_ascii_strcasecmp(gtk_entry_get_text(entry2),"") != 0))
		filename = get_filename_from_user("Open Policy", gtk_entry_get_text(entry2));
	else
		filename = get_filename_from_user("Open Policy", gtk_entry_get_text(entry));
	if (filename){
		gtk_entry_set_text(entry,filename->str);
	}
}

void sediff_open_dialog_on_p2browse_button_clicked(GtkButton *button, gpointer user_data)
{
	GtkEntry *entry = NULL;
	GString *filename = NULL;
	GtkEntry *entry1 = NULL;

	entry = (GtkEntry*)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry");
	entry1 = (GtkEntry*)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry");

	g_assert(entry);
	if ((g_ascii_strcasecmp(gtk_entry_get_text(entry),"") == 0) && (g_ascii_strcasecmp(gtk_entry_get_text(entry1),"") != 0))
		filename = get_filename_from_user("Open Policy", gtk_entry_get_text(entry1));
	else
		filename = get_filename_from_user("Open Policy", gtk_entry_get_text(entry));
	if (filename){
		gtk_entry_set_text(entry, filename->str);
	}
}

static void sediff_loading_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
  	gtk_widget_destroy(widget);
	sediff_app->loading_dlg = NULL;
}


void sediff_open_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy(widget);
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;	
}

void sediff_open_dialog_on_cancel_button_clicked(GtkButton *button, gpointer user_data)
{
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;
}

void sediff_menu_on_open_clicked(GtkMenuItem *menuitem, gpointer user_data)
{	
	GtkEntry *entry = NULL;
	char *dir;
	GString *path; 

	if (sediff_app->open_dlg) {
		gtk_window_present(sediff_app->open_dlg);
	} else {
		
		dir = find_file(GLADEFILE);
		if (!dir){
			fprintf(stderr, "Could not find sediff.glade!");
			return -1;
		}

		path = g_string_new(dir);
		free(dir);
		g_string_append_printf(path, "/%s", GLADEFILE);
		
		sediff_app->open_dlg_xml = glade_xml_new(path->str, OPEN_DIALOG_ID, NULL);
		g_assert(sediff_app->open_dlg_xml != NULL);
		sediff_app->open_dlg = GTK_WINDOW(glade_xml_get_widget(sediff_app->open_dlg_xml, OPEN_DIALOG_ID));
		g_assert(sediff_app->open_dlg);
		if (sediff_app->p1_filename) {
			entry = GTK_ENTRY(glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry"));
			gtk_entry_set_text(entry,sediff_app->p1_filename->str);
		}
		if (sediff_app->p2_filename) {
			entry = GTK_ENTRY(glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry"));
			gtk_entry_set_text(entry,sediff_app->p2_filename->str);
		}
		g_signal_connect(G_OBJECT(sediff_app->open_dlg), "delete_event", 
			G_CALLBACK(sediff_open_dialog_on_window_destroy), sediff_app);
		glade_xml_signal_autoconnect(sediff_app->open_dlg_xml);
	}
}

void sediff_menu_on_quit_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_exit_app(sediff_app);
}

void sediff_menu_on_help_clicked(GtkMenuItem *menuitem, gpointer user_data)
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
	gtk_window_set_title(GTK_WINDOW(window), "SeDiff Help");
	gtk_window_set_default_size(GTK_WINDOW(window), 480, 300);
	gtk_container_add(GTK_CONTAINER(window), scroll);
	gtk_container_add(GTK_CONTAINER(scroll), text_view);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view),GTK_WRAP_WORD);
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));	
	dir = find_file("sediff_help.txt");
	if (!dir) {
		string = g_string_new("");
		g_string_append(string, "Cannot find help file");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return;
	}
	string = g_string_new(dir);
	free(dir);
	g_string_append(string, "/sediff_help.txt");
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

void sediff_menu_on_about_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget *dialog;
	GString *str;
	
	str = g_string_new("");
	g_string_assign(str, "Policy Semantic Diff Tool for Security \nEnhanced Linux");
        g_string_append(str, "\n\nCopyright (c) 2005\nTresys Technology, LLC\nwww.tresys.com/selinux");
	g_string_append(str, "\n\nGUI version ");
	g_string_append(str, SEDIFF_GUI_VERSION_NUM);
	g_string_append(str, "\nlibapol version ");
	g_string_append(str, libapol_get_version()); /* the libapol version */
	
	dialog = gtk_message_dialog_new(sediff_app->window,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_INFO,
					GTK_BUTTONS_CLOSE,
					str->str);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_string_free(str, TRUE);
}

gboolean sediff_load_dlg_destroy()
{
	GtkWidget *widget = NULL;
	if (sediff_app->loading_dlg != NULL) {
		widget = GTK_WIDGET(sediff_app->loading_dlg);
		gtk_widget_destroy(GTK_WIDGET(sediff_app->loading_dlg));
		sediff_app->loading_dlg = NULL;
	}
	return FALSE;
}

gboolean sediff_load_dlg_show()
{
	GtkWidget *label;
	/* if the dialog is not already up */
	if (sediff_app->loading_dlg == NULL) {
		sediff_app->loading_dlg = gtk_dialog_new_with_buttons ("Loading",
						      sediff_app->window,
						      GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_NO_SEPARATOR,
				     NULL);
		gtk_widget_set_usize(sediff_app->loading_dlg,300,100);
		label = gtk_label_new ("Calculating difference - this may take a while");
		gtk_container_add (GTK_CONTAINER (GTK_DIALOG(sediff_app->loading_dlg)->vbox),
				   label);

		gtk_widget_show_all (sediff_app->loading_dlg);
	}
		g_signal_connect(G_OBJECT(sediff_app->loading_dlg), "delete_event", 
			G_CALLBACK(sediff_loading_dialog_on_window_destroy), sediff_app);

	return FALSE;
}

void sediff_on_policy1_notebook_event_after(GtkWidget *widget, GdkEvent *event, gpointer user_data) 
{
	GtkNotebook *notebook = (GtkNotebook*)user_data;
	GtkLabel *label = NULL;
	guint pagenum;
	GtkTextMark *mark = NULL;
	GtkTextBuffer *txt = NULL;
	GtkTextIter iter;
	GtkTextView *p1_textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");
				
	pagenum = gtk_notebook_get_current_page(notebook);
	txt = gtk_text_view_get_buffer(p1_textview);
	assert(txt);
	if (pagenum == 0) {
		label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
		gtk_label_set_text(label, "");
	} else if (gtk_text_buffer_get_modified(txt)) {
		g_assert(p1_textview);
		GString *string = g_string_new("");
		mark = gtk_text_buffer_get_insert(txt);
		if (mark != NULL) {
			gtk_text_buffer_get_iter_at_mark(txt, &iter, mark);
			g_string_printf(string, "Line: %d", gtk_text_iter_get_line(&iter)+1);
			label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
			gtk_label_set_text(label, string->str);
		}
		g_string_free(string,TRUE);
	}
}

void sediff_on_policy2_notebook_event_after(GtkWidget *widget, GdkEvent *event, gpointer user_data) 
{
	GtkNotebook *notebook = (GtkNotebook*)user_data;
	GtkLabel *label = NULL;
	guint pagenum;
	GtkTextMark *mark = NULL;
	GtkTextBuffer *txt = NULL;
	GtkTextIter iter;
	GtkTextView *p2_textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text");
				
	pagenum = gtk_notebook_get_current_page(notebook);
	txt = gtk_text_view_get_buffer(p2_textview);
	assert(txt);
	if (pagenum == 0) {
		label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
		gtk_label_set_text(label, "");
	} else if (gtk_text_buffer_get_modified(txt)) {
		g_assert(p2_textview);
		GString *string = g_string_new("");
		mark = gtk_text_buffer_get_insert(txt);
		if (mark != NULL) {
			gtk_text_buffer_get_iter_at_mark(txt, &iter, mark);
			g_string_printf(string, "Line: %d", gtk_text_iter_get_line(&iter)+1);
			label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
			gtk_label_set_text(label, string->str);
		}
		g_string_free(string,TRUE);
	}
}

static void sediff_initialize()
{
	GtkTextView *textview;
	GtkTextBuffer *txt;
	GtkWidget *container = NULL;
	GtkLabel *label = NULL;
	
	/* Close previously opened policies */ 
	if (sediff_app->policy1) 
		close_policy(sediff_app->policy1);
	if (sediff_app->policy2)
		close_policy(sediff_app->policy2);
	sediff_app->policy1 = sediff_app->policy2 = NULL;
	
	/* delete tree_view if it existed before */
	if (sediff_app->tree_view) {
		gtk_widget_destroy(GTK_WIDGET(sediff_app->tree_view));
		sediff_app->tree_view = NULL;
	}
	/* get the scrolled window and replace the tree_view with a blank dummy view */
	container = glade_xml_get_widget(sediff_app->window_xml, "scrolledwindow_list");
	g_assert(container);
	if (sediff_app->dummy_view == NULL) {
		sediff_app->dummy_view = gtk_text_view_new();
		g_assert(sediff_app->dummy_view);
		gtk_container_add(GTK_CONTAINER(container), sediff_app->dummy_view);
		gtk_widget_show_all(container);				
	} else if (!GTK_WIDGET_MAPPED(sediff_app->dummy_view)) { 
		/* If the dummy view has been removed, then re-add it to the container */
		gtk_container_add(GTK_CONTAINER(container), sediff_app->dummy_view);
		gtk_widget_show_all(container);					
	}
	
	/* Grab the 2 policy textviews */
	textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	/* Set modified bit to zero, so line numbers won't show while in initialized mode. */
	gtk_text_buffer_set_modified(txt, FALSE);
	
	textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	/* Set modified bit to zero, so line numbers won't show while in initialized mode. */
	gtk_text_buffer_set_modified(txt, FALSE);
	
	textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_stats_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
		
	textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_stats_text");
	g_assert(textview);
	/* grab the text buffer for our text view */
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	
	textview = GTK_TEXT_VIEW((glade_xml_get_widget(sediff_app->window_xml, "sediff_key_txt_view")));
	g_assert(textview);
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	
	textview = GTK_TEXT_VIEW((glade_xml_get_widget(sediff_app->window_xml, "sediff_p1_results_txt_view")));
	g_assert(textview);
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	
	label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
	gtk_label_set_text(label, "");
}

/* diff p1_file and p2_file and load gui with the resulting data, return -1 if
   fail on any dependencies */
static int sediff_diff_and_load_policies(const char *p1_file, const char *p2_file, bool_t new_files)
{
	GtkTextView *p1_textview, *p2_textview;
	GtkTextView *stats1, *stats2;
	GtkWidget *container = NULL;
	SEDiffTreeViewStore *tree_store = NULL;
	apol_diff_result_t *diff_results = NULL;
	GtkTreeModel *tree_model;
	GtkTreeSelection *sel;
	GtkTreeIter iter;
	gchar **labels = NULL;
	GString *string = g_string_new("");
	GdkCursor *cursor = NULL;
	GtkNotebook *notebook1, *notebook2;
	
	sediff_initialize();
	/* show our loading dialog while we load */
	sediff_load_dlg_show();
	
	/* set the cursor to a hand */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->loading_dlg)->window, cursor);	
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();

	while (gtk_events_pending ())
		gtk_main_iteration ();

	/* diff the two policies */
	diff_results = sediff_diff_policies(p1_file, p2_file, new_files);
	if (!diff_results) {
		/* get rid of the loading dialog on error */
		sediff_load_dlg_destroy();
		/* diff is done set cursor back to a ptr */
		gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, NULL);	
		return -1;
	}
	
	/* get the scrolled window we are going to put the tree_store in */
	container = glade_xml_get_widget(sediff_app->window_xml, "scrolledwindow_list");
	g_assert(container);
	if (sediff_app->dummy_view != NULL) {
		/* Add a reference to the dummy view widget before removing it from the container so we can add it later */
		sediff_app->dummy_view = gtk_widget_ref(sediff_app->dummy_view);
		gtk_container_remove(GTK_CONTAINER(container), sediff_app->dummy_view);
	}
	
	/* Grab the 2 policy textviews */
	p1_textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");
	g_assert(p1_textview);
	p2_textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text");
	g_assert(p2_textview);
	
	stats1 = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_stats_text");
	g_assert(stats1);
	stats2 = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_stats_text");
	g_assert(stats2);
	
	/* create the string to store in treeview */
	g_string_printf(string,"Difference Summary|Classes & Perms %d|Types %d|Attributes %d|"
			"Roles %d|Users %d|Booleans %d|TE Rules %d|RBAC Rules %d|Conditionals 0",
			(sediff_app->summary.classes.added + sediff_app->summary.classes.removed + sediff_app->summary.classes.changed +
			sediff_app->summary.permissions.added + sediff_app->summary.permissions.removed + sediff_app->summary.permissions.changed +
			 sediff_app->summary.commons.added + sediff_app->summary.commons.removed + sediff_app->summary.commons.changed),
			(sediff_app->summary.types.added + sediff_app->summary.types.removed + sediff_app->summary.types.changed),
			(sediff_app->summary.attributes.added + sediff_app->summary.attributes.removed + sediff_app->summary.attributes.changed),
			(sediff_app->summary.roles.added + sediff_app->summary.roles.removed + sediff_app->summary.roles.changed),
			(sediff_app->summary.users.added + sediff_app->summary.users.removed + sediff_app->summary.users.changed),
			(sediff_app->summary.booleans.added + sediff_app->summary.booleans.removed + sediff_app->summary.booleans.changed),	       
			(sediff_app->summary.te_rules.added + sediff_app->summary.te_rules.removed + sediff_app->summary.te_rules.changed),	       
			(sediff_app->summary.rbac.added + sediff_app->summary.rbac.removed + sediff_app->summary.rbac.changed));
			
  
	labels = g_strsplit(string->str,"|",-1);
	sediff_tree_store_set_labels(labels);

	g_strfreev(labels);
	g_string_free(string,TRUE);

	/* create a new tree_store */
	tree_store = sediff_tree_store_new();
	tree_store->diff_results = diff_results;
		
	notebook1 = (GtkNotebook *)glade_xml_get_widget(sediff_app->window_xml, "notebook1");
	g_assert(notebook1);
	notebook2 = (GtkNotebook *)glade_xml_get_widget(sediff_app->window_xml, "notebook2");
	g_assert(notebook2);
	g_signal_connect_after(G_OBJECT(notebook1), "event-after", 
			 G_CALLBACK(sediff_on_policy1_notebook_event_after), notebook1);
	g_signal_connect_after(G_OBJECT(notebook2), "event-after", 
			 G_CALLBACK(sediff_on_policy2_notebook_event_after), notebook2);
				 
	/* now lets populate the textviews with our new policies */
	sediff_policy_file_textview_populate(p1_file, p1_textview);
	sediff_policy_file_textview_populate(p2_file, p2_textview);

	/* populate the 2 stat buffers */
	sediff_policy_stats_textview_populate(tree_store->diff_results->p1, stats1,sediff_app->p1_filename->str);
	sediff_policy_stats_textview_populate(tree_store->diff_results->p2, stats2,sediff_app->p2_filename->str);

	/* create the tree_view */
	sediff_app->tree_view = sediff_tree_view_create_from_store(tree_store);
	
	/* make it viewable */
	gtk_container_add(GTK_CONTAINER(container), sediff_app->tree_view);
	gtk_widget_show_all(container);
	
	/* select the first element in the tree */
	tree_model = gtk_tree_view_get_model((GtkTreeView*)sediff_app->tree_view);
	sel = gtk_tree_view_get_selection((GtkTreeView*)sediff_app->tree_view);
	if (gtk_tree_model_get_iter_first(tree_model,&iter)) {
		gtk_tree_selection_select_iter(sel,&iter);
	}

	/* get rid of the loading when done */
	sediff_load_dlg_destroy();

	/* diff is done set cursor back to a ptr */
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, NULL);	

	return 0;
}


void sediff_open_dialog_on_diff_button_clicked(GtkButton *button, gpointer user_data)
{
	const gchar *p1_file = NULL;
	const gchar *p2_file = NULL;
	GtkEntry *p1_entry;
	GtkEntry *p2_entry;
	GdkCursor *cursor = NULL;
	int rt;
	GString *string = NULL;

	
	/* grab the GtkEntry widgets so we can get their data*/
	p1_entry = (GtkEntry *)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p1_entry");
	p2_entry = (GtkEntry *)glade_xml_get_widget(sediff_app->open_dlg_xml, "sediff_dialog_p2_entry");

	/* get the data */
	p1_file = gtk_entry_get_text(p1_entry);
	p2_file = gtk_entry_get_text(p2_entry);
	
	if (!g_file_test(p1_file, G_FILE_TEST_EXISTS) || g_file_test(p1_file, G_FILE_TEST_IS_DIR)) {
		string = g_string_new("Invalid file specified for policy 1!");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return;
	}
	if (!g_file_test(p2_file, G_FILE_TEST_EXISTS) || g_file_test(p2_file, G_FILE_TEST_IS_DIR)) {
		string = g_string_new("Invalid file specified for policy 2!");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return;
	}
	
	/* set the cursor to a hand */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();

	rt = sediff_diff_and_load_policies((const char*)p1_file, (const char*)p2_file, TRUE);

	/* diff is done set cursor back to a ptr */
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();

	if (rt < 0)
		return;

	/* destroy the no longer needed dialog widget */
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;

}

typedef struct filename_data {
	GString *p1_file;
	GString *p2_file;
} filename_data_t;

/*
 * We don't want to do the heavy work of loading and displaying 
 * the diff before the main loop has started because it will freeze
 * the gui for too long. To solve this, the function is called from an
 * idle callback set-up in main.
 */
gboolean delayed_main(gpointer data)
{
	filename_data_t *filenames = (filename_data_t *)data;
	const char *p1_file = filenames->p1_file->str;
	const char *p2_file = filenames->p2_file->str;

	sediff_diff_and_load_policies(p1_file,p2_file, TRUE);
	g_string_free(filenames->p1_file,TRUE);
	g_string_free(filenames->p2_file,TRUE);
	return FALSE;
}

void sediff_on_main_notebook_switch_page(GtkNotebook *notebook, GtkNotebookPage *page, guint pagenum, gpointer user_data) 
{
	sediff_app_t *sediff_app = (sediff_app_t*)user_data;
	GtkLabel *label = NULL;
	
	if (pagenum == 0) {
		label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
		gtk_label_set_text(label, "");
	} 
}

int main(int argc, char **argv)
{
	char *dir;
	GString *path; 
	filename_data_t filenames;
	bool_t havefiles = FALSE;
	int optc;
	int cli;
	const char *fname1;
	filenames.p1_file = filenames.p2_file = NULL;
	GtkNotebook *notebook;
	
	if (rindex(argv[0],'/')) {
		fname1 = rindex(argv[0],'/')+1;
	}
	else
		fname1 = argv[0];

	cli = strncmp("sediffx",fname1,strlen("sediffx"));
	
	while ((optc = getopt_long (argc, argv, "qXctrubiTRCshv", longopts, NULL)) != -1)  {
		switch (optc) {
		case 0:
	  		break;
		case 'X': /* gui */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
			break;
	  	case 'c': /* classes */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 't': /* types */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 'r': /* roles */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 'u': /* users */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 'b': /* conditional booleans */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 'i': /* initial SIDs */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 's': /* stats */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 'T': /* te rules */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 'R': /* rbac */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 'C': /* conditionals */
			if (cli == 0) {
				usage(argv[0], 0);
				exit(0);
			}
	  		break;
	  	case 'h': /* help */
	  		usage(argv[0], 0);
	  		exit(0);
	  		break;
	  	case 'v': /* version */
	  		printf("\n%s (sediff ver. %s)\n\n", COPYRIGHT_INFO, SEDIFF_VERSION_NUM);
	  		exit(0);
	  		break;
	  	default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}

	/* sediff with file names */
	if (argc - optind == 2) {
		havefiles = TRUE;
		filenames.p1_file = g_string_new(argv[optind]); 
		filenames.p2_file = g_string_new(argv[optind+1]); 
	}
	else if (argc - optind != 0){
		usage(argv[0],0);
		return -1; 
	}

	
	gtk_init(&argc, &argv);
	glade_init();
	dir = find_file(GLADEFILE);
	if (!dir){
		fprintf(stderr, "Could not find sediff.glade!");
		return -1;
	}

	path = g_string_new(dir);
	free(dir);
	g_string_append_printf(path, "/%s", GLADEFILE);
	
	sediff_app = (sediff_app_t *)malloc(sizeof(sediff_app_t));
	if (!sediff_app) {
		g_warning("Out of memory!");
		exit(-1);
	}
	memset(sediff_app, 0, sizeof(sediff_app_t));

	gtk_set_locale();
	gtk_init(&argc, &argv);
	sediff_app->window_xml = glade_xml_new(path->str, MAIN_WINDOW_ID, NULL);
	if (!sediff_app->window_xml) {
		free(sediff_app);
		g_warning("Unable to create interface");
		return -1;
	}
	sediff_app->window = GTK_WINDOW(glade_xml_get_widget(sediff_app->window_xml, MAIN_WINDOW_ID));
	g_signal_connect(G_OBJECT(sediff_app->window), "delete_event", 
			 G_CALLBACK(on_sediff_main_window_destroy), sediff_app);
	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));
	g_assert(notebook);
	g_signal_connect_after(G_OBJECT(notebook), "switch-page", 
			 G_CALLBACK(sediff_on_main_notebook_switch_page), sediff_app);
		
	glade_xml_signal_autoconnect(sediff_app->window_xml);
	
	if (havefiles) {
		g_idle_add(&delayed_main,&filenames);
	} else {
		sediff_initialize();
	}
	
	gtk_main();
	
	return 0;
}
                          

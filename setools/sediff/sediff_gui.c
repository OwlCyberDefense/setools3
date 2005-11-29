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
#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>
#include <poldiff.h>
#include <render.h>
#include <binpol/binpol.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <time.h>
#include <sys/mman.h>

/* The following should be defined in the make environment */
#ifndef SEDIFF_GUI_VERSION_NUM
	#define SEDIFF_GUI_VERSION_NUM "UNKNOWN"
#endif

#ifndef COPYRIGHT_INFO
        #define COPYRIGHT_INFO "Copyright (C) 2004-2005 Tresys Technology, LLC"
#endif

#define SEDIFF_GUI_PROG	"sediffx"
#define LOADING_DIALOG_ID      "sediff_loading"
#define MAXMYFILELEN     100
#define TABSIZE          4

sediff_app_t *sediff_app = NULL;
gboolean toggle = TRUE;
gint curr_option = OPT_CLASSES; 

static int sediff_txt_buffer_insert_te_results(GtkTextBuffer *txt, ap_single_te_diff_t *sted, policy_t *policy1, policy_t *policy2,
					       int opts, bool_t showheader);
static int sediff_txt_buffer_insert_cond_results(GtkTextBuffer *txt, ap_single_cond_diff_t *scd,
						 policy_t *policy_old, policy_t *policy_new,int opts);
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
  {"run-diff", no_argument, NULL, 'd' },
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

static gboolean sediff_modal_dlg_destroy()
{
	GtkWidget *widget = NULL;
	if (sediff_app->modal_dlg != NULL) {
		widget = GTK_WIDGET(sediff_app->modal_dlg);
		gtk_widget_destroy(GTK_WIDGET(sediff_app->modal_dlg));
		sediff_app->modal_dlg = NULL;
	}
	return FALSE;
}

static void sediff_modal_dialog_on_window_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
  	gtk_widget_destroy(widget);
	sediff_app->modal_dlg = NULL;
}

static gboolean sediff_modal_dlg_show(const char *title,const char *label_string)
{
	GtkWidget *label;
	/* if the dialog is not already up */
	if (sediff_app->modal_dlg == NULL) {
		sediff_app->modal_dlg = gtk_dialog_new_with_buttons (title,
						      sediff_app->window,
						      GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_NO_SEPARATOR,
				     NULL);
		gtk_widget_set_usize(sediff_app->modal_dlg,300,100);
		label = gtk_label_new (label_string);
		gtk_container_add (GTK_CONTAINER (GTK_DIALOG(sediff_app->modal_dlg)->vbox),
				   label);
	}
	g_signal_connect(G_OBJECT(sediff_app->modal_dlg), "delete_event", 
			 G_CALLBACK(sediff_modal_dialog_on_window_destroy), sediff_app);

	gtk_widget_show_all (sediff_app->modal_dlg);
	while (gtk_events_pending ())
		gtk_main_iteration ();

	return FALSE;
}

static void sediff_lazy_load_large_buffer(unsigned int buff_idx, gboolean show_dialog)
{
	if (show_dialog)
		sediff_modal_dlg_show("Loading...", "Loading text - this may take a while.");

	switch (buff_idx) {
	case OPT_TE_RULES_ADD:
		if (sediff_app->te_add_buffer == NULL) {
			sediff_app->te_add_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_add_buffer, sediff_app->svd->te, sediff_app->p1, 
							    sediff_app->p2, AP_SVD_OPT_ADD, TRUE);
		}
		break;
	case OPT_TE_RULES_ADD_TYPE:
		if (sediff_app->te_add_type_buffer == NULL) {
			sediff_app->te_add_type_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_add_type_buffer, sediff_app->svd->te, sediff_app->p1, 
							    sediff_app->p2, AP_SVD_OPT_ADD_TYPE, TRUE);
		}
		break;
	case OPT_TE_RULES_REM:
		if (sediff_app->te_rem_buffer == NULL) {
			sediff_app->te_rem_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_rem_buffer, sediff_app->svd->te, sediff_app->p1, 
							    sediff_app->p2, AP_SVD_OPT_REM, TRUE);
		}
		break;
	case OPT_TE_RULES_REM_TYPE:
		if (sediff_app->te_rem_type_buffer == NULL) {
			sediff_app->te_rem_type_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_rem_type_buffer, sediff_app->svd->te, sediff_app->p1, 
							    sediff_app->p2, AP_SVD_OPT_REM_TYPE, TRUE);
		}
		break;
	case OPT_TE_RULES_CHG:
		if (sediff_app->te_chg_buffer == NULL) {
			sediff_app->te_chg_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_te_results(sediff_app->te_chg_buffer, sediff_app->svd->te, sediff_app->p1, 
							    sediff_app->p2, AP_SVD_OPT_CHG, TRUE);
		}
		break;
	case OPT_CONDITIONALS_ADD:
		if (sediff_app->cond_add_buffer == NULL) {
			sediff_app->cond_add_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_cond_results(sediff_app->cond_add_buffer, sediff_app->svd->conds, sediff_app->p1, 
							      sediff_app->p2, AP_SVD_OPT_ADD);
		}
		break;
	case OPT_CONDITIONALS_REM:
		if (sediff_app->cond_rem_buffer == NULL) {
			sediff_app->cond_rem_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_cond_results(sediff_app->cond_rem_buffer, sediff_app->svd->conds, sediff_app->p1, 
							      sediff_app->p2, AP_SVD_OPT_REM);
		}
		break;
	case OPT_CONDITIONALS_CHG:
		if (sediff_app->cond_chg_buffer == NULL) {
			sediff_app->cond_chg_buffer = gtk_text_buffer_new(NULL);
			sediff_txt_buffer_insert_cond_results(sediff_app->cond_chg_buffer, sediff_app->svd->conds, sediff_app->p1, 
							      sediff_app->p2, AP_SVD_OPT_CHG);
		}

		break;
	default:
		assert(FALSE);
		break;
	}

	if (show_dialog)
		sediff_modal_dlg_destroy();
}

static void usage(const char *program_name, int brief)
{
	printf("%s (sediff ver. %s)\n\n", COPYRIGHT_INFO, SEDIFF_VERSION_NUM);
	printf("Usage: %s [-h|-v]\n", program_name);
	printf("Usage: %s [-d] [POLICY1 POLICY2]\n",program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Semantically differentiate two policies.  The policies can be either source\n \
or binary policy files, version 15 or later.  By default, all supported\n \
policy elements are examined.  The following diff options are available:\n \
", stdout);
	fputs("\n\
  -h, --help       display this help and exit\n\
  -v, --version    output version information and exit\n\
  -d, --diff-now   diff the policies immediately\n\n\
", stdout);
	return;
}

/* allocate a string that creates a "tab" of numspaces
   user in charge of freeing */
static char *sediff_get_tab_spaces(int numspaces)
{
	char *c = NULL;
	int i;

	c = (char *)malloc(sizeof(char)*(numspaces+1));
	if (!c) {
		g_warning("Out of memory!");
		exit(-1);
	}
	for (i = 0; i<numspaces; i++) {
		c[i] = ' ';
	}
	c[numspaces] = '\0'; 

	return c;
}

static int sediff_add_hdr(GtkTextBuffer *txt, GString *string)
{
	GtkTextTag *header_tag;
	GtkTextTagTable *table;
	GtkTextIter iter;

	gtk_text_buffer_get_end_iter(txt, &iter);
	table = gtk_text_buffer_get_tag_table(txt);
	header_tag = gtk_text_tag_table_lookup(table, "main-header-tag");
	if(header_tag == NULL) {
		header_tag = gtk_text_buffer_create_tag (txt, "main-header-tag", "family", "monospace", "style", 
							 PANGO_STYLE_ITALIC, "weight", PANGO_WEIGHT_BOLD, NULL); 
	}
	gtk_text_buffer_get_start_iter(txt, &iter);
	gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, header_tag, NULL);
	return 0;
}

/* clear text from passed in text buffer */
static void sediff_clear_text_buffer(GtkTextBuffer *txt)
{
	GtkTextIter start, end;
	
	gtk_text_buffer_get_start_iter(txt, &start);
	gtk_text_buffer_get_end_iter(txt, &end);
	gtk_text_buffer_remove_all_tags(txt, &start, &end);
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
static void sediff_callback_signal_emit(unsigned int type)
{

	g_list_foreach(sediff_app->callbacks, &sediff_callback_signal_emit_1, &type);
	return;
}

/* print the elements  in a int_a_diff where there is a change because of a type */
static int sediff_txt_buffer_insert_iad_type_chg_elements(GtkTextBuffer *txt, GString *string, GtkTextTag *tag_add, 
							  GtkTextTag *tag_rem, ap_single_iad_chg_t *asic, policy_t *p_add, 
							  policy_t *p_rem, char *adescrp, get_iad_name_fn_t get_a_name)
{
	int i;
	char *tmp;
	int rt;
	GtkTextIter iter;

	gtk_text_buffer_get_end_iter(txt, &iter);
	for (i=0; i < asic->num_add;i++) {
		rt = (*get_a_name)(asic->add[i], &tmp, p_add);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, asic->add[i]);
			return -1;
		}
		g_string_printf(string, "\t\t\t+ %s\n", tmp);
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str, 
						 -1, tag_add, NULL);
		free(tmp);
	}
	for (i=0; i < asic->num_rem;i++) {
		rt = (*get_a_name)(asic->rem[i], &tmp, p_rem);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, asic->rem[i]);
			return -1;
		}
		g_string_printf(string, "\t\t\t- %s\n", tmp);
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str, 
						 -1, tag_rem, NULL);
		free(tmp);
	}

	return 0;
}

static int sediff_txt_buffer_insert_iad_elements(GtkTextBuffer *txt, GString *string, GtkTextTag *tag, int_a_diff_t *diff, 
						 policy_t *policy, bool_t added, char *adescrp, get_iad_name_fn_t get_a_name)
{
	int i;
	char *tmp;
	int rt;
	GtkTextIter iter;

	gtk_text_buffer_get_end_iter(txt, &iter);
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
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, tag, NULL);
		free(tmp);
	}
	return 0;
}

static int sediff_txt_buffer_insert_rallow_element(GtkTextBuffer *txt, GString *string, GtkTextTag *tag, int_a_diff_t *diff, 
						   policy_t *policy, bool_t added, char *adescrp, get_iad_name_fn_t get_a_name)
{
	int i;
	char *tmp;
	int rt;
	GString *local_string = g_string_new("");
	GtkTextIter iter;

	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, tag, NULL);
	g_string_printf(local_string, " {");	       
	gtk_text_buffer_insert_with_tags(txt, &iter, local_string->str, 
							 -1, tag, NULL);
	for (i = 0; i < diff->numa; i++) {
		rt = (*get_a_name)(diff->a[i], &tmp, policy);
		if (rt < 0) {
			fprintf(stderr, "Problem getting element name for %s %d\n", adescrp, diff->a[i]);
			return -1;
		}
		g_string_printf(local_string, " %s", tmp);	       
		gtk_text_buffer_insert_with_tags(txt, &iter, local_string->str, 
							 -1, tag, NULL);
		free(tmp);
	}
	g_string_printf(local_string, " }\n");	       
	gtk_text_buffer_insert_with_tags(txt, &iter, local_string->str, 
							 -1, tag, NULL);

	g_string_free(local_string,TRUE);
	return 0;
}

static int sediff_txt_buffer_insert_rallow_rules(GtkTextBuffer *txt, GString *string, GtkTextTag *tag, policy_t *p1, 
						 policy_t *p2,char *name,char *adescrip)
{
	rbac_bool_t rb, rb2;
	int rt,idx1,idx2,i;
	char *rname = NULL;
	int num_found;
	GtkTextIter iter;

	/* find index of both roles in policies */
	idx1 = get_role_idx(name,p1);
	idx2 = get_role_idx(name, p2);

	if (init_rbac_bool(&rb, p1, TRUE) != 0) 
		goto sediff_txt_buffer_insert_rallow_rules_error;
	
	if (init_rbac_bool(&rb2, p2, TRUE) != 0) 
		goto sediff_txt_buffer_insert_rallow_rules_error;
	

	/* find all target roles that have that role in the source of a role allow rule */
	rt = match_rbac_roles(idx1, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb, &num_found, p1);
	if (rt < 0) 
		return -1;
	rt = match_rbac_roles(idx2, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb2, &num_found, p2);
	if (rt < 0) {
		free_rbac_bool(&rb);
		return -1;
	}
	/* print that stuff out */
	g_string_printf(string, "\t\t* Policy 1: allow %s",name);
	g_string_append(string," { ");
	for (i = 0; i < p1->num_roles; i++) {
		if (!rb.allow[i])
			continue;
		rt = get_role_name(i,&rname,p1);
		if (rt < 0)
			goto sediff_txt_buffer_insert_rallow_rules_error;
		g_string_append_printf(string,"%s ",rname);
		free(rname);
		rname = NULL;		
	}
	g_string_append(string,"}\n");
	g_string_append_printf(string, "\t\t* Policy 2: allow %s", name);
	g_string_append(string," { ");
	for (i = 0; i < p2->num_roles; i++) {
		if (!rb2.allow[i])
			continue;
		rt = get_role_name(i,&rname,p2);
		if (rt < 0)
			goto sediff_txt_buffer_insert_rallow_rules_error;
		g_string_append_printf(string,"%s ",rname);
		free(rname);
		rname = NULL;
	}
	g_string_append(string,"}\n");
	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, tag, NULL);
	free_rbac_bool(&rb);
	free_rbac_bool(&rb2);
	return 0;

 sediff_txt_buffer_insert_rallow_rules_error:
	if (rname)
		free(rname);
	free_rbac_bool(&rb);
	free_rbac_bool(&rb2);
	return -1;
}

static int sediff_txt_buffer_insert_rallow_results(GtkTextBuffer *txt, GString *string, ap_single_iad_diff_t *siad, 
						   policy_t *p_old, policy_t *p_new,int opts)
{
	get_iad_name_fn_t get_name, get_a_name;
	char *name, *descrp = NULL, *adescrp = NULL;
	int rt,i;
	GtkTextTag *added_tag, *removed_tag, *changed_tag;
	GtkTextTag *header_added_tag,*header_removed_tag,*header_changed_tag,*header_tag;		
	GtkTextTagTable *table;
	GtkTextMark *mark;
	GtkTextIter iter;

	gtk_text_buffer_get_start_iter(txt, &iter);

	/* create a mark that always goes to the left..urr top */ 	
	mark = gtk_text_buffer_get_mark(txt,"added-mark");
	if (!mark)
		mark = gtk_text_buffer_create_mark (txt,"added-mark",&iter,TRUE);
	gtk_text_buffer_get_iter_at_mark(txt,&iter,mark);



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
	assert(((IDX_TYPE|IDX_ATTRIB|IDX_ROLE|IDX_USER|IDX_OBJ_CLASS|IDX_COMMON_PERM|IDX_PERM)) != 0);

       	switch(siad->id) {
	case IDX_ROLE|IDX_PERM:
		get_name = &get_role_name;
		get_a_name = &get_role_name;
		descrp = "Role Allows";
		adescrp = "Role Allows";
		break;
	default:
		g_return_val_if_reached(-1);
		break;
	}

	g_string_printf(string, "%s (%d Added, %d Removed, %d Changed)\n",descrp,siad->num_add,
			siad->num_rem, siad->num_chg);

	sediff_add_hdr(txt, string);

	/* First goes adds */
	if (opts & AP_SVD_OPT_ADD) {
		g_string_printf(string, "\tAdded %s: %d\n",descrp,siad->num_add);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "header-added-tag", NULL);
		for (i=0; i<siad->num_add; i++) {
			rt = (*get_name)(siad->add[i]->idx, &name, p_new);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, siad->add[i]->idx);
				return -1;
			}
			g_string_printf(string, "\t\t+ %s", name);
			rt = sediff_txt_buffer_insert_rallow_element(txt, string, added_tag, siad->add[i], p_new, FALSE, adescrp, get_a_name);
			if (rt < 0)
				return -1;
			free(name);
		}
	}
	if (opts & AP_SVD_OPT_REM) {
		g_string_printf(string, "\tRemoved %s: %d\n",descrp,siad->num_rem);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "header-removed-tag", NULL);
		for (i=0; i<siad->num_rem; i++) {	       
			rt = (*get_name)(siad->rem[i]->idx, &name, p_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, siad->rem[i]->idx);
				return -1;
			}
			g_string_printf(string, "\t\t- allow %s", name);
			rt = sediff_txt_buffer_insert_rallow_element(txt, string,removed_tag,siad->rem[i],p_old,TRUE,adescrp,get_a_name);
			if (rt < 0)
				return -1;
			free(name);
		}

	}

	if (opts & AP_SVD_OPT_CHG) {
		g_string_printf(string, "\tChanged %s: %d\n",descrp,siad->num_chg);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "header-changed-tag", NULL);
		
		for (i=0; i < siad->num_chg; i++) {
			if (siad->chg[i].p1_idx >= 0)
				rt = (*get_name)(siad->chg[i].p1_idx, &name, p_old);			
			else
				rt = (*get_name)(siad->chg[i].p2_idx, &name, p_new);
			if (rt < 0)
				return -1;
			if (siad->chg[i].rem_iad != NULL && siad->chg[i].add_iad != NULL) {
				sediff_txt_buffer_insert_rallow_rules(txt, string,changed_tag,p_old,p_new,name,adescrp);
				rt = sediff_txt_buffer_insert_iad_elements(txt, string,added_tag,siad->chg[i].add_iad,p_new,TRUE,adescrp,get_a_name);
				if (rt < 0)
					return -1;
				rt = sediff_txt_buffer_insert_iad_elements(txt, string,removed_tag,siad->chg[i].rem_iad,p_old,FALSE,adescrp,get_a_name);
				if (rt < 0)
					return -1;
				
			} else if (siad->chg[i].rem_iad != NULL) {
				sediff_txt_buffer_insert_rallow_rules(txt, string,changed_tag,p_old,p_new,name,adescrp);
				rt = sediff_txt_buffer_insert_iad_elements(txt, string,removed_tag,siad->chg[i].rem_iad,p_old,FALSE,adescrp,get_a_name);
				if (rt < 0)
					return -1;
				
			} else {
				sediff_txt_buffer_insert_rallow_rules(txt, string,changed_tag,p_old,p_new,name,adescrp);
				rt = sediff_txt_buffer_insert_iad_elements(txt, string,added_tag,siad->chg[i].add_iad,p_new,TRUE,adescrp,get_a_name);
				if (rt < 0)
					return -1;
			}			
			free(name);
		}
	}
	return 0;
}


static int sediff_txt_buffer_insert_iad_results(GtkTextBuffer *txt, GString *string, ap_single_iad_diff_t *siad, 
						policy_t *p_old, policy_t *p_new, int opts)
{
	get_iad_name_fn_t get_name, get_a_name;
	char *name, *descrp = NULL, *adescrp = NULL;
	int rt,i;
	GtkTextTag *added_tag, *removed_tag, *changed_tag;
	GtkTextTag *header_added_tag,*header_removed_tag,*header_changed_tag,*header_tag;		
	GtkTextTagTable *table;
	bool_t type_chg = FALSE;
	GtkTextMark *mark;
	GtkTextIter iter;

	if (string == NULL || p_old == NULL || p_new == NULL) {
		g_assert(FALSE);
		return -1;
	}

	gtk_text_buffer_get_start_iter(txt, &iter);

	/* create a mark that always goes to the left..urr top */ 	
	mark = gtk_text_buffer_get_mark(txt,"added-mark");
	if (!mark)
		mark = gtk_text_buffer_create_mark (txt,"added-mark",&iter,TRUE);
	gtk_text_buffer_get_iter_at_mark(txt,&iter,mark);

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

       	switch(siad->id) {
	case IDX_ROLE|IDX_PERM:
		get_name = &get_role_name;
		get_a_name = &get_role_name;
		descrp = "Role Allows";
		adescrp = "Role Allows";
		break;
	case IDX_TYPE:
		get_name = &get_type_name;
		get_a_name = &get_attrib_name;
		descrp = "Types";
		adescrp = "Attributes";
		break;
	case IDX_ATTRIB:
		get_name = &get_attrib_name;
		get_a_name = &get_type_name;
		descrp = "Attributes";
		adescrp = "Types";
		type_chg = TRUE;
		break;
	case IDX_ROLE:
		get_name = &get_role_name;
		get_a_name = &get_type_name;
		descrp = "Roles";
		adescrp = "Types";
		type_chg = TRUE;
		break;
	case IDX_USER:
		get_name = &get_user_name2;
		get_a_name = &get_role_name;
		descrp = "Users";
		adescrp = "Roles";
		break;
	case IDX_OBJ_CLASS:
		get_name = &get_obj_class_name;
		get_a_name = &get_perm_name;
		descrp = "Classes";
		adescrp = "Permissions";
		break;
	case IDX_COMMON_PERM:
		get_name = &get_common_perm_name;
		get_a_name = &get_perm_name;
		descrp = "Commons";
		adescrp = "Permissions";
		break;
	default:
		g_assert(FALSE);
		return -1;
	}

	if (type_chg == FALSE)
		g_string_printf(string, "%s (%d Added, %d Removed, %d Changed)\n",descrp,siad->num_add,
				siad->num_rem, siad->num_chg);
	else
		g_string_printf(string, "%s (%d Added, %d Removed, %d Changed, %d "
				"Changed New Type , %d Changed Missing Type)\n",descrp,siad->num_add,
				siad->num_rem, siad->num_chg,siad->num_chg_add,siad->num_chg_rem);

	sediff_add_hdr(txt, string);

	/* First goes adds */
	if (opts & AP_SVD_OPT_ADD) {
		g_string_printf(string, "\tAdded %s: %d\n", descrp, siad->num_add);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "header-added-tag", NULL);
		for (i=0; i<siad->num_add; i++) {
			rt = (*get_name)(siad->add[i]->idx, &name, p_new);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, siad->add[i]->idx);
				return -1;
			}
			g_string_printf(string, "\t\t+ %s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "added-tag", NULL);
			free(name);
		}
	}
	if (opts & AP_SVD_OPT_REM) {
		g_string_printf(string, "\tRemoved %s: %d\n",descrp,siad->num_rem);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "header-removed-tag", NULL);
		for (i=0; i<siad->num_rem; i++) {	       
			rt = (*get_name)(siad->rem[i]->idx, &name, p_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, siad->rem[i]->idx);
				return -1;
			}
			g_string_printf(string, "\t\t- %s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "removed-tag", NULL);
			free(name);
		}

	}

	if (opts & AP_SVD_OPT_CHG && !((siad->id & IDX_ROLE) | (siad->id & IDX_ATTRIB))) {
		g_string_printf(string, "\tChanged %s: %d\n",descrp,siad->num_chg);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "header-changed-tag", NULL);

		for (i=0; i < siad->num_chg; i++) {
			if (siad->chg[i].p1_idx >= 0)
				rt = (*get_name)(siad->chg[i].p1_idx, &name, p_old);			
			else
				rt = (*get_name)(siad->chg[i].p2_idx, &name, p_new);
			if (rt < 0)
				return -1;
			if (siad->chg[i].rem_iad != NULL && siad->chg[i].add_iad != NULL) {
				g_string_printf(string, "\t\t* %s (%d Added, %d Removed %s)\n", name,
						siad->chg[i].add_iad->numa,siad->chg[i].rem_iad->numa, adescrp);
				gtk_text_buffer_get_end_iter(txt, &iter);
				gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
									 -1, "changed-tag", NULL);			
				rt = sediff_txt_buffer_insert_iad_elements(txt, string, added_tag, siad->chg[i].add_iad, p_new, TRUE, adescrp, get_a_name);
				if (rt < 0)
					return -1;
				rt = sediff_txt_buffer_insert_iad_elements(txt, string, removed_tag, siad->chg[i].rem_iad, p_old, FALSE, adescrp, get_a_name);
				if (rt < 0)
					return -1;

			} else if (siad->chg[i].rem_iad != NULL) {
				g_string_printf(string, "\t\t* %s (%d Removed %s)\n", name, siad->chg[i].rem_iad->numa, adescrp);
				gtk_text_buffer_get_end_iter(txt, &iter);
				gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "changed-tag", NULL);			
				rt = sediff_txt_buffer_insert_iad_elements(txt, string, removed_tag, siad->chg[i].rem_iad, p_old, FALSE, adescrp, get_a_name);
				if (rt < 0)
					return -1;

			} else {
				g_string_printf(string, "\t\t* %s (%d Added %s)\n", name, siad->chg[i].add_iad->numa, adescrp);
				gtk_text_buffer_get_end_iter(txt, &iter);
				gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "changed-tag", NULL);			
				rt = sediff_txt_buffer_insert_iad_elements(txt,string,added_tag,siad->chg[i].add_iad,p_new,TRUE,adescrp,get_a_name);
				if (rt < 0)
					return -1;
			}			
			free(name);
		}
	} else if (opts & AP_SVD_OPT_CHG && ((siad->id & IDX_ROLE) | (siad->id & IDX_ATTRIB))) {
		g_string_printf(string, "\tChanged %s: %d\n",descrp,siad->num_chg);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "header-changed-tag", NULL);
		for (i=0; i < siad->num_chg; i++) {
			if (siad->chg[i].p1_idx >= 0)
				rt = (*get_name)(siad->chg[i].p1_idx, &name, p_old);			
			else
				rt = (*get_name)(siad->chg[i].p2_idx, &name, p_new);
			g_string_printf(string, "\t\t* %s (%d Added, %d Removed %s)\n", name,
					siad->chg[i].num_add,siad->chg[i].num_rem, adescrp);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "changed-tag", NULL);			
			sediff_txt_buffer_insert_iad_type_chg_elements(txt, string, added_tag, removed_tag, &(siad->chg[i]), p_new, p_old, adescrp, get_a_name);
			free(name);
		}
	}
	if (opts & AP_SVD_OPT_ADD_TYPE) {
		g_string_printf(string, "\tChanged, New Type %s: %d\n",descrp,siad->num_chg_add);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "header-changed-tag", NULL);
		for (i=0; i < siad->num_chg_add; i++) {
			rt = (*get_name)(siad->chg_add[i].p2_idx, &name, p_new);			
			g_string_printf(string, "\t\t* %s (%d Added, %d Removed %s)\n", name,
					siad->chg_add[i].num_add,siad->chg_add[i].num_rem, adescrp);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "changed-tag", NULL);			
			sediff_txt_buffer_insert_iad_type_chg_elements(txt, string, added_tag, removed_tag, &(siad->chg_add[i]), p_new, p_old, adescrp, get_a_name);
			free(name);
		}
	}
	if (opts & AP_SVD_OPT_REM_TYPE) {
		g_string_printf(string, "\tChanged, Removed Type %s: %d\n",descrp,siad->num_chg_rem);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "header-removed-tag", NULL);
		for (i=0; i < siad->num_chg_rem; i++) {
			rt = (*get_name)(siad->chg_rem[i].p1_idx, &name, p_old);			
			g_string_printf(string, "\t\t* %s (%d Added, %d Removed %s)\n", name,
					siad->chg_rem[i].num_add,siad->chg_rem[i].num_rem, adescrp);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "changed-tag", NULL);			
			sediff_txt_buffer_insert_iad_type_chg_elements(txt, string, added_tag, removed_tag, &(siad->chg_rem[i]), p_new, p_old, adescrp, get_a_name);
			free(name);
		}
	}

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


static void sediff_main_window_rename_policy_tabs(GString *p1, GString *p2) 
{
	const char *fname1; 
	const char *fname2; 
	GtkNotebook *notebook;
	GtkWidget *p1_label,*p2_label;
	GString *string = g_string_new("");

	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));

	if (p1 == NULL || p1->str == NULL) {
		p1_label = gtk_label_new("Policy 1");
		gtk_widget_show(p1_label);
		gtk_notebook_set_tab_label(notebook, gtk_notebook_get_nth_page(notebook, 1), p1_label);
	} else if (rindex(p1->str,'/')) {
		fname1 = rindex(p1->str,'/')+1;
		g_string_printf(string,"Policy 1: %s",fname1);
		p1_label = gtk_label_new (string->str);
		gtk_widget_show (p1_label);
		gtk_notebook_set_tab_label (notebook, gtk_notebook_get_nth_page (notebook, 1), p1_label);
	}
	
	if (p2 == NULL || p2->str == NULL) {
		p2_label = gtk_label_new("Policy 2");
		gtk_widget_show(p2_label);
		gtk_notebook_set_tab_label(notebook, gtk_notebook_get_nth_page(notebook, 2), p2_label);
	} else if (rindex(p2->str,'/')) {
		fname2 = rindex(p2->str,'/')+1;
		g_string_printf(string,"Policy 2: %s",fname2);
		p2_label = gtk_label_new (string->str);
		gtk_widget_show (p2_label);
		gtk_notebook_set_tab_label (notebook, gtk_notebook_get_nth_page (notebook, 2), p2_label);
	}
	g_string_free(string,TRUE);
}

static void sediff_set_open_policies_gui_state(gboolean open)
{
	GtkWidget *widget = NULL;

	widget = glade_xml_get_widget(sediff_app->window_xml, "toolbutton_rename_types");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, open);
	widget = glade_xml_get_widget(sediff_app->window_xml, "toolbutton_run_diff");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, open);
	widget = glade_xml_get_widget(sediff_app->window_xml, "menu_rename_types");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, open);
	widget = glade_xml_get_widget(sediff_app->window_xml, "menu_run_diff");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, open);
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_menu_find");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, open);
	sediff_main_window_rename_policy_tabs(sediff_app->p1_sfd.name, sediff_app->p2_sfd.name);
}

static int sediff_txt_buffer_insert_boolean_results(GtkTextBuffer *txt, GString *string, ap_single_bool_diff_t *sbd,
						    policy_t *policy_old, policy_t *policy_new, uint options)
{
	int rt,i;
	char *name;
	bool_t state;
	GtkTextTag *added_tag, *removed_tag, *changed_tag;
	GtkTextTag *header_added_tag,*header_removed_tag,*header_changed_tag,*header_tag;		
	GtkTextTagTable *table;
	GtkTextIter iter;

	
	if (policy_old == NULL || policy_new == NULL)
		return -1;
		

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

	g_string_printf(string, "Booleans (%d Added, %d Removed, %d Changed)\n",sediff_app->svd->bools->num_add,
			sediff_app->svd->bools->num_rem, sediff_app->svd->bools->num_chg);
	sediff_add_hdr(txt, string);

	/* added booleans */
	if (options & AP_SVD_OPT_ADD) {
		g_string_printf(string, "\tAdded Booleans: %d\n",sbd->num_add);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
							 -1, "header-added-tag", NULL);
		for (i = 0;i < sbd->num_add;i++) {
			rt = get_cond_bool_name(sbd->add[i]->idx, &name, policy_new);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", sbd->add[i]->idx);
				return -1;
			}
			g_string_printf(string, "\t\t+ %s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "added-tag", NULL);
			free(name);
		}
	}

	/* removed booleans */
	if (options & AP_SVD_OPT_REM) {
		/* removed booleans header */
		g_string_printf(string, "\tRemoved Booleans: %d\n",sbd->num_rem);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "header-removed-tag", NULL);
		for (i = 0;i < sbd->num_rem;i++) {
			rt = get_cond_bool_name(sbd->rem[i]->idx, &name, policy_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", sbd->rem[i]->idx);
				return -1;
			}
			g_string_printf(string, "\t\t- %s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "removed-tag", NULL);
			free(name);
		}		
	}

	/* Changed booleans */
	if (options & AP_SVD_OPT_CHG) {
		/* Changed Booleans header */
		g_string_printf(string, "\tChanged Booleans: %d\n",sbd->num_chg);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
							 -1, "header-changed-tag", NULL);
		for (i = 0;i < sbd->num_chg;i++) {
			rt = get_cond_bool_name(sbd->chg[i]->idx, &name, policy_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for boolean %d\n", sbd->chg[i]->idx);
				return -1;
			}
			g_string_printf(string, "\t\t* %s (changed", name);
			rt = get_cond_bool_default_val_idx(sbd->chg[i]->idx, &state, policy_old);
			if (rt < 0) {
				fprintf(stderr, "Problem getting boolean state for %s\n", name);
				free(name);
				return -1;
			}
			g_string_append_printf(string, " from %s to %s)\n", (state ? "TRUE" : "FALSE"), (state ? "FALSE" : "TRUE") );
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "changed-tag", NULL);
			free(name);
		}				
	      
	}

	return 0;
}

/* raise the correct policy tab on the gui, and go to the line clicked by the user */
static void sediff_main_notebook_raise_policy_tab_goto_line(unsigned long line, int whichview)
{
	GtkNotebook *main_notebook,*tab_notebook;
	GtkTextBuffer *buffer;
	GtkTextIter iter,end_iter;
	GtkTextView *text_view = NULL;
	GtkTextTagTable *table = NULL;
	GtkTextMark *mark = NULL;
	GtkLabel *lbl = NULL;
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

	/* when moving the buffer we must use marks to scroll because
	   goto_line if called before the line height has been calculated can produce 
	   undesired results, in our case we get no scolling at all */
	buffer = gtk_text_view_get_buffer(text_view);
	g_assert(buffer);

	table = gtk_text_buffer_get_tag_table(buffer);

	gtk_text_buffer_get_start_iter(buffer, &iter);
	gtk_text_iter_set_line(&iter, line);
	gtk_text_buffer_get_start_iter(buffer, &end_iter);
	gtk_text_iter_set_line(&end_iter, line);
	while (!gtk_text_iter_ends_line(&end_iter))	
		gtk_text_iter_forward_char(&end_iter);

	mark = gtk_text_buffer_create_mark(buffer, "line-position", &iter, TRUE);	
	assert(mark);
	
	gtk_text_view_scroll_to_mark(text_view, mark, 0.0, TRUE, 0.0, 0.5);
	
	/* destroying the mark and recreating is faster than doing a move on a mark that
	   still exists, so we always destroy it once we're done */
	gtk_text_buffer_delete_mark(buffer, mark);
	gtk_text_view_set_cursor_visible(text_view, TRUE);
	gtk_text_buffer_place_cursor(buffer, &iter);
	gtk_text_buffer_select_range(buffer, &iter, &end_iter);

	gtk_container_set_focus_child(GTK_CONTAINER(tab_notebook),
					 GTK_WIDGET(text_view));
	
	g_string_printf(string, "Line: %d", gtk_text_iter_get_line(&iter)+1);
	lbl = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
	gtk_label_set_text(lbl, string->str);
	g_string_free(string, TRUE);


	return;
}

/* 
 *  returns true when user clicks line number we are able to get it, and 
 *  raise the correct tab 
 */
static gboolean txt_view_on_policy_link_event(GtkTextTag *tag, GObject *event_object, 
					      GdkEvent *event, const GtkTextIter *iter, 
					      gpointer user_data)
{
	int offset,page;
	unsigned long line;
	GtkTextBuffer *buffer;
	GtkTextIter *start, *end;

	if (event->type == GDK_BUTTON_PRESS) {
		page = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(tag),"page"));
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

		sediff_main_notebook_raise_policy_tab_goto_line(line,page);
		return TRUE;
	}

	return FALSE;
}

static void sediff_txt_buffer_insert_summary(GtkTextBuffer *txt, int opt)
{
	GtkTextTagTable *table;
	GtkTextTag *header_tag, *header_removed_tag = NULL, *header_changed_tag = NULL;
	GtkTextTag *header_added_tag = NULL, *main_header_tag;
	GString *string;
	GtkTextIter iter;

	string = g_string_new("");
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

	gtk_text_buffer_get_end_iter(txt, &iter);
	switch(opt) {
	case OPT_CLASSES:		
		g_string_printf(string,"Classes:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, header_tag, NULL);
		g_string_printf(string,"\tAdded: %d\n", sediff_app->svd->classes->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->classes->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->classes->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter, string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_COMMON_PERMS:
		g_string_printf(string,"Commons:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->common_perms->num_add);		
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->common_perms->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->common_perms->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_PERMISSIONS:
		g_string_printf(string,"Permissions:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->perms->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->perms->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		break;
	case OPT_TYPES:
		g_string_printf(string,"Types:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->types->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->types->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->types->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_ATTRIBUTES:
		g_string_printf(string,"Attributes:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->attribs->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->attribs->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->attribs->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		g_string_printf(string,"\tChanged removed type: %d\n",sediff_app->svd->attribs->num_chg_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		g_string_printf(string,"\tChanged added type: %d\n",sediff_app->svd->attribs->num_chg_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_ROLES:
		g_string_printf(string,"Roles:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->roles->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->roles->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->roles->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		g_string_printf(string,"\tChanged removed type: %d\n",sediff_app->svd->roles->num_chg_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		g_string_printf(string,"\tChanged added type: %d\n",sediff_app->svd->roles->num_chg_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_USERS:
		g_string_printf(string,"Users:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->users->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->users->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->users->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_BOOLEANS:
		g_string_printf(string,"Booleans:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->bools->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->bools->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->bools->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_TE_RULES:
		g_string_printf(string,"TE Rules:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->te->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tAdded new type: %d\n",sediff_app->svd->te->num_add_type);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->te->num_rem);		
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tRemoved missing type: %d\n",sediff_app->svd->te->num_rem_type);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->te->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_ROLE_ALLOWS:
		g_string_printf(string,"Role Allows:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->rallows->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->rallows->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->rallows->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_ROLE_TRANS:
		g_string_printf(string,"Role Transitions:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->rtrans->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tAdded new type: %d\n",sediff_app->svd->rtrans->num_add_type);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->rtrans->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tRemoved missing type: %d\n",sediff_app->svd->rtrans->num_rem_type);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->rtrans->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	case OPT_CONDITIONALS:
		g_string_printf(string,"Conditionals:\n");
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_tag,NULL);
		g_string_printf(string,"\tAdded: %d\n",sediff_app->svd->conds->num_add);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_added_tag,NULL);
		g_string_printf(string,"\tRemoved: %d\n",sediff_app->svd->conds->num_rem);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_removed_tag,NULL);
		g_string_printf(string,"\tChanged: %d\n",sediff_app->svd->conds->num_chg);
		gtk_text_buffer_insert_with_tags(txt, &iter,string->str,-1,header_changed_tag,NULL);
		break;
	default:
		break;
	}
	g_string_free(string,TRUE);
}

/* Insert the diff stats into the summary buffer */
static void sediff_txt_buffer_insert_summary_results(GtkTextBuffer *txt)
{
	GtkTextIter iter;
	GtkTextTagTable *table;
	GString *string = g_string_new("");
	GtkTextTag *header_tag, *header_removed_tag = NULL, *header_changed_tag = NULL;
	GtkTextTag *header_added_tag = NULL, *main_header_tag;

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
	gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, main_header_tag, NULL);
	g_string_printf(string,"Policy Filenames:\n");
	gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, header_tag, NULL);
	g_string_printf(string,"\tPolicy 1: %s\n", sediff_app->p1_sfd.name->str);
	gtk_text_buffer_insert(txt,&iter,string->str, -1);
	g_string_printf(string,"\tPolicy 2: %s\n\n", sediff_app->p2_sfd.name->str);
	gtk_text_buffer_insert(txt,&iter,string->str, -1);

	sediff_txt_buffer_insert_summary(txt, OPT_CLASSES);
	sediff_txt_buffer_insert_summary(txt, OPT_COMMON_PERMS);
	sediff_txt_buffer_insert_summary(txt, OPT_PERMISSIONS);
	sediff_txt_buffer_insert_summary(txt, OPT_TYPES);
	sediff_txt_buffer_insert_summary(txt, OPT_ATTRIBUTES);
	sediff_txt_buffer_insert_summary(txt, OPT_ROLES);
	sediff_txt_buffer_insert_summary(txt, OPT_USERS);
	sediff_txt_buffer_insert_summary(txt, OPT_BOOLEANS);
	sediff_txt_buffer_insert_summary(txt, OPT_ROLE_ALLOWS);
	sediff_txt_buffer_insert_summary(txt, OPT_ROLE_TRANS);
	sediff_txt_buffer_insert_summary(txt, OPT_TE_RULES);
	sediff_txt_buffer_insert_summary(txt, OPT_CONDITIONALS);

	g_string_free(string,TRUE);
}

static int sediff_txt_buffer_insert_perms_results(GtkTextBuffer *txt, GString *string, ap_single_perm_diff_t *spd,
						  policy_t *policy_old, policy_t *policy_new, int opts)
{
	int rt, i;
	char *name;
	GtkTextTag *added_tag, *removed_tag, *header_added_tag, *header_removed_tag,*header_tag;		
	GtkTextTagTable *table;
	GtkTextIter iter;

       	g_return_val_if_fail(spd != NULL, -1);

	gtk_text_buffer_get_end_iter(txt, &iter);
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

	g_string_printf(string, "Permissions (%d Added, %d Removed)\n",sediff_app->svd->perms->num_add,
			sediff_app->svd->perms->num_rem);
	sediff_add_hdr(txt, string);


	if (opts & AP_SVD_OPT_ADD) {
		g_string_printf(string,"\tAdded Permissions: %d\n",spd->num_add);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter,string->str,-1,"header-added-tag",NULL);
		for (i = 0; i < spd->num_add; i++) {
			rt = get_perm_name(spd->add[i], &name, policy_new);
			if(rt < 0) {
				fprintf(stderr, "Problem getting name for Permission %d\n", spd->add[i]);
				return -1;
			}
			g_string_printf(string, "\t\t+ %s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "added-tag", NULL);
			gtk_text_buffer_get_end_iter(txt, &iter);
			free(name);
		}
	}
	if (opts & AP_SVD_OPT_REM) {
		g_string_printf(string,"\tRemoved Permissions: %d\n",spd->num_rem);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter,string->str,-1,"header-removed-tag",NULL);
		for (i = 0; i < spd->num_rem; i++) {
			rt = get_perm_name(spd->rem[i], &name, policy_old);
			if(rt < 0) {
				fprintf(stderr, "Problem getting name for Permission %d\n", spd->rem[i]);
				return -1;
			}
			g_string_printf(string, "\t\t- %s\n", name);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "removed-tag", NULL);
			free(name);
		}
	}
	return 0;	
}

static int sediff_txt_buffer_insert_rtrans_results(GtkTextBuffer *txt, GString *string, ap_single_rtrans_diff_t *srd,
						   policy_t *policy_old, policy_t *policy_new, int opts)
{
	char *srole = NULL,*trole = NULL,*type = NULL, *trole2 = NULL;
	GtkTextTag *added_tag, *removed_tag, *changed_tag;
	GtkTextTag *header_added_tag,*header_removed_tag,*header_changed_tag,*header_tag;		
	GtkTextTagTable *table;
	int rt;
	int i;
	GtkTextIter iter;

	if (srd == NULL) {
		g_assert(FALSE);
		return -1;
	}

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

	g_string_printf(string, "Role Transitions (%d Added, %d Added New Type, %d Removed, %d Removed Missing Type"
			", %d Changed)\n",srd->num_add,srd->num_add_type,srd->num_rem,srd->num_rem_type,srd->num_chg);
	sediff_add_hdr(txt, string);

	/* added rtrans */
	if (opts & AP_SVD_OPT_ADD) {
		/* Put added header on */
		g_string_printf(string, "\tAdded Role Transitions: %d\n",srd->num_add);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
							 -1, "header-added-tag", NULL);

		for (i = 0; i < srd->num_add;i++) {
			rt = get_role_name(srd->add[i]->rs_idx,&srole,policy_new);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_type_name(srd->add[i]->t_idx,&type,policy_new);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_role_name(srd->add[i]->rt_idx,&trole,policy_new);
			if (rt < 0)
					goto sediff_txt_buffer_insert_rtrans_error;
			g_string_printf(string,"\t\t+ role_transition %s %s %s\n",srole,type,trole);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
									 -1, "added-tag", NULL);
			free(srole);
			free(type);
			free(trole);
		}
	}

	if (opts & AP_SVD_OPT_ADD_TYPE) {
		/* Put added header on */
		g_string_printf(string, "\tAdded Role Transitions, New Type: %d\n",srd->num_add_type);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
							 -1, "header-added-tag", NULL);
		for (i = 0; i < srd->num_add_type;i++) {
			rt = get_role_name(srd->add_type[i]->rs_idx,&srole,policy_new);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_type_name(srd->add_type[i]->t_idx,&type,policy_new);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_role_name(srd->add_type[i]->rt_idx,&trole,policy_new);
			if (rt < 0)
					goto sediff_txt_buffer_insert_rtrans_error;
			g_string_printf(string,"\t\t+ role_transition %s %s %s\n",srole,type,trole);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
									 -1, "added-tag", NULL);
			free(srole);
			free(type);
			free(trole);			
		}
	}

	if (opts & AP_SVD_OPT_REM) {
		/* Put changed header on */
		g_string_printf(string, "\tRemoved Role Transitions: %d\n",srd->num_rem);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
							 -1, "header-removed-tag", NULL);
		for (i = 0; i < srd->num_rem;i++) {
			rt = get_role_name(srd->rem[i]->rs_idx,&srole,policy_old);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_type_name(srd->rem[i]->t_idx,&type,policy_old);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_role_name(srd->rem[i]->rt_idx,&trole,policy_old);
			if (rt < 0)
					goto sediff_txt_buffer_insert_rtrans_error;
			g_string_printf(string,"\t\t- role_transition %s %s %s\n",srole,type,trole);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
									 -1, "removed-tag", NULL);
			free(srole);
			free(type);
			free(trole);
		}
	}

	if (opts & AP_SVD_OPT_REM_TYPE) {
		/* Put changed header on */
		g_string_printf(string, "\tRemoved Role Transitions, Removed Type: %d\n",srd->num_rem_type);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
							 -1, "header-removed-tag", NULL);
		for (i = 0; i < srd->num_rem_type;i++) {
			rt = get_role_name(srd->rem_type[i]->rs_idx,&srole,policy_old);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_type_name(srd->rem_type[i]->t_idx,&type,policy_old);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_role_name(srd->rem_type[i]->rt_idx,&trole,policy_old);
			if (rt < 0)
					goto sediff_txt_buffer_insert_rtrans_error;
			g_string_printf(string,"\t\t- role_transition %s %s %s\n",srole,type,trole);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
									 -1, "removed-tag", NULL);
			free(srole);
			free(type);
			free(trole);
		}
	}


	/* Changed rtrans */
	if (opts & AP_SVD_OPT_CHG) {
	/* Put changed header on */
		g_string_printf(string, "\tChanged Role Transitions: %d\n",srd->num_chg);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
						 -1, "header-changed-tag", NULL);

		for (i = 0; i < srd->num_chg;i++) {
			rt = get_role_name(srd->chg_rem[i]->rs_idx,&srole,policy_old);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_type_name(srd->chg_rem[i]->t_idx,&type,policy_old);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_role_name(srd->chg_rem[i]->rt_idx,&trole,policy_old);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			rt = get_role_name(srd->chg_add[i]->rt_idx,&trole2,policy_new);
			if (rt < 0)
				goto sediff_txt_buffer_insert_rtrans_error;
			
			gtk_text_buffer_get_end_iter(txt, &iter);
			g_string_printf(string,"\t\t* role_transition %s %s\n",srole,type);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "changed-tag", NULL);
			g_string_printf(string,"\t\t\t+ %s\n",trole2);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "added-tag", NULL);
			g_string_printf(string,"\t\t\t- %s\n",trole);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "removed-tag", NULL);
			free(srole);
			free(type);
			free(trole);
			free(trole2);
		}
	}

	return 0;
 sediff_txt_buffer_insert_rtrans_error:
	return -1;
}
/* 
 * set the cursor to a hand when user scrolls over a line number in when displaying te diff 
 */
gboolean txt_view_on_text_view_motion(GtkWidget *widget, GdkEventMotion *event, gpointer user_data)
{
	GtkTextBuffer *buffer;
 	GtkTextView *textview;
	GdkCursor *cursor;
	GtkTextIter iter;
	GSList *tags,*tagp;
	gint x, ex, ey, y;
	bool_t hovering = FALSE;
	
	textview = GTK_TEXT_VIEW(widget);

	if (event->is_hint) {	
		gdk_window_get_pointer(event->window, &ex, &ey, NULL);
	} else {
		ex = event->x;
		ey = event->y;
	}

	gtk_text_view_window_to_buffer_coords(textview, GTK_TEXT_WINDOW_WIDGET,
					       ex, ey, &x, &y);

	buffer = gtk_text_view_get_buffer(textview);
	gtk_text_view_get_iter_at_location(textview, &iter, x, y);
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

/*
 * switches the currently displayed text buffer
 */
static void sediff_results_txt_view_switch_buffer(GtkTextView *textview,gint option,gint policy_option)
{
	GtkTextTag *link1_tag;
	GtkTextTag *link2_tag;
	GtkTextTagTable *table;
	GtkTextAttributes *attr;
	gint size;
	PangoTabArray *tabs;
	GtkTextIter end;
	GString *string = g_string_new("");
	int rt;
	GtkWidget *widget = NULL;
	GtkTextIter iter;
	GtkTextMark *mark;
	GtkTextBuffer *txt;
	GdkRectangle rect;

	/* Save position in this buffer 
	   you must use an offset because an x/y coord is does not stay true
	   across clears and redraws */
	gtk_text_view_get_visible_rect(textview, &rect);
	gtk_text_view_get_iter_at_location(textview, &iter, rect.x,
					   rect.y);
	sediff_app->tv_buf_offsets[sediff_app->tv_curr_buf] = gtk_text_iter_get_offset(&iter);


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
		sediff_find_window_reset_idx(sediff_app->find_window);
		widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_sort_menu");
		g_assert(widget);
		gtk_widget_set_sensitive(widget, FALSE);

		switch (option) {
		case OPT_SUMMARY:
			if (sediff_app->svd != NULL) {
				sediff_txt_buffer_insert_summary_results(sediff_app->main_buffer);
			}
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);
			break;
		case OPT_CLASSES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_CLASSES);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_CLASSES_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer, 
					    string, sediff_app->svd->classes, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);						
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_CLASSES_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer, 
					    string, sediff_app->svd->classes, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_REM);						
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_CLASSES_CHG:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer, 
					    string, sediff_app->svd->classes, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_PERMISSIONS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_PERMISSIONS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_PERMISSIONS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_perms_results(sediff_app->main_buffer, 
					    string, sediff_app->svd->perms, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_PERMISSIONS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_perms_results(sediff_app->main_buffer,
					    string, sediff_app->svd->perms, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);			
			break;
		case OPT_COMMON_PERMS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_COMMON_PERMS);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);			
			break;
		case OPT_COMMON_PERMS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer, 
							    string, sediff_app->svd->common_perms, 
							    sediff_app->svd->diff->p1, 
							    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_COMMON_PERMS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer, 
							    string, sediff_app->svd->common_perms, 
							    sediff_app->svd->diff->p1, 
							    sediff_app->svd->diff->p2, AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_COMMON_PERMS_CHG:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer, 
							    string, sediff_app->svd->common_perms, 
							    sediff_app->svd->diff->p1, 
							    sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_TYPES:			
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_TYPES);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);			
			break;
		case OPT_TYPES_ADD:			
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->types, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_TYPES_REM:			
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->types, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2,AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_TYPES_CHG:			
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->types, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_ROLES);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);			
			break;
		case OPT_ROLES_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->roles, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLES_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->roles, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLES_CHG:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->roles, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLES_CHG_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->roles, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLES_CHG_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->roles, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_REM_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_USERS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_USERS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_USERS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->users, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_USERS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->users, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_USERS_CHG:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->users, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ATTRIBUTES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			gtk_text_buffer_get_start_iter(sediff_app->main_buffer,&end);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_ATTRIBUTES);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ATTRIBUTES_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ATTRIBUTES_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ATTRIBUTES_CHG:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ATTRIBUTES_CHG_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ATTRIBUTES_CHG_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_iad_results(sediff_app->main_buffer,
					    string, sediff_app->svd->attribs, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_REM_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_BOOLEANS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_BOOLEANS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_BOOLEANS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_boolean_results(sediff_app->main_buffer,
					      string, sediff_app->svd->bools,sediff_app->svd->diff->p1,
					      sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_BOOLEANS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_boolean_results(sediff_app->main_buffer,
					      string, sediff_app->svd->bools,sediff_app->svd->diff->p1,
					      sediff_app->svd->diff->p2, AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_BOOLEANS_CHG:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_boolean_results(sediff_app->main_buffer,
					      string, sediff_app->svd->bools,sediff_app->svd->diff->p1,
					      sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_ALLOWS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_ROLE_ALLOWS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_ALLOWS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_rallow_results(sediff_app->main_buffer,
					    string, sediff_app->svd->rallows, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_ALLOWS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_rallow_results(sediff_app->main_buffer,
					    string, sediff_app->svd->rallows, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_ALLOWS_CHG:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			rt = sediff_txt_buffer_insert_rallow_results(sediff_app->main_buffer,
					    string, sediff_app->svd->rallows, 
					    sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_TRANS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer,OPT_ROLE_TRANS);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_TRANS_ADD:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer, 
							 string, sediff_app->svd->rtrans, 
							 sediff_app->svd->diff->p1, 
							 sediff_app->svd->diff->p2, AP_SVD_OPT_ADD);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_TRANS_ADD_TYPE:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans, 
							 sediff_app->svd->diff->p1, 
							 sediff_app->svd->diff->p2, AP_SVD_OPT_ADD_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_TRANS_REM:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans, 
							 sediff_app->svd->diff->p1, 
							 sediff_app->svd->diff->p2, AP_SVD_OPT_REM);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_TRANS_REM_TYPE:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans, 
							 sediff_app->svd->diff->p1, 
							 sediff_app->svd->diff->p2, AP_SVD_OPT_REM_TYPE);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_ROLE_TRANS_CHG:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_rtrans_results(sediff_app->main_buffer,
							 string, sediff_app->svd->rtrans, 
							 sediff_app->svd->diff->p1, 
							 sediff_app->svd->diff->p2, AP_SVD_OPT_CHG);
			gtk_text_view_set_buffer(textview,sediff_app->main_buffer);			
			break;
		case OPT_CONDITIONALS:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_CONDITIONALS);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);
			break;
		case OPT_CONDITIONALS_ADD:
			if (sediff_app->cond_add_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_CONDITIONALS_ADD, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->cond_add_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->cond_add_buffer);
			break;
		case OPT_CONDITIONALS_REM:
			if (sediff_app->cond_rem_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_CONDITIONALS_REM, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->cond_rem_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->cond_rem_buffer);
			break;
		case OPT_CONDITIONALS_CHG:
			if (sediff_app->cond_chg_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_CONDITIONALS_CHG, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->cond_chg_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->cond_chg_buffer);
			break;
		case OPT_TE_RULES:
			sediff_clear_text_buffer(sediff_app->main_buffer);
			sediff_txt_buffer_insert_summary(sediff_app->main_buffer, OPT_TE_RULES);
			gtk_text_view_set_buffer(textview, sediff_app->main_buffer);
			break;
		case OPT_TE_RULES_ADD:
			if (sediff_app->te_add_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_ADD, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_add_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_add_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		case OPT_TE_RULES_REM:
			if (sediff_app->te_rem_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_REM, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_rem_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_rem_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		case OPT_TE_RULES_CHG:
			if (sediff_app->te_chg_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_CHG, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_chg_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_chg_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		case OPT_TE_RULES_ADD_TYPE:
			if (sediff_app->te_add_type_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_ADD_TYPE, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_add_type_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_add_type_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		case OPT_TE_RULES_REM_TYPE:
			if (sediff_app->te_rem_type_buffer == NULL)
				sediff_lazy_load_large_buffer(OPT_TE_RULES_REM_TYPE, TRUE);
			table = gtk_text_buffer_get_tag_table(sediff_app->te_rem_type_buffer);
			link1_tag = gtk_text_tag_table_lookup(table, "policy1-link-tag");
			link2_tag = gtk_text_tag_table_lookup(table, "policy2-link-tag");
			/* the tags will not exist if the policies are binary */
			if (link1_tag) {
				g_signal_connect_after(G_OBJECT(link1_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link1_tag), "page", GINT_TO_POINTER (1));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link1_tag);
			}
			if (link2_tag) {
				g_signal_connect_after(G_OBJECT(link2_tag), "event", GTK_SIGNAL_FUNC(txt_view_on_policy_link_event), 
						       textview);
				g_object_set_data (G_OBJECT (link2_tag), "page", GINT_TO_POINTER (2));
				glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
							      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), link2_tag);
			}
			gtk_text_view_set_buffer(textview,sediff_app->te_rem_type_buffer);
			gtk_widget_set_sensitive(widget, TRUE);
			break;
		default:
			fprintf(stderr, "Invalid list item %d!", option);
			break;
		};

		/* go back to our previous location if we had one 
		   must use marks to ensure that we go to this position even if
		   it hasn't been drawn
		 */
		txt = gtk_text_view_get_buffer(textview);
		gtk_text_buffer_get_start_iter(txt, &iter);
		gtk_text_iter_set_offset(&iter, sediff_app->tv_buf_offsets[option]);
		mark = gtk_text_buffer_create_mark(txt, "location-mark", &iter, FALSE);
		gtk_text_view_scroll_to_mark(textview, mark, 0.0, TRUE, 0.0, 0.0);			
		gtk_text_buffer_delete_mark(txt, mark);
		sediff_app->tv_curr_buf = option;
	}
}

/* 
 *  returns true when user clicks line number we are able to get it, and 
 *  raise the correct tab 
 */
static gboolean txt_view_on_cond_link_event(GtkTextTag *tag, GObject *event_object, 
					      GdkEvent *event, const GtkTextIter *iter, 
					      gpointer user_data)
{
	GtkTextBuffer *buffer = NULL;
	GtkTextIter start, end;
	gchar *my_str = NULL;
	GtkTextView *textview = GTK_TEXT_VIEW(user_data);
	GtkTextMark *mark = NULL;
	GtkTreeModel *tree_model;
	GtkTreeIter tree_iter;
	GtkTreeIter tree_iter_next;
	GtkTreeSelection *sel;
	GtkTreePath *parent = NULL,*child = NULL;
	GString *string;
	int opt,rt;
	
	if (textview == NULL)
		return FALSE;

	if (event->type == GDK_BUTTON_PRESS) {

		/* get the id to find the mark */
		my_str = (char *)g_object_get_data (G_OBJECT (tag), "id");	      
		if (my_str == NULL) {
			return FALSE;
		}

		/* switch the textview to show the cond buffer */
		sediff_modal_dlg_show("Searching...", "Searching text - this may take a while.");
		if (sediff_app->cond_add_buffer == NULL) 
			sediff_lazy_load_large_buffer(OPT_CONDITIONALS_ADD, FALSE);
		if ((mark = gtk_text_buffer_get_mark(sediff_app->cond_add_buffer, my_str)) != NULL) {
			opt = OPT_CONDITIONALS_ADD;
			buffer = sediff_app->cond_add_buffer;
			goto got_mark;
		}
		if (sediff_app->cond_rem_buffer == NULL)
			sediff_lazy_load_large_buffer(OPT_CONDITIONALS_REM, FALSE);
		if ((mark = gtk_text_buffer_get_mark(sediff_app->cond_rem_buffer,my_str)) != NULL) {
			opt = OPT_CONDITIONALS_REM;
			buffer = sediff_app->cond_rem_buffer;
			goto got_mark;
		} 
		if (sediff_app->cond_chg_buffer == NULL) 
			sediff_lazy_load_large_buffer(OPT_CONDITIONALS_CHG, FALSE);
		if ((mark = gtk_text_buffer_get_mark(sediff_app->cond_chg_buffer, my_str)) != NULL) {
			opt = OPT_CONDITIONALS_CHG;
			buffer = sediff_app->cond_chg_buffer;
			goto got_mark;
		}
		/* we didn't find the mark */
		sediff_modal_dlg_destroy();
		string = g_string_new("Error finding mark.");
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, string->str);
		g_string_free(string, TRUE);
		return FALSE;

	got_mark:
		sediff_modal_dlg_destroy();
		sediff_results_txt_view_switch_buffer(textview,opt,1);
		/* select the last element in the tree */
		tree_model = gtk_tree_view_get_model(GTK_TREE_VIEW(sediff_app->tree_view));		
		sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(sediff_app->tree_view));
		
		/* get the iterators */
		rt = sediff_get_model_option_iter(tree_model,&tree_iter,&tree_iter_next,opt);
		if (rt < 0)
			return FALSE;
		parent = gtk_tree_model_get_path(tree_model,&tree_iter);		
		child = gtk_tree_model_get_path(tree_model,&tree_iter_next);
		/* if these iterators are equal then there is no child */
		if (gtk_tree_path_compare(parent,child) == 0)
			gtk_tree_selection_select_iter(sel,&tree_iter);			
		/* otherwise there is a child, we need to expand parent 
		 then selec the child*/
		else {
			gtk_tree_view_expand_row(GTK_TREE_VIEW(sediff_app->tree_view),
						 parent,FALSE);
			gtk_tree_selection_select_path(sel,child);			
		}    


		/* set the iterators to our mark which is right after the newline
		   char  of the conditional */
		gtk_text_buffer_get_iter_at_mark(buffer,&end,mark);
		gtk_text_buffer_get_iter_at_mark(buffer,&start,mark);

		/* move the end iterator to the end of the cond expr */
		while (!gtk_text_iter_ends_sentence(&end))	
			gtk_text_iter_backward_char(&end);
		
		/* move the start iter to the start of the line */
		gtk_text_iter_backward_char(&start);
		while (!gtk_text_iter_starts_line(&start))	
			gtk_text_iter_backward_char(&start);

		/* set the viewable part to be the conditional */
		/* have to scroll to mark to avoid issues with drawing */
		gtk_text_view_scroll_to_mark(textview, mark, 0.0, TRUE, 0.0, 0.5);			
		gtk_text_view_set_cursor_visible(textview, TRUE);
		gtk_text_buffer_place_cursor(buffer, &start);
		/* highlight */
		gtk_text_buffer_select_range(buffer,&start,&end);
		
		return TRUE;
	}

	return FALSE;
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
	gtk_text_buffer_get_end_iter(txt, &iter);

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

	g_string_printf(string," Added(+):\n  Items added\n  in policy 2.\n\n");
	gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "added-tag", NULL);
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
	g_string_printf(string,"Classes %d Perms: %d "
			"Commons %d Types: %d Attribs: %d Roles: %d Users: %d Bools: %d "
			"TE Rules: %d Role Allows: %d Role Trans: %d Conds: %d",
			(sediff_app->svd->classes->num_add + sediff_app->svd->classes->num_rem + sediff_app->svd->classes->num_chg),
			(sediff_app->svd->perms->num_add + sediff_app->svd->perms->num_rem),		
			(sediff_app->svd->common_perms->num_add + sediff_app->svd->common_perms->num_rem + sediff_app->svd->common_perms->num_chg),
			(sediff_app->svd->types->num_add + sediff_app->svd->types->num_rem + sediff_app->svd->types->num_chg),
			(sediff_app->svd->attribs->num_add + sediff_app->svd->attribs->num_rem + sediff_app->svd->attribs->num_chg +
				sediff_app->svd->attribs->num_chg_add + sediff_app->svd->attribs->num_chg_rem),
			(sediff_app->svd->roles->num_add + sediff_app->svd->roles->num_rem + sediff_app->svd->roles->num_chg +
				sediff_app->svd->attribs->num_chg_add + sediff_app->svd->attribs->num_chg_rem),
			(sediff_app->svd->users->num_add + sediff_app->svd->users->num_rem + sediff_app->svd->users->num_chg),
			(sediff_app->svd->bools->num_add + sediff_app->svd->bools->num_rem + sediff_app->svd->bools->num_chg),
			(sediff_app->svd->rallows->num_add + sediff_app->svd->rallows->num_rem + sediff_app->svd->rallows->num_chg),
			(sediff_app->svd->rtrans->num_add + sediff_app->svd->rtrans->num_rem + sediff_app->svd->rtrans->num_chg +
				sediff_app->svd->rtrans->num_add_type + sediff_app->svd->rtrans->num_rem_type),
			(sediff_app->svd->te->num_add + sediff_app->svd->te->num_rem + sediff_app->svd->te->num_chg +
				sediff_app->svd->te->num_add_type + sediff_app->svd->te->num_rem_type),
			(sediff_app->svd->conds->num_add + sediff_app->svd->conds->num_rem + sediff_app->svd->conds->num_chg));

	gtk_label_set_text(statusbar, string->str);
	g_string_free(string, TRUE);
}




/* this function given a policy #(1 or 2),the idx of the conditional in that
   policy , and whether this is an add/rem/chg,
   will create a hyperlinked tag with the id "cond-link-policynum-idx", will
   associate that id to the tag, and will connect that tag to a callback fcn in the
   main textview. That will link us to the mark with the matching id in conditionals */
static GtkTextTag *txt_buffer_create_cond_tag(GtkTextBuffer *txt,int policy_num,int idx)
{
	GtkTextTag *tag = NULL;
	GtkTextTagTable *table = NULL;
	GString *string = g_string_new("");
	GtkTextView *textview = NULL;

	table = gtk_text_buffer_get_tag_table(txt);
	if (table == NULL)
		return NULL;

	g_string_printf(string,"cond-link-%d-%d",policy_num,idx);
	tag = gtk_text_tag_table_lookup(table, string->str);

	if (!tag) {
		tag = gtk_text_buffer_create_tag(txt, string->str,
						 "family", "monospace",
						 "foreground", "blue", 
						 "underline", PANGO_UNDERLINE_SINGLE, NULL);
		g_object_set_data (G_OBJECT (tag), "id", string->str);		
		g_object_set_data (G_OBJECT (tag), "page", GINT_TO_POINTER (1));
		/* grab the text buffers for our text views */
		textview = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_results_txt_view"));
		g_assert(textview);
		g_signal_connect_after(G_OBJECT(tag), "event", GTK_SIGNAL_FUNC(txt_view_on_cond_link_event), 
				       textview);
		glade_xml_signal_connect_data(sediff_app->window_xml, "txt_view_on_text_view_motion", 
					      GTK_SIGNAL_FUNC(txt_view_on_text_view_motion), tag);


	}
	g_string_free(string,FALSE);
	return tag;
}

/* insert a full te rule line, with colors, and spacing */
static int sediff_txt_buffer_insert_te_line(GtkTextBuffer *txt, avh_node_t *cur, policy_t *policy, GtkTextTag *colortag, 
					    GtkTextTag *linktag, GtkTextTag *pangotag, const char *str, bool_t show_conds, int policy_num)
{
	char *fulltab = sediff_get_tab_spaces(TABSIZE);
	char *condtab = sediff_get_tab_spaces(TABSIZE-2);
	char *rule = NULL;
	gchar **split_line_array = NULL;
	int j;
	GtkTextTag *cond_tag;
	GtkTextIter iter;
	GString *string;

	string = g_string_new("");
	/* are there conditionals */
	if (show_conds && cur->flags & AVH_FLAG_COND) {
		rule = re_render_avh_rule_cond_state(cur,policy);
		g_string_printf(string,"%s%s",rule,condtab);
		free(rule);
	}
	/* in this case we are hiding conds(so we're printing in conditionals we need to double tab these */
	else if (!show_conds && cur->flags & AVH_FLAG_COND) {
		g_string_printf(string,"%s%s",fulltab,fulltab);
	}
	else
		g_string_printf(string,"%s",fulltab);
	gtk_text_buffer_get_end_iter(txt, &iter);
	gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, pangotag, NULL);  

	
	/* print the rule */
	rule = re_render_avh_rule(cur, policy); 
	if (rule == NULL) { 
		g_return_val_if_reached(-1); 
	} 
	g_string_printf(string, "%s%s", str, rule); 
	gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, colortag, NULL);  
	
	free(rule); 
	
	
	/* get the line # */
	rule = re_render_avh_rule_linenos(cur, policy); 
	if (rule != NULL) { 
		j = 0; 
		split_line_array = g_strsplit((const gchar*)rule, " ", 0);   
		while (split_line_array[j] != NULL) {   
			gtk_text_buffer_insert_with_tags(txt, &iter, "(", -1, pangotag, NULL); 
			g_string_printf(string, "%s", split_line_array[j]); 
			if (!is_binary_policy(policy)) { 
				gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, linktag, NULL); 
			} 
			gtk_text_buffer_insert_with_tags(txt, &iter, ")", -1, pangotag, NULL); 
			j++; 
		} 
		free(rule); 
		g_strfreev(split_line_array); 
	} 		
	/* get the conditional expression */
	if (show_conds && cur->flags & AVH_FLAG_COND) {
		rule = re_render_avh_rule_cond_expr(cur,policy);
		cond_tag = txt_buffer_create_cond_tag(txt,policy_num,cur->cond_expr);
		gtk_text_buffer_insert_with_tags(txt, &iter, rule, -1, cond_tag, NULL); 		
		free(rule);
	}
       	gtk_text_buffer_insert(txt, &iter, "\n", -1); 
	g_string_free(string, TRUE);
	return 0;
}

static int sediff_txt_buffer_insert_te_results(GtkTextBuffer *txt, ap_single_te_diff_t *sted, policy_t *policy1, policy_t *policy2,
					       int opts, bool_t showheader)
{
	int i, j;
	avh_node_t *diffcur1;
	avh_node_t *diffcur2;
	char cond_on[TABSIZE+1];
	char cond_off[TABSIZE+1];
	char cond_none[TABSIZE+1];
	char *fulltab = sediff_get_tab_spaces(TABSIZE);
	char *condtab = sediff_get_tab_spaces(TABSIZE-2);
	GtkTextTag *link1_tag, *link2_tag, *rules_tag, *added_tag, *changed_tag, *removed_tag, *header_tag;
	GtkTextTagTable *table;
	char *name = NULL;
	GString *string;
	GtkTextIter iter;

	snprintf(cond_on,TABSIZE,"D:\t");
	snprintf(cond_off,TABSIZE,"E:\t");
	snprintf(cond_none,TABSIZE,"\t");
	cond_on[TABSIZE] = '\0';
	cond_off[TABSIZE] = '\0';
	cond_none[TABSIZE] = '\0';

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
	
	if (showheader == TRUE) {
		string = g_string_new("");
		g_string_printf(string, "TE Rules (%d Added, %d Added New Type, %d Removed, %d Removed Missing Type,"
				" %d Changed)\n",sted->num_add,sted->num_add_type,sted->num_rem,sted->num_rem_type,sted->num_chg);
		sediff_add_hdr(txt, string);
		g_string_free(string, TRUE);
	}

	/* are we printing adds */
	if (opts & AP_SVD_OPT_ADD) {
		string = g_string_new("");
		g_string_printf(string, "\n%s%sTE RULES ADDED: %d\n",showheader ? "" : fulltab,
				showheader ? "" : fulltab, sted->num_add);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "header-tag", NULL); 
		g_string_free(string, TRUE);
		for (i = 0; i < sted->num_add; i++) {
			sediff_txt_buffer_insert_te_line(txt, sted->add[i], policy2, added_tag,
							 link2_tag, rules_tag, "+ ", showheader, 2);
		}
	}
	/* are we printing adds that have new types */
	if (opts & AP_SVD_OPT_ADD_TYPE) {
		string = g_string_new("");
		g_string_printf(string, "\n%s%sTE RULES ADDED NEW TYPE: %d\n",showheader ? "" : fulltab,
				showheader ? "" : fulltab, sted->num_add_type);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "header-tag", NULL); 
		g_string_free(string, TRUE);
		for (i = 0; i < sted->num_add_type; i++) {
			sediff_txt_buffer_insert_te_line(txt, sted->add_type[i], policy2, added_tag,
							 link2_tag, rules_tag, "+ ", showheader, 2);
		}
	}
	/* removes */
	if (opts & AP_SVD_OPT_REM) {
		string = g_string_new("");
		g_string_printf(string, "\n%s%sTE RULES REMOVED: %d\n",showheader ? "" : fulltab,
				showheader ? "" : fulltab,sted->num_rem);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,-1, "header-tag", NULL); 
		g_string_free(string, TRUE);
		for (i = 0; i < sted->num_rem; i++) {
			sediff_txt_buffer_insert_te_line(txt, sted->rem[i], policy1, removed_tag, 
							 link1_tag, rules_tag, "- ", showheader, 1);
		}
	}
	/* removes that have a missing type */
	if (opts & AP_SVD_OPT_REM_TYPE) {
		string = g_string_new("");
		g_string_printf(string, "\n%s%sTE RULES REMOVED MISSING TYPE: %d\n",showheader ? "" : fulltab,
				showheader ? "" : fulltab,sted->num_rem_type);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,-1, "header-tag", NULL); 
		g_string_free(string, TRUE);
		for (i = 0; i < sted->num_rem_type; i++) {
			sediff_txt_buffer_insert_te_line(txt, sted->rem_type[i], policy1, removed_tag,
							 link1_tag, rules_tag, "- ", showheader,1);
		}
	}
	/* changes */
	if (opts & AP_SVD_OPT_CHG) {
		string = g_string_new("");
		g_string_printf(string, "\n%s%sTE RULES CHANGED: %d\n",showheader ? "" : fulltab,
				showheader ? "" : fulltab,sted->num_chg);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,-1, "header-tag", NULL); 
		g_string_free(string, TRUE);
		for (i = 0; i < sted->num_chg; i++) {
			sediff_txt_buffer_insert_te_line(txt, sted->chg[i].rem, policy1, changed_tag,
							 link1_tag, rules_tag, "Policy 1: ", showheader,1);
			sediff_txt_buffer_insert_te_line(txt, sted->chg[i].add, policy2, changed_tag,
							 link2_tag, rules_tag, "Policy 2: ", showheader,1);
			/* now print the diffs */
			diffcur1 = sted->chg[i].rem_diff;
			diffcur2 = sted->chg[i].add_diff;
			if (diffcur1 != NULL) {
				if (diffcur1->key.rule_type <= RULE_MAX_AV) {
					for (j = 0 ; j < diffcur1->num_data; j++) {
						if (get_perm_name(diffcur1->data[j],&name,policy1) == 0) {
							string = g_string_new("");
							g_string_printf(string,"%s%s%s- %s\n",showheader ? "" : fulltab,fulltab,fulltab,name);
							gtk_text_buffer_get_end_iter(txt, &iter);
							gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1,removed_tag, NULL);
							g_string_free(string, TRUE);
							free(name);
						} else
							goto insert_te_results_error;
					}
				} else {
					if (diffcur1->num_data == 1) {
						if (get_type_name(diffcur1->data[0],&name,policy1) == 0) {
							string = g_string_new("");
							g_string_printf(string,"%s%s%s- %s\n",showheader ? "" : fulltab,fulltab,fulltab,name);
							gtk_text_buffer_get_end_iter(txt, &iter);
							gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1,removed_tag, NULL);
							g_string_free(string, TRUE);
							free(name);
						} else
							goto insert_te_results_error;
					}
				}
			} 
			if (diffcur2) {
				if (diffcur2->key.rule_type <= RULE_MAX_AV) {
					for (j = 0 ; j < diffcur2->num_data; j++) {
						if (get_perm_name(diffcur2->data[j],&name,policy2) == 0) {
							string = g_string_new("");
							g_string_printf(string,"%s%s%s+ %s\n",showheader ? "" : fulltab,fulltab,fulltab,name);
							gtk_text_buffer_get_end_iter(txt, &iter);
							gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "added-tag", NULL);
							g_string_free(string, TRUE);
							free(name);
						} else
							goto insert_te_results_error;
					}
					
				} else {
					if (diffcur2->num_data == 1) {
						if (get_type_name(diffcur2->data[0],&name,policy2) == 0) {
							string = g_string_new("");
							g_string_printf(string,"%s%s%s+ %s\n",showheader ? "" : fulltab,fulltab,fulltab,name);
							gtk_text_buffer_get_end_iter(txt, &iter);
							gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "added-tag", NULL);
							g_string_free(string, TRUE);
							free(name);
						} else
							goto insert_te_results_error;
					}
				}
			}
		}
	}
	if (fulltab)
		free(fulltab);
	if (condtab)		
		free(condtab);
	return 0;

 insert_te_results_error:
	if (fulltab)
		free(fulltab);
	if (condtab)		
		free(condtab);
	return -1;
}



static GtkTextMark *sediff_txt_buffer_insert_cond_mark(GtkTextBuffer *txt, GString *string, int policy, 
						       int idx, bool_t goes_left)
{
	GtkTextMark *mark = NULL;
	GtkTextIter iter;

	if (!txt || !string)
		return NULL;

	g_string_printf(string, "cond-link-%d-%d", policy, idx);
	mark = gtk_text_buffer_get_mark(txt, string->str);
	if (!mark) {
		gtk_text_buffer_get_end_iter(txt, &iter);
		mark = gtk_text_buffer_create_mark(txt, string->str, &iter, goes_left);	
	}
	return mark;
}

static int sediff_txt_buffer_insert_cond_results(GtkTextBuffer *txt, ap_single_cond_diff_t *scd,
						 policy_t *policy_old, policy_t *policy_new,int opts)
{
	GtkTextTag *added_tag, *removed_tag, *changed_tag;
	GtkTextTag *header_added_tag,*header_removed_tag,*header_changed_tag,*header_tag;		
	GtkTextTagTable *table;
	int i;
	char *rule = NULL;
	GtkTextIter iter;
	GString *string;

	sediff_clear_text_buffer(txt);
	string = g_string_new("");
	
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
	g_string_printf(string, "Conditionals (%d Added, %d Removed, %d Changed)\n",scd->num_add,scd->num_rem,
			scd->num_chg);
	sediff_add_hdr(txt, string);

	if (opts & AP_SVD_OPT_ADD) {
		/* print the header */
		g_string_printf(string, "\nCONDITIONALS ADDED: %d\n",scd->num_add);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,-1, "header-tag", NULL); 
		for (i = 0;i < scd->num_add;i++) {
			/* print the conditional */
			rule = re_render_cond_expr(scd->add[i].idx,policy_new);
			g_string_printf(string,"+%s\n",rule);
			free(rule);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags(txt, &iter, string->str, 
							 -1, added_tag, NULL);
			sediff_txt_buffer_insert_cond_mark(txt, string, 2, scd->add[i].idx, TRUE);
			g_string_printf(string,"    TRUE list:\n");	
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "added-tag", NULL);
			
			sediff_txt_buffer_insert_te_results(txt, scd->add[i].true_list, policy_old, policy_new, 
							    AP_SVD_OPT_ALL, FALSE);
			g_string_printf(string,"    FALSE list:\n");	
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "added-tag", NULL);
			
			sediff_txt_buffer_insert_te_results(txt, scd->add[i].false_list, policy_old, policy_new, 
							    AP_SVD_OPT_ALL, FALSE);
		}
	}
	if (opts & AP_SVD_OPT_REM) {
		g_string_printf(string, "\nCONDITIONALS REMOVED: %d\n",scd->num_rem);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,-1, "header-tag", NULL); 
		for (i = 0;i < scd->num_rem;i++) {
			/* print the conditional */
			rule = re_render_cond_expr(scd->rem[i].idx, policy_old);
			g_string_printf(string, "-%s\n", rule);
			free(rule);

			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags(txt, &iter, string->str, -1, removed_tag, NULL);
			sediff_txt_buffer_insert_cond_mark(txt, string, 1, scd->rem[i].idx, TRUE);

			g_string_printf(string,"    TRUE list:\n");	    		
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "removed-tag", NULL);
			sediff_txt_buffer_insert_te_results(txt, scd->rem[i].true_list, policy_old, policy_new,
							    AP_SVD_OPT_ALL, FALSE);
			g_string_printf(string, "    FALSE list:\n");	
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "removed-tag", NULL);
			sediff_txt_buffer_insert_te_results(txt, scd->rem[i].false_list, policy_old, policy_new,
							    AP_SVD_OPT_ALL, FALSE);	
		}
	}
	if (opts & AP_SVD_OPT_CHG) {
		g_string_printf(string, "\nCONDITIONALS CHANGED: %d\n",scd->num_chg);
		gtk_text_buffer_get_end_iter(txt, &iter);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str,-1, "header-tag", NULL); 
		for (i = 0;i < scd->num_chg;i++) {
			/* print the conditional */
			rule = re_render_cond_expr(scd->chg[i].idx,policy_old);
			g_string_printf(string,"*%s\n",rule);
			free(rule);
			gtk_text_buffer_get_end_iter(txt, &iter);
			gtk_text_buffer_insert_with_tags(txt, &iter, string->str, 
							 -1, changed_tag, NULL);
			sediff_txt_buffer_insert_cond_mark(txt, string, 1, scd->chg[i].idx, TRUE);
			sediff_txt_buffer_insert_cond_mark(txt, string, 2, scd->chg[i].idx2, TRUE);
			g_string_printf(string,"    TRUE list:\n");	
			gtk_text_buffer_get_end_iter(txt, &iter);    				
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "changed-tag", NULL);
			sediff_txt_buffer_insert_te_results(txt, scd->chg[i].true_list, policy_old, policy_new, 
							    AP_SVD_OPT_ALL, FALSE);
			g_string_printf(string,"    FALSE list:\n");	
			gtk_text_buffer_get_end_iter(txt, &iter);    				
			gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, 
								 -1, "changed-tag", NULL);
			sediff_txt_buffer_insert_te_results(txt, scd->chg[i].false_list, policy_old, policy_new, 
							    AP_SVD_OPT_ALL, FALSE);	
		}
	}
	g_string_free(string, TRUE);
	return 0;
}

/*
  clear the text buffers 
*/
static void sediff_free_stored_buffers()
{

	if (sediff_app->main_buffer) {
		g_object_unref (G_OBJECT(sediff_app->main_buffer)); 
		sediff_app->main_buffer = NULL;	
	}
	if (sediff_app->te_add_buffer) {
		g_object_unref (G_OBJECT(sediff_app->te_add_buffer)); 
		sediff_app->te_add_buffer = NULL;
	}
	if (sediff_app->te_rem_buffer) {
		g_object_unref (G_OBJECT(sediff_app->te_rem_buffer)); 
		sediff_app->te_rem_buffer = NULL;
	}
	if (sediff_app->te_chg_buffer) {
		g_object_unref (G_OBJECT(sediff_app->te_chg_buffer)); 
		sediff_app->te_chg_buffer = NULL;
	}
	if (sediff_app->te_add_type_buffer) {
		g_object_unref (G_OBJECT(sediff_app->te_add_type_buffer)); 	
		sediff_app->te_add_type_buffer = NULL;
	}
	if (sediff_app->te_rem_type_buffer) {
		g_object_unref (G_OBJECT(sediff_app->te_rem_type_buffer));
		sediff_app->te_rem_type_buffer = NULL;	
	}
	if (sediff_app->cond_add_buffer) {
		g_object_unref (G_OBJECT(sediff_app->cond_add_buffer)); 
		sediff_app->cond_add_buffer = NULL;
	}
	if (sediff_app->cond_rem_buffer) {
		g_object_unref (G_OBJECT(sediff_app->cond_rem_buffer)); 
		sediff_app->cond_rem_buffer = NULL;
	}
	if (sediff_app->cond_chg_buffer) {
		g_object_unref (G_OBJECT(sediff_app->cond_chg_buffer)); 
		sediff_app->cond_chg_buffer = NULL; 
	}
}

/* 
   callback used to switch our text view based on
   user input from the treeview
*/
static gboolean sediff_results_txt_view_switch_results(gpointer data)
{

	GtkTextView *textview1;
	gint option;

	option = sediff_get_current_treeview_selected_row(GTK_TREE_VIEW(sediff_app->tree_view));
	/* grab the text buffers for our text views */
	textview1 = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_results_txt_view"));
	g_assert(textview1);

	/* check to make sure the svd is valid */
	g_return_val_if_fail(sediff_app->svd != NULL, FALSE);
	
	/* Configure text_view */
	gtk_text_view_set_editable(GTK_TEXT_VIEW (textview1), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview1), FALSE);

	sediff_results_txt_view_switch_buffer(textview1,option,1);

       	return FALSE;
}


static void sediff_treeview_on_row_double_clicked(GtkTreeView *tree_view, 
						  GtkTreePath *path, 
						  GtkTreeViewColumn *col, 
						  gpointer user_data)
{
	/* Finish later */

	g_idle_add_full(G_PRIORITY_HIGH_IDLE, &sediff_results_txt_view_switch_results, NULL, NULL);	
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
		g_idle_add_full(G_PRIORITY_HIGH_IDLE, &sediff_results_txt_view_switch_results, NULL, NULL);
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

	if (sediff_app == NULL)
		return;
	
	if (sediff_app->dummy_view && gtk_widget_get_parent(GTK_WIDGET(sediff_app->dummy_view)) == NULL)
		gtk_widget_unref(sediff_app->dummy_view);
	if (sediff_app->tree_view != NULL) 
		gtk_widget_destroy(GTK_WIDGET(sediff_app->tree_view));
	if (sediff_app->window != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->window));
	if (sediff_app->open_dlg != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->open_dlg));
	if (sediff_app->modal_dlg != NULL)
		gtk_widget_destroy(GTK_WIDGET(sediff_app->modal_dlg));
	if (sediff_app->window_xml != NULL)
		g_object_unref(G_OBJECT(sediff_app->window_xml));
	if (sediff_app->open_dlg_xml != NULL)
		g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	if (sediff_app->p1_sfd.name) 
		g_string_free(sediff_app->p1_sfd.name, TRUE);
	if (sediff_app->p2_sfd.name) 
		g_string_free(sediff_app->p2_sfd.name, TRUE);
	if (sediff_app->p1_sfd.data)
		munmap(sediff_app->p1_sfd.data, sediff_app->p1_sfd.size);
	if (sediff_app->p2_sfd.data)
		munmap(sediff_app->p2_sfd.data, sediff_app->p2_sfd.size);
	if (sediff_app->rename_types_window) {
		sediff_rename_types_window_unref_members(sediff_app->rename_types_window);
		free(sediff_app->rename_types_window);
	}
	if (sediff_app->svd) {
		ap_single_view_diff_destroy(sediff_app->svd);
		sediff_app->svd = NULL;
	}

	g_list_foreach(sediff_app->callbacks, &sediff_callbacks_free_elem_data, NULL);
	g_list_free(sediff_app->callbacks);

	/* destroy our stored buffers */
	sediff_free_stored_buffers();
	free(sediff_app);
	sediff_app = NULL;
}

static void sediff_exit_app(sediff_app_t *sediff_app)
{
	sediff_destroy(sediff_app);
	gtk_main_quit();
}

static void sediff_main_window_on_destroy(GtkWidget *widget, GdkEvent *event, gpointer user_data) 
{
	sediff_exit_app(sediff_app);	
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

static int sediff_policy_file_textview_populate(sediff_file_data_t *sfd, GtkTextView *textview)
{
        GtkTextBuffer *txt;
	GtkTextIter iter;
	gchar *contents = NULL;
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
	gtk_text_buffer_get_end_iter(txt, &iter);

	/* set some variables up */
	gtk_text_view_set_editable (GTK_TEXT_VIEW (textview), FALSE);
	gtk_text_view_set_cursor_visible (GTK_TEXT_VIEW (textview), TRUE);

	/* if this is not a binary policy */
	if (!fn_is_binpol(sfd->name->str) && sfd->data) {
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, sfd->data, sfd->size, "mono-tag", NULL);
		gtk_text_buffer_set_modified(txt, TRUE);
		g_free(contents);
	} else {
		string = g_string_new("");
		g_string_printf(string,"Policy File %s is a binary policy", sfd->name->str);
		gtk_text_buffer_insert_with_tags_by_name(txt, &iter, string->str, -1, "mono-tag", NULL);
		g_string_free(string,TRUE);
	}

	return 0;
}

/* this function is used to determine whether we allow
   a window click events to happen, if there is nothing in the 
   buffer we don't */
gboolean sediff_textview_button_event(GtkWidget *widget,
			       GdkEventButton *event,
			       gpointer user_data)
{
        GtkTextBuffer *txt = NULL;
        GtkTextView *view = NULL;
        GtkTextIter start,end;

	if ( strcmp("GtkTextView", gtk_type_name(GTK_WIDGET_TYPE( widget ))) == 0 )
		view = GTK_TEXT_VIEW(widget);
	else
		return FALSE;
        if (view == NULL)
                return FALSE;
        txt = gtk_text_view_get_buffer(view);

	/* check to see if there is anything currently in this buffer that can be selected */
	gtk_text_buffer_get_start_iter(txt,&start);
	gtk_text_buffer_get_end_iter(txt,&end);
	if (gtk_text_iter_get_offset(&start) == gtk_text_iter_get_offset(&end)) {
		return TRUE;
	} else {
		return FALSE;
	}

	return TRUE;
}
/* this function resets the treemodel, recreates our stored buffers
   (this is faster than clearing them), clears out the keys, and results
   textviews, resets the indexes into diff buffers, and resets the diff pointer itself */
static void sediff_initialize_diff()
{
	GtkTextView *textview;
	GtkTextBuffer *txt;
	GtkWidget *container = NULL;
	GtkLabel *label = NULL;
	GtkTreeSelection *selection = NULL;
	GtkWidget *widget;
	int i;
	
	if (sediff_app->tree_view) {
		/* unselect the selected items */
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(sediff_app->tree_view));
		gtk_tree_selection_unselect_all(selection);
		/* delete tree_view */
		gtk_widget_destroy(GTK_WIDGET(sediff_app->tree_view));
		sediff_app->tree_view = NULL;
	}

	/*deselect the sort te rules menu item */
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_sort_menu");
	g_assert(widget);
	gtk_widget_set_sensitive(widget, FALSE);
	
	/* get the scrolled window and replace the text_view with a blank dummy view */
	container = glade_xml_get_widget(sediff_app->window_xml, "scrolledwindow_list");
	g_assert(container);
	if (sediff_app->dummy_view == NULL) {
		sediff_app->dummy_view = gtk_text_view_new();
		g_assert(sediff_app->dummy_view);
		gtk_text_view_set_editable(GTK_TEXT_VIEW(sediff_app->dummy_view),FALSE);
		gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(sediff_app->dummy_view),FALSE);
		g_signal_connect(G_OBJECT(sediff_app->dummy_view), "button-press-event", 
				 G_CALLBACK(sediff_textview_button_event), sediff_app);
		gtk_container_add(GTK_CONTAINER(container), sediff_app->dummy_view);
		gtk_widget_show_all(container);				
	} else if (gtk_widget_get_parent(GTK_WIDGET(sediff_app->dummy_view)) == NULL) { 
		/* If the dummy view has been removed, then re-add it to the container */
		gtk_container_add(GTK_CONTAINER(container), sediff_app->dummy_view);
		gtk_widget_show_all(container);			
	}
	
	sediff_free_stored_buffers();
	/* re-create the main buffer */
	if (sediff_app->main_buffer == NULL) 
		sediff_app->main_buffer = gtk_text_buffer_new(NULL);

	textview = GTK_TEXT_VIEW((glade_xml_get_widget(sediff_app->window_xml, "sediff_key_txt_view")));
	g_assert(textview);
	txt = gtk_text_view_get_buffer(textview);
	g_assert(txt);
	sediff_clear_text_buffer(txt);
	
	/* switch to our newly blank main buffer */
	textview = GTK_TEXT_VIEW((glade_xml_get_widget(sediff_app->window_xml, "sediff_results_txt_view")));
	gtk_text_view_set_buffer(textview,sediff_app->main_buffer);

	label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
	gtk_label_set_text(label, "");

	label = (GtkLabel *)(glade_xml_get_widget(sediff_app->window_xml, "label_stats"));
	gtk_label_set_text(label, "");

	for (i = 0; i < OPT_NUM_DIFF_NODES; i++)
		sediff_app->tv_buf_offsets[i] = 0;
	sediff_app->tv_curr_buf = OPT_SUMMARY;

	/* clear out the svd if we need to */
	if (sediff_app->svd != NULL) {
		ap_single_view_diff_destroy(sediff_app->svd);
		sediff_app->svd = NULL;
	}
}


/* 
   diff p1 and p2
   also sets up the buffers used in gui so we can switch faster
   returns -1 on error otherwise 0
*/
static int sediff_diff_policies(policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types)
{
	unsigned int opts = POLOPT_ALL;
	GdkCursor *cursor = NULL;
	GString *string = g_string_new("");
	GtkWidget *container = NULL;
	GtkTreeModel *tree_model;
	GtkTreeSelection *sel;
	GtkTreeIter iter;
	GtkNotebook *notebook1, *notebook2;
	GtkTextView *textview;
	
	if (p1 == NULL || p2 == NULL)
		goto err;

	/* show our loading dialog */
	sediff_modal_dlg_show("Calculating", "Calculating difference - this may take a while");

	sediff_initialize_diff();
	/* set the cursor to a hourglass */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();

	/* make sure we clear everything out before we run the diff */
	while (gtk_events_pending ())
		gtk_main_iteration ();

	/* create a new svd */
	sediff_app->svd = ap_single_view_diff_new(opts, p1, p2, renamed_types);
	if (sediff_app->svd == NULL) {
		g_string_printf(string,"Error creating single view difference");
		message_display(sediff_app->window,GTK_MESSAGE_ERROR,string->str);
		goto err;
	}
	
	/* load up the status bar */
	sediff_update_status_bar();

	/* populate the key */
	sediff_populate_key_buffer();

	/* get the scrolled window we are going to put the tree_store in */
	container = glade_xml_get_widget(sediff_app->window_xml, "scrolledwindow_list");
	g_assert(container);
	if (sediff_app->dummy_view != NULL) {
		/* Add a reference to the dummy view widget before removing it from the container so we can add it later */
		sediff_app->dummy_view = gtk_widget_ref(sediff_app->dummy_view);
		gtk_container_remove(GTK_CONTAINER(container), sediff_app->dummy_view);
	}

	/* create the tree_view */
	sediff_app->tree_view = sediff_create_view_and_model(sediff_app->svd);

	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(sediff_app->tree_view));
        gtk_tree_selection_set_mode(sel,GTK_SELECTION_BROWSE);
	gtk_tree_selection_set_select_function(sel, sediff_treeview_on_row_selected, sediff_app->tree_view, NULL);
	g_signal_connect(G_OBJECT(sediff_app->tree_view), "row-activated", 
			 G_CALLBACK(sediff_treeview_on_row_double_clicked), NULL);
		
	notebook1 = (GtkNotebook *)glade_xml_get_widget(sediff_app->window_xml, "notebook1");
	g_assert(notebook1);
	notebook2 = (GtkNotebook *)glade_xml_get_widget(sediff_app->window_xml, "notebook2");
	g_assert(notebook2);
	
	/* make it viewable */
	gtk_container_add(GTK_CONTAINER(container), sediff_app->tree_view);
	gtk_widget_show_all(container);
	
	/* select the first element in the tree */
	tree_model = gtk_tree_view_get_model(GTK_TREE_VIEW(sediff_app->tree_view));
	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(sediff_app->tree_view));
	if (gtk_tree_model_get_iter_first(tree_model, &iter)) {
		gtk_tree_selection_select_iter(sel, &iter);
	}

	/* grab the text buffers for our text views */
	textview = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_results_txt_view"));
	g_assert(textview);

	/* set the buffer to the summary page */
	sediff_results_txt_view_switch_buffer(textview, OPT_SUMMARY, 1);


	/* get rid of the loading when done */
	sediff_modal_dlg_destroy();

	/* diff is done set cursor back to a ptr */
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	if (sediff_app->window != NULL)
		gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	
	return 0;
err:
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	if (sediff_app->window != NULL)
		gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();
	g_string_free(string,TRUE);
	sediff_modal_dlg_destroy();
	return -1;
}

static void run_diff_clicked()
{
	if (sediff_app->p1_sfd.name && sediff_app->p2_sfd.name) {
		if (sediff_app->rename_types_window)
			sediff_diff_policies(sediff_app->p1, sediff_app->p2, sediff_app->rename_types_window->renamed_types);
		else
			sediff_diff_policies(sediff_app->p1, sediff_app->p2, NULL);
	}
	else
		message_display(sediff_app->window, GTK_MESSAGE_ERROR, "A policy filename is empty! Could not reload.");		
}

/* sort the te rules in the currently displayed buffer */
static void sediff_sort_te_rules(int sort_opt, int direction)
{
	int treeview_row;
	GtkTextIter iter;
	int draw_opt;
	GtkTextBuffer *buffer;

	sediff_modal_dlg_show("Sorting", "Sorting - this may take a while");
	/* get the current row so we know what to sort */
	treeview_row = sediff_get_current_treeview_selected_row(GTK_TREE_VIEW(sediff_app->tree_view));

	/* set up the buffers and the drawing options */
	if (treeview_row == OPT_TE_RULES_ADD) {
		draw_opt = AP_SVD_OPT_ADD;
		buffer = sediff_app->te_add_buffer;
	} else if (treeview_row == OPT_TE_RULES_ADD_TYPE) {
		draw_opt = AP_SVD_OPT_ADD_TYPE;
		buffer = sediff_app->te_add_type_buffer;		
	} else if (treeview_row == OPT_TE_RULES_REM) {
		draw_opt = AP_SVD_OPT_REM;
		buffer = sediff_app->te_rem_buffer;
	} else if (treeview_row == OPT_TE_RULES_REM_TYPE) {
		draw_opt = AP_SVD_OPT_REM_TYPE;
		buffer = sediff_app->te_rem_type_buffer;
	} else if (treeview_row == OPT_TE_RULES_CHG) {
		draw_opt = AP_SVD_OPT_CHG;
		buffer = sediff_app->te_chg_buffer;
	} else {
		assert(FALSE);
		return;
	}

	/* sort the rules */
	ap_single_view_diff_sort_te_rules(sediff_app->svd, sort_opt, draw_opt, direction);
	sediff_clear_text_buffer(buffer);
	gtk_text_buffer_get_start_iter(buffer, &iter);

	/* put the sorted rules into the buffer */
	sediff_txt_buffer_insert_te_results(buffer, sediff_app->svd->te, sediff_app->svd->diff->p1, 
					    sediff_app->svd->diff->p2, draw_opt, TRUE);

	/* get rid of the loading when done */
	sediff_modal_dlg_destroy();
}

void sediff_menu_on_oclass_asc_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_sort_te_rules(AP_OCLASS,1);
}

void sediff_menu_on_oclass_des_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_sort_te_rules(AP_OCLASS,-1);
}

void sediff_menu_on_src_type_asc_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_sort_te_rules(AP_SRC_TYPE,1);
}

void sediff_menu_on_src_type_des_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_sort_te_rules(AP_SRC_TYPE,-1);
}

void sediff_menu_on_tgt_type_asc_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_sort_te_rules(AP_TGT_TYPE,1);
}

void sediff_menu_on_tgt_type_des_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_sort_te_rules(AP_TGT_TYPE,-1);
}

void sediff_menu_on_find_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	if (sediff_app->find_window == NULL)
		sediff_app->find_window = sediff_find_window_new(sediff_app);
	g_assert(sediff_app->find_window);
	sediff_find_window_display(sediff_app->find_window);
}

void sediff_menu_on_edit_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
        GtkTextBuffer *txt = NULL;
        GtkTextView *view = NULL;
        GtkTextIter start,end;
	GtkWidget *widget = NULL;
        if (sediff_app == NULL)
                return;
        view = sediff_get_current_view(sediff_app);
        if (view == NULL)
                return;
        txt = gtk_text_view_get_buffer(view);
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_menu_copy");
	g_assert(widget);

	/* check to see if anything has been selected and set copy button up*/
	if (gtk_text_buffer_get_selection_bounds(txt,&start,&end)) {
		gtk_widget_set_sensitive(widget, TRUE);
	} else {
		gtk_widget_set_sensitive(widget, FALSE);
	}
	widget = glade_xml_get_widget(sediff_app->window_xml, "sediff_select_all");
	g_assert(widget);
	/* check to see if there is anything currently in this buffer that can be selected */
	gtk_text_buffer_get_start_iter(txt,&start);
	gtk_text_buffer_get_end_iter(txt,&end);
	if (gtk_text_iter_get_offset(&start) == gtk_text_iter_get_offset(&end)) {
		gtk_widget_set_sensitive(widget, FALSE);
	} else {
		gtk_widget_set_sensitive(widget, TRUE);
	}
}

void sediff_menu_on_select_all_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkTextBuffer *txt = NULL;
	GtkTextView *view = NULL;
	GtkTextIter start,end;
	if (sediff_app == NULL)
		return;
	view = sediff_get_current_view(sediff_app);
	if (view == NULL)
		return;
	txt = gtk_text_view_get_buffer(view);
	gtk_text_buffer_get_start_iter(txt,&start);
	gtk_text_buffer_get_end_iter(txt,&end);
	gtk_text_buffer_select_range(txt,&start,&end);	
}

void sediff_menu_on_copy_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkClipboard *clipboard = NULL;
	GtkTextBuffer *txt = NULL;
	GtkTextView *view = NULL;
	if (sediff_app == NULL)
		return;
	clipboard = gtk_clipboard_get(NULL);
	if (clipboard == NULL)
		return;
	view = sediff_get_current_view(sediff_app);
	if (view == NULL)
		return;
	txt = gtk_text_view_get_buffer(view);
	if (txt == NULL)
		return;
	gtk_text_buffer_copy_clipboard(txt,clipboard);
}

void sediff_menu_on_rundiff_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	run_diff_clicked();
}

void sediff_toolbar_on_rundiff_button_clicked(GtkButton *button, gpointer user_data)
{
	run_diff_clicked();
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
		filename = get_filename_from_user(sediff_app->open_dlg, "Open Policy", gtk_entry_get_text(entry2));
	else
		filename = get_filename_from_user(sediff_app->open_dlg, "Open Policy", gtk_entry_get_text(entry));
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
		filename = get_filename_from_user(sediff_app->open_dlg, "Open Policy", gtk_entry_get_text(entry1));
	else
		filename = get_filename_from_user(sediff_app->open_dlg, "Open Policy", gtk_entry_get_text(entry));
	if (filename){
		gtk_entry_set_text(entry, filename->str);
	}
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

static void sediff_open_button_clicked()
{
	GtkEntry *entry = NULL;
	char *dir;
	GString *path; 

	if (sediff_app->open_dlg) {
		gtk_window_set_position(sediff_app->open_dlg, GTK_WIN_POS_CENTER_ON_PARENT);
		gtk_window_present(GTK_WINDOW(sediff_app->open_dlg));
	} else {
		
		dir = find_file(GLADEFILE);
		if (!dir){
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

static void sediff_rename_types_window_show()
{
	if (sediff_app->rename_types_window == NULL)
		sediff_app->rename_types_window = sediff_rename_types_window_new(sediff_app);
	g_assert(sediff_app->rename_types_window);
	sediff_rename_types_window_display(sediff_app->rename_types_window);
}

void sediff_menu_on_renametypes_clicked(GtkMenuItem *menuitem, gpointer user_data)
{
	sediff_rename_types_window_show();
}

void sediff_toolbar_on_renametypes_button_clicked(GtkToolButton *button, gpointer user_data)
{
	sediff_rename_types_window_show();
}

void sediff_toolbar_on_open_button_clicked(GtkToolButton *button, gpointer user_data)
{
	sediff_open_button_clicked();
}

void sediff_menu_on_open_clicked(GtkMenuItem *menuitem, gpointer user_data)
{	
	sediff_open_button_clicked();
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
	gtk_window_set_transient_for(GTK_WINDOW(window), sediff_app->window);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER_ON_PARENT);
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


static void sediff_policy_notebook_on_switch_page(GtkNotebook *notebook, GtkNotebookPage *page, guint pagenum, gpointer user_data) 
{
	GtkTextView *txt;
	int main_pagenum;
	GtkNotebook *main_notebook;
	sediff_file_data_t *sfd = NULL;

	/* if we don't have filenames we can't open anything... */
	if (!sediff_app->p1_sfd.name && !sediff_app->p2_sfd.name)
		return;

	/* if we aren't looking at the policy tab of the noteboook return */
	if (pagenum == 0)
		return;

	main_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));
	assert(main_notebook);

	/* here we know pagenum is going to be 1 or 2 */
	main_pagenum = gtk_notebook_get_current_page(main_notebook);

	if (main_pagenum == 1) {
		/* if we are looking at policy 1 */
		txt = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text"));
		g_assert(txt);
		sfd = &(sediff_app->p1_sfd);
	} else {
		/* if we are looking at policy 2 */
		txt = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text"));
		g_assert(txt);
		sfd = &(sediff_app->p2_sfd);
	}

	/* if the buffer has already been modified, i.e. its had the policy put into it
	   just return we have already printed*/
	if (gtk_text_buffer_get_modified(gtk_text_view_get_buffer(txt)) == TRUE) 
		return;

	/* set the modified bit immediately because of gtk is asynchronous
	 and this fcn might be called again before its set in the populate fcn*/
	gtk_text_buffer_set_modified(gtk_text_view_get_buffer(txt), TRUE);

	/* show our loading dialog */
	sediff_modal_dlg_show("Loading...", "Loading text - this may take a while.");

	sediff_policy_file_textview_populate(sfd, txt);	

	sediff_modal_dlg_destroy();

	return;
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
	sediff_find_window_reset_idx(sediff_app->find_window);
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

static void sediff_initialize_policies()
{
	GtkTextView *textview;
	GtkTextBuffer *txt;
	
	if (sediff_app->p1)
		close_policy(sediff_app->p1);
	if (sediff_app->p2)
		close_policy(sediff_app->p2);
	sediff_app->p1 = NULL;
	sediff_app->p2 = NULL;
	if (sediff_app->p1_sfd.name)
		g_string_free(sediff_app->p1_sfd.name, TRUE);
	if (sediff_app->p2_sfd.name)
		g_string_free(sediff_app->p2_sfd.name, TRUE);
	sediff_app->p1_sfd.name = NULL;
	sediff_app->p2_sfd.name = NULL;

	sediff_rename_types_window_unref_members(sediff_app->rename_types_window);

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

	sediff_set_open_policies_gui_state(FALSE);
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

/* file_data should be a char ** that can be assigned to the data allocated
   by mmap, size should be a preallocated int that we can put the size of data into 
   will also clear out any existing data from file_data.  will return 0 after clearing
   out data if file is binary
*/
static int sediff_file_mmap(const char *file, char **file_data, size_t *size)
{
	struct stat statbuf;
	int rt;

	/* clear out any old data */
	if (*file_data)
		munmap(*file_data,*size);
	
	*file_data = NULL;
	*size = 0;

	/* if this is a binary policy just return now
	   but this is not an error */
	if (fn_is_binpol(file))
		return 0;
	
	rt = open(file, O_RDONLY);
	if (rt < 0)
		return -1;
	if (fstat(rt, &statbuf) < 0) {
		close(rt);
		return -1;
	}

        *size = statbuf.st_size;
	if ((*file_data = mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE,
			  rt, 0)) == (caddr_t) -1) {
		close(rt);
		return -1;
	}
	close(rt);
	return 0;
}

/* opens p1 and p2, populates policy text buffers */
static int sediff_load_policies(const char *p1_file, const char *p2_file)
{
	GtkTextView *p1_textview, *p2_textview, *stats1, *stats2;
	GString *string = g_string_new("");
	GdkCursor *cursor = NULL;
	GtkNotebook *notebook1, *notebook2;
	unsigned int opts = POLOPT_ALL;
	int rt;
	policy_t *p1;
	policy_t *p2;

	/* set the cursor to a hourglass */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, cursor);
	gdk_cursor_unref(cursor);
	gdk_flush();

	sediff_initialize_policies();
	while (gtk_events_pending ())
		gtk_main_iteration ();
		
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

	/* set up the policies */
	if (sediff_app->p1)
		close_policy(p1);
	if (sediff_app->p2)
		close_policy(p2);

	sediff_app->p1_sfd.name = g_string_new(p1_file);
	sediff_app->p2_sfd.name = g_string_new(p2_file);
	sediff_app->p1 = p1;
	sediff_app->p2 = p2;
	sediff_file_mmap(p1_file, &(sediff_app->p1_sfd.data), &(sediff_app->p1_sfd.size));
	sediff_file_mmap(p2_file, &(sediff_app->p2_sfd.data), &(sediff_app->p2_sfd.size));
		
	/* Grab the 2 policy textviews */
	p1_textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_text");
	g_assert(p1_textview);
	p2_textview = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_text");
	g_assert(p2_textview);
	
	stats1 = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p1_stats_text");
	g_assert(stats1);
	stats2 = (GtkTextView *)glade_xml_get_widget(sediff_app->window_xml, "sediff_main_p2_stats_text");
	g_assert(stats2);
	
	notebook1 = (GtkNotebook *)glade_xml_get_widget(sediff_app->window_xml, "notebook1");
	g_assert(notebook1);
	notebook2 = (GtkNotebook *)glade_xml_get_widget(sediff_app->window_xml, "notebook2");
	g_assert(notebook2);
	
	g_signal_connect_after(G_OBJECT(notebook1), "event-after", 
			 G_CALLBACK(sediff_on_policy1_notebook_event_after), notebook1);
	g_signal_connect_after(G_OBJECT(notebook2), "event-after", 
			 G_CALLBACK(sediff_on_policy2_notebook_event_after), notebook2);

	/* populate the 2 stat buffers */
	sediff_policy_stats_textview_populate(p1, stats1, p1_file);
	sediff_policy_stats_textview_populate(p2, stats2, p2_file);

	sediff_reset_policy_notebooks();
	
	/* open is done set cursor back to a ptr */
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, NULL);

	sediff_set_open_policies_gui_state(TRUE);
	sediff_initialize_diff();
	return 0;
	
	err:
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->window)->window, NULL);
	sediff_initialize_policies();
	sediff_initialize_diff();
	return -1;
}

/* open the files listed in the open_dialog */
void sediff_open_dialog_open_and_load_policies()
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

	rt = sediff_load_policies((const char*)p1_file, (const char*)p2_file);

	/* load is done set cursor back to a ptr */
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();

	if (rt < 0)
		return;
}

void sediff_open_dialog_on_open_and_diff_button_clicked(GtkButton *button, gpointer user_data)
{
	GdkCursor *cursor = NULL;
	
	sediff_open_dialog_open_and_load_policies();

	/* set the cursor to a hand */
	cursor = gdk_cursor_new(GDK_WATCH);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();

	run_diff_clicked();

	/* load is done set cursor back to a ptr */
	cursor = gdk_cursor_new(GDK_LEFT_PTR);
	gdk_window_set_cursor(GTK_WIDGET(sediff_app->open_dlg)->window, cursor);	
	gdk_cursor_unref(cursor);
	gdk_flush();

	/* destroy the no longer needed dialog widget */
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;
}

void sediff_open_dialog_on_open_button_clicked(GtkButton *button, gpointer user_data)
{

	sediff_open_dialog_open_and_load_policies();
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	sediff_app->open_dlg = NULL;
	g_object_unref(G_OBJECT(sediff_app->open_dlg_xml));
	sediff_app->open_dlg_xml = NULL;

}

typedef struct delayed_main_data {
	GString *p1_file;
	GString *p2_file;
	bool_t run_diff;
} delayed_data_t;

/*
 * We don't want to do the heavy work of loading and displaying 
 * the diff before the main loop has started because it will freeze
 * the gui for too long. To solve this, the function is called from an
 * idle callback set-up in main.
 */
static gboolean delayed_main(gpointer data)
{
	delayed_data_t *delay_data = (delayed_data_t *)data;
	const char *p1_file = delay_data->p1_file->str;
	const char *p2_file = delay_data->p2_file->str;

	sediff_load_policies(p1_file, p2_file);
	g_string_free(delay_data->p1_file, TRUE);
	g_string_free(delay_data->p2_file, TRUE);

	if (delay_data->run_diff == TRUE)
		run_diff_clicked();
	return FALSE;
}

static void sediff_main_notebook_on_switch_page(GtkNotebook *notebook, GtkNotebookPage *page, guint pagenum, gpointer user_data) 
{
	sediff_app_t *sediff_app = (sediff_app_t*)user_data;
	GtkLabel *label = NULL;
	
	if (pagenum == 0) {
		label = (GtkLabel*)glade_xml_get_widget(sediff_app->window_xml, "line_label");
		gtk_label_set_text(label, "");
	} 
}

/* return the textview currently displayed to the user */
GtkTextView *sediff_get_current_view(sediff_app_t *app)
{
	GtkNotebook *notebook = NULL;
	GtkNotebook *tab_notebook = NULL;
	int pagenum;
	GtkTextView *text_view = NULL;
	
	notebook = GTK_NOTEBOOK(glade_xml_get_widget(app->window_xml, "main_notebook"));
	pagenum = gtk_notebook_get_current_page(notebook);
	/* do we need to use the treeview */
	if (pagenum == 0) {
		text_view = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_results_txt_view"));
	} else if (pagenum == 1) {
		/* is this one of the other notebooks */
		tab_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook1"));
		pagenum = gtk_notebook_get_current_page(tab_notebook);
		if (pagenum == 0) 
			text_view = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_main_p1_stats_text"));			
		else
			text_view = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_main_p1_text"));			
	} else {
		/* is this one of the other notebooks */
		tab_notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook2"));
		pagenum = gtk_notebook_get_current_page(tab_notebook);
		if (pagenum == 0) 
			text_view = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_main_p2_stats_text"));			
		else
			text_view = GTK_TEXT_VIEW(glade_xml_get_widget(app->window_xml, "sediff_main_p2_text"));			
	}
	return text_view;

}

int main(int argc, char **argv)
{
	char *dir = NULL;
	GString *path = NULL; 
	delayed_data_t delay_data;
	bool_t havefiles = FALSE;
	int optc;
	int cli;
	const char *fname1;
        delay_data.p1_file = delay_data.p2_file = NULL;
	delay_data.run_diff = FALSE;
	GtkNotebook *notebook = NULL;
	GtkTextView *textview = NULL;
	
	
	if (rindex(argv[0],'/')) {
		fname1 = rindex(argv[0],'/')+1;
	}
	else
		fname1 = argv[0];

	cli = strncmp("sediffx",fname1,strlen("sediffx"));
	
	while ((optc = getopt_long (argc, argv, "qXctrubiTRCshvd", longopts, NULL)) != -1)  {
		switch (optc) {
		case 0:
	  		break;
	  	case 'd': /* run the diff only for gui */
			delay_data.run_diff = TRUE;
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
		delay_data.p1_file = g_string_new(argv[optind]); 
		delay_data.p2_file = g_string_new(argv[optind+1]); 
	}
	else if (argc - optind != 0){
		usage(argv[0],0);
		return -1; 
	} else {
		/* here we have found no missing arguments, but perhaps the user specified -d with no files */
		if (delay_data.run_diff == TRUE) {
			usage(argv[0], 0);
			return -1;
		}
	}

	
	gtk_init(&argc, &argv);
	glade_init();
	dir = find_file(GLADEFILE);
	if (!dir){
		fprintf(stderr, "Could not find %s!", GLADEFILE);
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
			 G_CALLBACK(sediff_main_window_on_destroy), sediff_app);
	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "main_notebook"));
	g_assert(notebook);
	g_signal_connect_after(G_OBJECT(notebook), "switch-page", 
			 G_CALLBACK(sediff_main_notebook_on_switch_page), sediff_app);
		
	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook1"));
	g_assert(notebook);
	g_signal_connect_after(G_OBJECT(notebook), "switch-page", 
			 G_CALLBACK(sediff_policy_notebook_on_switch_page), sediff_app);
	notebook = GTK_NOTEBOOK(glade_xml_get_widget(sediff_app->window_xml, "notebook2"));
	g_assert(notebook);
	g_signal_connect_after(G_OBJECT(notebook), "switch-page", 
			 G_CALLBACK(sediff_policy_notebook_on_switch_page), sediff_app);


	glade_xml_signal_autoconnect(sediff_app->window_xml);
	
	sediff_initialize_policies();
	sediff_initialize_diff();

	if (havefiles) 
		g_idle_add(&delayed_main, &delay_data);

	/* grab the text buffers for our text views */
	textview = GTK_TEXT_VIEW(glade_xml_get_widget(sediff_app->window_xml, "sediff_results_txt_view"));
	g_assert(textview);

	/* Configure text_view */
	gtk_text_view_set_editable(textview, FALSE);
	gtk_text_view_set_cursor_visible(textview, FALSE);




	sediff_results_txt_view_switch_buffer(textview,OPT_SUMMARY,1);
	
	gtk_main();
	
	if (path != NULL)
		g_string_free(path,1);
	return 0;
}

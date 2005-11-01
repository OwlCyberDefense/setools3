#include "../filters.h"
#include "../auditlog.h"
#include "../parse.h"
#include "../multifilter.h"
#include "../auditlog_view.h"
#include <errno.h>
#include <string.h>
#include <assert.h>

int main(int argc, char **argv)
{
	audit_log_t *log;
	char *src_type = "user_t";
	char *class = "file";
	int *deleted = NULL, num_deleted, num_kept, old_sz, new_sz;
	FILE *tmp_file = NULL;
	seaudit_filter_t *filter = NULL;
	seaudit_multifilter_t *multifilter = NULL;
	audit_log_view_t *log_view = NULL;
	
	if (argc != 2) {
		printf("usage: test [message_file]\n");
		return 0;
	}
	log = audit_log_create();
	tmp_file = fopen(argv[1], "r");
	if (!tmp_file) {
		fprintf(stderr, "Error opening file: %s\n", strerror(errno));
		return -1;
	}
			
	parse_audit(tmp_file, log);
	printf("parsed audit log: %s\n", argv[1]);
	
	/* Create a log view */
	log_view = audit_log_view_create();
	if (log_view == NULL) {
		return -1;
	}
	multifilter = seaudit_multifilter_create();
	if (multifilter == NULL) {
		return -1;
	}
	audit_log_view_set_log(log_view, log);
	
	seaudit_multifilter_set_match(multifilter, SEAUDIT_FILTER_MATCH_ALL);
	seaudit_multifilter_set_show_matches(multifilter, TRUE);	
	
	filter = seaudit_filter_create();
	filter->src_type_criteria = src_type_criteria_create(&src_type, 1);
	filter->class_criteria = class_criteria_create(&class, 1);

	seaudit_multifilter_add_filter(multifilter, filter);
	audit_log_view_set_multifilter(log_view, multifilter);
	
	printf("added src_type and obj_class filters\n");
	old_sz = log_view->num_fltr_msgs;
	audit_log_view_do_filter(log_view, &deleted, &num_deleted);
	new_sz = log_view->num_fltr_msgs;
	num_kept = old_sz - num_deleted;

	assert(num_kept >= 0);
	assert(num_kept <= new_sz);
	printf("deleted %d items by filter\n", num_deleted);
	if (deleted){
		free(deleted);
	}
	seaudit_multifilter_destroy(multifilter);
	
	printf("did filtering\n");
	audit_log_destroy(log);
	audit_log_view_destroy(log_view);
	
	log = audit_log_create();
	parse_audit(tmp_file, log);
	audit_log_destroy(log);
	fclose(tmp_file);
	return 0;
}

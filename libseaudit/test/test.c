#include "filters.h"
#include "auditlog.h"
#include "parse.h"

int main(int argc, char **argv)
{
	filter_t *filter;
	audit_log_t *log;
	char *src_type = "user_t";
	char *class = "file";
	int *deleted = NULL;
	int num_deleted;

	if (argc != 2) {
		printf("useage: test [message_file]\n");
		return 0;
	}
	log = audit_log_create();
	parse_audit(argv[1], log);
	printf("parsed audit log: %s\n", argv[1]);
	filter = src_type_filter_create(&src_type, 1);
	audit_log_add_filter(log, filter);
	filter = class_filter_create(&class, 1);
	audit_log_add_filter(log, filter);
	printf("added src_type and obj_class filters\n");
	log->fltr_out = TRUE;
	audit_log_do_filter(log, TRUE, &deleted, &num_deleted);
	printf("deleted %d items by filter\n", num_deleted);
	if (deleted)
		free(deleted);
	printf("did filtering\n");
	audit_log_destroy(log);
	log = audit_log_create();
	parse_audit(argv[1], log);
	audit_log_destroy(log);
	return 0;
}

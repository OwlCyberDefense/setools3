/* 
 *  Copyright (C) 2003-2004 Tresys Technology, LLC
 *  see file 'COPYING' for use and warranty information
 *
 */

/* 
 *  Author: Jeremy Stitz <jstitz@tresys.com> 
 *          Kevin Carr <kcarr@tresys.com>
 *
 *    Date: January 14, 2004 
 * 
 *  replcon: a tool for replacing file contexts in SE Linux
 */

/* replcon definitions */
#include "replcon.h"
#include <string.h>
#include <assert.h>
#include <selinux/context.h>

/* globals */ 
extern replcon_info_t replcon_info;
extern const char *replcon_object_classes[];

static struct option const longopts[] =
{
	{"recursive", no_argument, NULL, 'r'},
	{"object", required_argument, NULL, 'o'},
	{"context", optional_argument, NULL, 'c'},
	{"stdin", no_argument, NULL, 's'},
	{"quiet", no_argument, NULL, 'q'},
	{"verbose", no_argument, NULL, 'V'},
	{"version", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0}
};

void replcon_info_print_progress(replcon_info_t *info, char *normal_output, char *verbose_output)
{
	if (info->quiet)
		return;
	if (info->verbose) {
		printf(verbose_output);
		return;
	}
	printf(normal_output);
}

/* 
 * replcon_usage
 *
 * Prints out usage instrcutions for the program. If brief is set to 1 (true) only the 
 * syntax for program execution is displayed
 */
void replcon_usage(const char *program_name, int brief)
{
	printf("Usage: %s [OPTIONS] [-c OLD NEW] FILENAMES...\n", program_name);
	if(brief) {
		printf("\nTry %s --help for more help.\n\n", program_name);
		return;
	}
	printf("\nFile context replacement tool for Security Enhanced Linux.\n");
        printf("  -c,  --context=OLD NEW  Specify context to replace, see below.\n");
        printf("  -o,  --object=OBJECT    Only replace context for the specific\n");
	printf("                          object class.\n");
        printf("  -r,  --recursive        Recurse through directories.\n");
        printf("  -s,  --stdin            Read FILENAMES from standard input.\n");
 	printf("  -q,  --quiet            Suppress progress output.\n");
        printf("  -V,  --verbose          Display context info.\n");
 	printf("  -v,  --version          Display version information and exit.\n");
	printf("  -h,  --help             Display this help and exit.\n");
	printf("\n");
	printf("A context may be specified as a colon separated list of user, role, and type\n");
	printf("as follows - user_u:object_r:user_t.  replcon will automatically match a user,\n");
	printf("role, or type that is not specified, with any other user, role, or type.\n");
	printf("For example ::user_t specifies any context that has user_t as the type.\n\n");
}

/*
 * replcon_info_init
 *
 * Sets the data members of info to initial values
 */ 
void replcon_info_init(replcon_info_t *info)
{
	info->recursive = 0;
	info->quiet     = 0;
	info->verbose   = 0;
	info->stdin     = 0;
	info->obj_classes = NULL;
	info->pairs    = NULL;
	info->locations   = NULL;
	info->num_classes   = 0;
	info->num_pairs  = 0;
	info->num_locations = 0;
}

/*
 * replcon_info_free
 * 
 * Frees all the allocated memory in info 
 */
void replcon_info_free(replcon_info_t *info)
{
	int i;

	/* Free Object Classes */
	if(info->obj_classes) {
		free(info->obj_classes);
		info->obj_classes = NULL;
	}
	/* Free context pairs */
	if (info->pairs) {
		for(i = 0; i < (info->num_pairs); i++) {
			if(info->pairs[i].old_context) {
				context_free(info->pairs[i].old_context);
				info->pairs[i].old_context = NULL;
			}
			if(info->pairs[i].new_context) {
				context_free(info->pairs[i].new_context);
				info->pairs[i].new_context = NULL;
			}
		}
		free(info->pairs);
		info->pairs = NULL;
	}
	/* Free Locations */
	if (info->locations) {
		for(i = 0; i < info->num_locations; i++) {
			if(info->locations[i]) {
				free(info->locations[i]);
				info->locations[i] = NULL;
			}
		}
		free(info->locations);
	}
	return;
}

/*
 * replcon_info_add_object_class
 *
 * Adds class_id to the array of object types stored in replcon_info that will have their 
 * context changed upon program execution
 */
bool_t replcon_info_add_object_class(replcon_info_t *info, const char *str)
{
	replcon_classes_t class_id;

	class_id = replcon_is_valid_object_class(str);
	/* Check the object class */
	if(class_id == -1) {
		fprintf(stderr, "Error: invalid object class \'%s\'\n", optarg);
		return FALSE;
	}

	info->obj_classes = (replcon_classes_t*)realloc(info->obj_classes, sizeof(replcon_classes_t)*(info->num_classes+1));
	if(!info->obj_classes)
		return FALSE;
	
	info->obj_classes[info->num_classes] = class_id;
	info->num_classes++;
	return TRUE;
}
		
/*
 * add_context_pair
 *
 * Adds the context pair, old and new, to the array of context pairs stored in replcon_info
 * that will be changed upon program execution
 */
bool_t replcon_info_add_context_pair(replcon_info_t *info, const char *old, const char *new)
{
	info->pairs = (replcon_context_pair_t*)realloc(info->pairs, sizeof(replcon_context_pair_t)*(info->num_pairs+1));
	if(!info->pairs)
		return FALSE;
	
	/* Check the required context pairs */
	if (!replcon_is_valid_context_format(old)) {
		fprintf(stderr, "Error: \'%s\' is not a valid context format.\n", old);
		return FALSE;
	}

	if (!replcon_is_valid_context_format(new)) {
		fprintf(stderr, "Error: \'%s\' is not a valid context format.\n", new);
		return FALSE;
	}
	info->pairs[info->num_pairs].old_context = context_new(old);
	if (context_type_get(info->pairs[info->num_pairs].old_context) == NULL)
		context_type_set(info->pairs[info->num_pairs].old_context, "");
	info->pairs[info->num_pairs].new_context = context_new(new);
	if (context_type_get(info->pairs[info->num_pairs].new_context) == NULL)
		context_type_set(info->pairs[info->num_pairs].new_context, "");
	info->num_pairs++;
	return TRUE;
}

/*
 * add_location
 *
 * Adds loc to the array of file/directory locations stored in replcon_info that will
 * have contexts replaced
 */
bool_t replcon_info_add_location(replcon_info_t *info, const char *loc)
{
	info->locations = realloc(info->locations, sizeof(char*)*(info->num_locations+1));
	if (!info->locations) {
		fprintf(stderr, "Error: Out of memory\n");
		return FALSE;
	}
	info->locations[info->num_locations] = strdup(loc);
	info->num_locations++;
	return TRUE;
}

/*
 * replcon_info_has_object_class
 *
 * Check if replcon_info has an object class
 */
bool_t replcon_info_has_object_class(replcon_info_t *info, replcon_classes_t obj_class)
{
	int i;
	
	for(i = 0; i < info->num_classes; i++)
		if(info->obj_classes[i] == obj_class || replcon_info.obj_classes[i] == ALL_FILES)
			return TRUE;
	return FALSE;
}

/*
 * repcon_is_valid_object_class
 *
 * Determines if class_name is a valid object class.  Return -1 if invalid
 * otherwise the index of the valid object class
 */
int replcon_is_valid_object_class(const char *class_name)
{
	int i;

	for(i = 0; i < NUM_OBJECT_CLASSES; i++)
		if(strcmp(class_name, replcon_object_classes[i]) == 0)
			return i;
	return -1;
}


/* 
 * replcon_is_valid_context_format
 *
 * Determines if context is a valid file context format
 */
bool_t replcon_is_valid_context_format(const char *context_str)
{
	context_t context;

	context = context_new(context_str);
	if(!context)
		return FALSE;

	context_free(context);
	context = NULL;
	return TRUE;
}


/*
 * replcon get_file_class
 *
 * Determines the file's class, and returns it
 */
int replcon_get_file_class(const struct stat *statptr)
{
	if(S_ISREG(statptr->st_mode))
		return NORM_FILE;
	if(S_ISDIR(statptr->st_mode))
		return DIR;
	if(S_ISLNK(statptr->st_mode))
		return LNK_FILE;
	if(S_ISCHR(statptr->st_mode))
		return CHR_FILE;
	if(S_ISBLK(statptr->st_mode))
		return BLK_FILE;
	if(S_ISSOCK(statptr->st_mode))
		return SOCK_FILE;
	if(S_ISFIFO(statptr->st_mode))
		return FIFO_FILE;
	return ALL_FILES;
}	


/*
 * replcon_context_equal
 *
 * return true if the contexts are the same, if any context field is empty (ie. no user field) then that field matches
 * example - ::user_t == x_u:y_r:user_t, 
 * example - x_u:y_r:user_t != user_u:y_r:user_t
 */
bool_t replcon_context_equal(context_t a, context_t b)
{
	bool_t user_match, role_match, type_match;
	user_match = strcmp(context_user_get(a), context_user_get(b)) == 0 || strcmp(context_user_get(a), "") == 0 || strcmp(context_user_get(b), "") == 0;
	role_match = strcmp(context_role_get(a), context_role_get(b)) == 0 || strcmp(context_role_get(a), "") == 0 || strcmp(context_role_get(b), "") == 0;
	type_match = strcmp(context_type_get(a), context_type_get(b)) == 0 || strcmp(context_type_get(a), "") == 0 || strcmp(context_type_get(b), "") == 0;
	return user_match && role_match && type_match;
}
	
/*  
 * change_context
 *
 * Change the context of the file, as long as it meets the specifications in replcon_info.
 * The caller must pass a valid filename and statptr.
 */ 
int replcon_replace_file_context(const char *filename, const struct stat *statptr, int fileflags, struct FTW *pfwt)
{
	int file_class, i;
	context_t tmp=NULL, tmp_new=NULL;
	security_context_t old_con=NULL, new_con=NULL;
	const size_t REPLCON_BUFF_SZ = 1024;
	char normal_output[REPLCON_BUFF_SZ];
	char verbose_output[REPLCON_BUFF_SZ];
	
	file_class = replcon_get_file_class(statptr);
	if (!replcon_info_has_object_class(&replcon_info, file_class))
		return 0;

	for (i = 0; i < replcon_info.num_pairs; i++) {
		if (lgetfilecon(filename, &old_con) <= 0) {
			fprintf(stderr, "Warning: %s is not labeled.  File skipped.\n", filename);
			return 0;
		}
		tmp = context_new(old_con);
		if (replcon_context_equal(replcon_info.pairs[i].old_context, tmp)) {
			tmp_new = context_new(context_str(replcon_info.pairs[i].new_context));
			if (context_type_get(tmp_new) == NULL)
				context_type_set(tmp_new, "");
			/* if the new context was not specified completely, fill in the blanks */
			if (strcmp(context_user_get(tmp_new), "") == 0)
				context_user_set(tmp_new, context_user_get(tmp));
			if (strcmp(context_role_get(tmp_new), "") == 0)
				context_role_set(tmp_new, context_role_get(tmp));
			if (strcmp(context_type_get(tmp_new), "") == 0)
				context_type_set(tmp_new, context_type_get(tmp));			
			new_con = context_str(tmp_new);
			if (lsetfilecon(filename, new_con) != 0) {
				fprintf(stderr, "Warning: Unable to replace context for %s. Possibly invalid context [%s].\n", filename, new_con);
			}
			snprintf(normal_output, REPLCON_BUFF_SZ, "Replaced context: %s\n", filename);
			snprintf(verbose_output, REPLCON_BUFF_SZ, "Replaced context: %s     old context: [%s]     new context: [%s]\n", 
				 filename, old_con, new_con);
			replcon_info_print_progress(&replcon_info, normal_output, verbose_output);	
			context_free(tmp_new);
		}
		context_free(tmp);
		freecon(old_con);
	}
 	return 0;
}

/*
 * remove_new_line_char
 *
 * Removes the new line character from stdin stream input strings
 */
void remove_new_line_char(char *input)
{
	int i;

	for(i = 0; i < strlen(input); i++) {
		if(input[i] == '\n')
			input[i] = '\0';
	}
	return;
}

void replcon_parse_command_line(int argc, char **argv)
{
	int optc, i;


	/* get option arguments */
	while ((optc = getopt_long (argc, argv, "o:c:rsVqvh", longopts, NULL)) != -1) {
		switch (optc) {
	        case 0:
	  		break;
		case 'o':
			if (!replcon_info_add_object_class(&replcon_info, optarg)) {
				fprintf(stderr, "Unable to add object class.\n");
				exit(-1);
			}
			break;
		case 'c':		
			if (!replcon_info_add_context_pair(&replcon_info, optarg, argv[optind])) {
				fprintf(stderr, "Unable to add context pair.\n");
				replcon_info_free(&replcon_info);
				exit(-1);
			}
			optind++;
			break;
		case 'r': /* recursive directory parsing */
		        replcon_info.recursive = TRUE;
			break;
		case 's': /* read from standard in */
		        replcon_info.stdin = TRUE;
		        break;
		case 'q':
			if (replcon_info.verbose) {
				fprintf(stderr, "Error: Can not specify -q and -V\n");
				goto bad;
			}
			replcon_info.quiet = TRUE;
			break;
		case 'V': /* verbose program execution */
			if (replcon_info.quiet) {
				fprintf(stderr, "Error: Can not specify -q and -V\n");
				goto bad;
			}
			replcon_info.verbose = TRUE;
			break;
	  	case 'v': /* version */
	  		printf("\n%s (%s)\n\n", COPYRIGHT_INFO, REPLCON_VERSION_NUM);
			replcon_info_free(&replcon_info);
	  		exit(0);
	  	case 'h': /* help */
	  		replcon_usage(argv[0], 0);
			replcon_info_free(&replcon_info);
	  		exit(0);
	  	default:  /* usage */
	  		replcon_usage(argv[0], 1);
			replcon_info_free(&replcon_info);
	  		exit(-1);
		}
	}
	/* If no object class was specified revert to the default of all files */
	if (replcon_info.num_classes == 0) {
		if (!replcon_info_add_object_class(&replcon_info, "all_files")) {
			fprintf(stderr, "Unable to add oject class.\n");
			goto bad;
		}
	}
	/* Make sure required arguments were supplied */
	if (((!replcon_info.stdin) && ((argc - optind) < 3)) || ((replcon_info.stdin) && ((argc - optind) < 2))) {
		fprintf(stderr, "Error: Missing required arguments.\n");
		replcon_usage(argv[0], 1);
		replcon_info_free(&replcon_info);
		exit(-1);
	}
	/* Add required context pair */
	if (!replcon_info_add_context_pair(&replcon_info, argv[optind], argv[optind+1])) {
		fprintf(stderr, "Unable to add context pair.\n");
		replcon_info_free(&replcon_info);
		exit(-1);
	}
	/* Add required Locations */
	for (i = (argc - 1); i >=  (optind + 2); i--) {
		if (!replcon_info_add_location(&replcon_info, argv[i])) {
			fprintf(stderr, "Unable to add file or directory.\n");
			goto bad;
		}
	}	  
	/* Ensure that locations were not specified in addition to the standard in option */
	if((replcon_info.num_locations > 0) && replcon_info.stdin) {
		fprintf(stderr, "Warning: Command line filename(s) will be ignored. Reading from stdin.\n");
	}
	return;

 bad:
	replcon_info_free(&replcon_info);
	exit(-1);	
}

void replcon_stat_file_replace_context(const char *filename)
{
	struct stat file_status;

	if(stat(filename, &file_status) != 0) {
		fprintf(stderr, "Warning: Can not stat \'%s\'.  Skipping this file.\n", filename);
		return;
	}
	if (replcon_info.recursive)
		nftw(filename, replcon_replace_file_context, NFTW_DEPTH, NFTW_FLAGS);
	else 
		replcon_replace_file_context(filename, &file_status, 0, NULL);

}

int main (int argc, char **argv)
{
	char stream_input[MAX_INPUT_SIZE];
	int i;

	replcon_info_init(&replcon_info);
	replcon_parse_command_line(argc, argv);

	if(replcon_info.stdin)
		while (fgets(stream_input, (MAX_INPUT_SIZE - 1), stdin)) {
			remove_new_line_char(stream_input);
			replcon_stat_file_replace_context(stream_input);
		}
	else
		for(i = 0; i < replcon_info.num_locations; i++)
			replcon_stat_file_replace_context(replcon_info.locations[i]);

	replcon_info_free(&replcon_info);
	return 0;
}

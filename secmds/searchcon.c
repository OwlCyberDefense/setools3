/*
 *  Copyright (C) 2003-2006 Tresys Technology, LLC
 *  see file 'COPYING' for use and warranty information
 *
 *  searchcon: a tool for searching SELinux filesystem databases
 */

#include <config.h>

/* libsefs */
#include <sefs/fsdata.h>
/* standard library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* command line parsing commands */
#include <getopt.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2006 Tresys Technology, LLC"

static struct option const longopts[] =
{
  {"type", required_argument, NULL, 't'},
  {"user", required_argument, NULL, 'u'},
  {"mls-range", required_argument, NULL, 'm'},
  {"path", required_argument, NULL, 'p'},
  {"list", no_argument, NULL, 'l'},
  {"regex", no_argument, NULL, 'r'},
  {"object", required_argument, NULL, 'o'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};

static void sefs_double_array_print(char **array,int size)
{
	int i;
	for (i=0;i<size;i++){
		printf("%s\n",array[i]);
	}

}

static void sefs_search_keys_ret_print(sefs_search_ret_t *key)
{
	sefs_search_ret_t *curr = NULL;

	/* walk the linked list	 */
	curr = key;
	if (curr == NULL) {
		printf("No results\n");
	}
	while (curr) {
		if (curr->context)
			printf("%s\t",curr->context);
		if (curr->object_class)
			printf("%s\t",curr->object_class);
		if (curr->path)
			printf("%s",curr->path);
		printf("\n");
		curr = curr->next;
	}
}

void usage(const char *program_name, int brief)
{
	int size;
	char **array = NULL;
	printf("%s (searchcon ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
	printf("Usage: %s <index file> [OPTIONS]\n", program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Print requested information about an SELinux policy.\n\
  -t type,   --type=typename   	   The name of the type to search for\n\
  -u user,   --user=username   	   The name of the user to search for\n\
  -m range,  --mls-range=range     MLS range to search for\n\
  -p path,   --path=pathname       The path or path fragment to search for\n\
  -o object, --object=class        The name of the object class to search for\n\
  -r, --regex                      Search using regular expressions\n\
  -l, --list                       List types in the snapshot\n\
", stdout);
	fputs("\n\
  -h, --help                       Display this help and exit\n\
  -v, --version                    Output version information and exit\n\
", stdout);
	printf("If the index file does not contain any MLS ranges then the search\nwill return nothing.\n");
	fputs("\n\
Valid object classes include:\n\
",stdout);
	array = sefs_get_valid_object_classes(&size);
	sefs_double_array_print(array,size-1); /* don't print "all_files" it is not used here */
	sefs_double_array_destroy(array,size);
	return;
}

int main(int argc, char **argv, char **envp)
{
	char *filename = NULL;
	int optc = 0, list_sz = 0, list = 0;
	sefs_filesystem_db_t fsdata;
	sefs_search_keys_t search_keys;
	char **list_ret = NULL;
	const char **holder = NULL;

	memset(&search_keys, 0, sizeof(search_keys));

	while ((optc = getopt_long (argc, argv, "t:u:m:p:o:rlhv", longopts, NULL)) != -1)  {
		switch (optc) {
		case 't': /* type */
			if((holder = (const char**)realloc(search_keys.type,sizeof(char *)*(search_keys.num_type+1))) == NULL){
				printf("Out of memory\n");
				return 1;
			}
			search_keys.type = holder;
			search_keys.type[search_keys.num_type] = optarg;
			search_keys.num_type++;
			break;
		case 'u': /* user */
			if((holder = (const char**)realloc(search_keys.user,sizeof(char*)*(search_keys.num_user+1))) == NULL){
				printf("Out of memory\n");
				return 1;
			}
			search_keys.user = holder;
			search_keys.user[search_keys.num_user] = optarg;
			search_keys.num_user++;
			break;
		case 'm': /* MLS range */
			if((holder = (const char**)realloc(search_keys.range,sizeof(char*)*(search_keys.num_range+1))) == NULL){
				printf("Out of memory\n");
				return 1;
			}
			search_keys.range = holder;
			search_keys.range[search_keys.num_range] = optarg;
			search_keys.num_range++;
			break;
		case 'p': /* path */
			if((holder = (const char**)realloc(search_keys.path,sizeof(char*)*(search_keys.num_path+1))) == NULL){
				printf("Out of memory\n");
				return 1;
			}
			search_keys.path = holder;
			search_keys.path[search_keys.num_path] = optarg;
			search_keys.num_path++;
			break;
		case 'o': /* object */
			if ((holder = (const char**)realloc(search_keys.object_class,sizeof(char*)*(search_keys.num_object_class+1))) == NULL) {
				printf("Out of memory");
				return 1;
			}
			search_keys.object_class = holder;
			search_keys.object_class[search_keys.num_object_class] = optarg;
			search_keys.num_object_class++;
			break;
		case 'l': /* list */
			list = 1;
			break;
		case 'r': /* regex */
			search_keys.do_type_regEx = 1;
			search_keys.do_user_regEx = 1;
			search_keys.do_range_regEx = 1;
			search_keys.do_path_regEx = 1;
			break;
		case 'h': /* help */
			usage(argv[0], 0);
			exit(0);
		case 'v': /* version */
			printf("\n%s (searchcon ver. %s)\n\n", COPYRIGHT_INFO, VERSION);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}
	if (argc - optind > 1 || argc - optind < 1) {
		usage(argv[0], 1);
		exit(-1);
	} else
		filename = argv[optind];

	if (sefs_filesystem_db_load(&fsdata, filename) == -1 ){
		fprintf(stderr, "sefs_filesystem_data_load failed\n");
		return -1;
	}

	if (list == 1) {
		if ((list_ret = sefs_filesystem_db_get_known(&fsdata, SEFS_TYPES, &list_sz)) != NULL) {
			sefs_double_array_print(list_ret, list_sz);
			sefs_double_array_destroy(list_ret, list_sz);
		}
	}
	else {
		sefs_filesystem_db_search(&fsdata,&search_keys);
		sefs_search_keys_ret_print(search_keys.search_ret);
		sefs_search_keys_ret_destroy(search_keys.search_ret);
	}

	free(search_keys.user);
	free(search_keys.type);
	free(search_keys.path);
	free(search_keys.object_class);

	return 0;
}

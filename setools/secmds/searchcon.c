/*
 *  Copyright (C) 2003-2004 Tresys Technology, LLC
 *  see file 'COPYING' for use and warranty information
 *
 */

/*
 *  searchcon: a tool for searching SELinux filesystem databases
 */

/* SE Linux includes*/
#include <selinux/selinux.h>
#include <selinux/context.h>
/* standard library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <regex.h>
/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>
#include <mntent.h>
/* AVL Tree Handling */
#include <avl-util.h>
#include <policy.h>
#include <fsdata.h>
/* libapol helpers */
#include <util.h>

/* LISTCON_VERSION_NUM should be defined in the make environment */
#ifndef SEARCHCON_VERSION_NUM
#define SEARCHCON_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004 Tresys Technology, LLC"

static struct option const longopts[] =
{
  {"type", required_argument, NULL, 't'},
  {"user", required_argument, NULL, 'u'},
  {"path", required_argument, NULL, 'p'},
  {"list", no_argument, NULL, 'l'},
  {"regex", no_argument, NULL, 'r'},
  {"object", required_argument, NULL, 'o'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};

extern const char *sefs_object_classes[];

void usage(const char *program_name, int brief)
{
	printf("%s (listcon ver. %s)\n\n", COPYRIGHT_INFO, SEARCHCON_VERSION_NUM);
	printf("Usage: %s <index file> [OPTIONS]\n", program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fputs("\n\
Print requested information about an SELinux policy.\n\
  -t type, --type=typename   	   The name of the type to search for\n\
  -u user, --user=username   	   The name of the user to search for\n\
  -p path, --path=pathname   	   The path or path fragment to search for\n\
  -o object, --object=class        The name of the object class to search for\n\
  -r regex, --regex   		   Search using regular expressions\n\
  -l, --list			   List types in the snapshot\n\
", stdout);
	fputs("\n\
  -h, --help                       Display this help and exit\n\
  -v, --version                    Output version information and exit\n\
", stdout);
	fputs("\n\
Valid object classes include:\n\
",stdout);
	sefs_print_valid_object_classes();
	return;
}

int sefs_search_type(sefs_filesystem_data_t * fsd, char * type, uint32_t** list, uint32_t* list_size, int use_regex)
{
	regex_t reg;
	int i, j, rc = 0;

	if (fsd == NULL) {
		fprintf(stderr, "fsd is null\n");
		return -1;
	}

	if (type == NULL) {
		fprintf(stderr, "typename is null\n");
		return -1;
	}

	if (use_regex) {
		rc = regcomp(&reg, type, REG_EXTENDED|REG_NOSUB);
		if (rc != 0) {
			regfree(&reg);
			return -1;
		}
		for(i = 0; i < fsd->num_types; i++) {
			if (regexec(&reg, fsd->types[i].name, 0, NULL, 0) == 0) {
				for(j=0; j< fsd->types[i].num_inodes; j++) {
					rc = add_uint_to_a(fsd->types[i].index_list[j], list_size, list);
					if (rc == -1) {
						fprintf(stderr, "error in search_type()\n");
						return -1;
					}
				}
			}
		}
	} else {
		for(i = 0; i < fsd->num_types; i++) {
			if(strcmp(type, fsd->types[i].name) == 0) {
				for(j=0; j< fsd->types[i].num_inodes; j++) {
					rc = add_uint_to_a(fsd->types[i].index_list[j], list_size, list);
					if (rc == -1) {
						fprintf(stderr, "error in search_type()\n");
						return -1;
					}
				}
			}
		}
	

	}
	return !(*list_size);
}

int sefs_search_path(sefs_filesystem_data_t * fsd, char * path, uint32_t** list, uint32_t* list_size, int use_regex)
{
	int i, j, rc = 0;
	regex_t reg;
	uint32_t** new_list = (uint32_t**)malloc(sizeof(uint32_t*));
	uint32_t new_list_size = 0;
	if (!new_list) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	*new_list = NULL;

	if (fsd == NULL)
	{
		fprintf(stderr, "fsd is null\n");
		return -1;
	}

	if (path == NULL)
	{
		fprintf(stderr, "pathname is null\n");
		return -1;
	}
	if(*list == NULL) {
		if (use_regex) {
			rc = regcomp(&reg, path, REG_EXTENDED|REG_NOSUB);
			if (rc != 0) {
				regfree(&reg);
				return -1;
			}
			for (i = 0; i < fsd->num_files; i++) {
				for (j = 0; j < fsd->files[i].num_links; j++) {
					if(regexec(&reg, fsd->files[i].path_names[j],
						 0, NULL, 0) == 0) {
					rc = add_uint_to_a(i, &new_list_size, new_list);
						if ( rc == -1) {
							fprintf(stderr, 
								"error in search_path()\n");
							return -1;
						}
					}
				}
			}
	
		} else {
			for (i = 0; i < fsd->num_files; i++) {
				for(j=0; j < fsd->files[i].num_links; j++) {
					if(!strncmp(fsd->files[i].path_names[j], path, 
					strlen(path) < strlen(fsd->files[i].path_names[j]) ?
					strlen(path) : strlen(fsd->files[i].path_names[j]) )) {
					rc = add_uint_to_a(i, &new_list_size, new_list);
						if ( rc == -1) {
							fprintf(stderr, 
								"error in search_path()\n");
							return -1;
						}
					}
				}
			}
		}
	} else {
		if (use_regex) {
			rc = regcomp(&reg, path, REG_EXTENDED|REG_NOSUB);
			if (rc != 0) {
				regfree(&reg);
				return -1;
			}
			for (i = 0; i < *list_size; i++) {
				for (j = 0; j < fsd->files[(*list)[i]].num_links; j++) {
					if(regexec(&reg, fsd->files[(*list)[i]].path_names[j],
						 0, NULL, 0) == 0) {
					rc = add_uint_to_a((*list)[i], &new_list_size, new_list);
						if ( rc == -1) {
							fprintf(stderr, 
								"error in search_path()\n");
							return -1;
						}
					}
				}
			}
	
		} else {
			for (i = 0; i < *list_size; i++) {
				for(j=0; j < fsd->files[(*list)[i]].num_links; j++) {
					if(!strncmp(fsd->files[(*list)[i]].path_names[j], path,
				strlen(path) < strlen(fsd->files[(*list)[i]].path_names[j]) ?
				strlen(path) : strlen(fsd->files[(*list)[i]].path_names[j]) )) {
					rc = add_uint_to_a((*list)[i], &new_list_size, new_list);
						if ( rc == -1) {
							fprintf(stderr, 
								"error in search_path()\n");
							return -1;
						}
					}
				}
			}
		}

	}
	
	free(*list);
	*list = *new_list;
	*list_size = new_list_size;
	return !(*list_size);
}


int sefs_search_user(sefs_filesystem_data_t * fsd, char * uname, uint32_t** list, uint32_t* list_size)
{
	int i, rc;
	uint32_t** new_list = (uint32_t**)malloc(sizeof(uint32_t*));
	uint32_t new_list_size = 0;

	if (!new_list) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	*new_list = NULL;

	if (fsd == NULL) {
		fprintf(stderr, "fsd is null\n");
		return -1;
	}

	if (*list == NULL) {
		for (i = 0; i < fsd->num_files; i++) {
			if (!(strncmp(fsd->users[fsd->files[i].context.user], uname, strlen(uname) ))) {
				rc = add_uint_to_a(i, &new_list_size, new_list);
				if (rc == -1) {
					fprintf(stderr, "error in search_user()\n");
					return -1;
				}
			}
		}
		
	} else {
		for (i = 0; i < *list_size; i++) {
			if (!(strncmp(fsd->users[fsd->files[(*list)[i]].context.user], uname, strlen(uname)))) {
				rc = add_uint_to_a((*list)[i], &new_list_size, new_list);
				if (rc == -1) {
					fprintf(stderr, "error in search_user()\n");
					return -1;
				}
			}
		}
	}

	free(*list);
	*list = *new_list;
	*list_size = new_list_size;
	return !(*list_size);
}

int sefs_search_object_class(sefs_filesystem_data_t * fsd, int object, uint32_t** list, uint32_t* list_size)
{
	int i, rc;
	uint32_t** new_list = (uint32_t**)malloc(sizeof(uint32_t*));
	uint32_t new_list_size = 0;

	if (!new_list) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	*new_list = NULL;

	if(fsd == NULL) {
		fprintf(stderr, "fsd is null\n");
		return -1;
	}

	if(*list == NULL) {
		for (i = 0; i < fsd->num_files; i++) {
			if (object == fsd->files[i].obj_class) {
				rc = add_uint_to_a(i, &new_list_size, new_list);
				if (rc == -1) {
					fprintf(stderr, "error in search_object()\n");
					return -1;
				}
			}
		}
	} else {
		for (i = 0; i < *list_size; i++) {
			if (object == fsd->files[(*list)[i]].obj_class) {
				rc = add_uint_to_a((*list)[i], &new_list_size, new_list);
				if (rc == -1) {
					fprintf(stderr, "error in search_object()\n");
					return -1;
				}
			}
		}
	}

	free(*list);
	*list = *new_list;
	*list_size = new_list_size;	
	return !(*list_size);
}

void print_list (sefs_filesystem_data_t* fsd, uint32_t* list, uint32_t list_size)
{
	int i;
	char con[100];
	

	if (list_size && (!fsd || !list)) {
		fprintf(stderr, "invalid search results\n");
		return;
	}
	if(!list_size) {
		printf("search returned no results\n");
		return;
	}	
	
	for (i = 0; i < list_size; i++) {
		snprintf(con, sizeof(con), "%s:%s:%s", fsd->users[fsd->files[list[i]].context.user],
			fsd->files[list[i]].context.role == OBJECT_R ? "object_r": "UNLABLED",
			fsd->types[fsd->files[list[i]].context.type].name);

		printf("%-40s %-10s %s", con, 
			sefs_object_classes[fsd->files[list[i]].obj_class],
			fsd->files[list[i]].path_names[0]);

		if (fsd->files[list[i]].obj_class == LNK_FILE)
			printf(" -> %s\n", fsd->files[list[i]].symlink_target);
		else
			printf("\n");
			
	}	
}

int sefs_list_types(sefs_filesystem_data_t * fsd)
{
	int i = 0;

	for (i = 0; i < fsd->num_types; i++) {
		printf("%s\n", fsd->types[i].name);
	}

	return 0;
}


int main(int argc, char **argv, char **envp)
{
	char *filename = NULL, *tname = NULL, *uname = NULL, *path = NULL, *object = NULL;
	int optc = 0, rc = 0, list = 0, use_regex = 0;
	sefs_filesystem_data_t fsdata;
	uint32_t* index_list = NULL;
	uint32_t index_list_size = 0;

        filename = argv[1];
	if (filename == NULL) {
		usage(argv[0], 0);
		return -1;
	}

	while ((optc = getopt_long (argc, argv, "t:u:p:o:rlhv", longopts, NULL)) != -1)  {
		switch (optc) {
		case 't': /* type */
	  		tname = optarg;
	  		break;
		case 'u': /* user */
	  		uname = optarg;
	  		break;
		case 'p': /* path */
	  		path = optarg;
	  		break;
		case 'o': /* object */
			object = optarg;
			break;
		case 'l': /* list */
	  		list = 1;
	  		break;
		case 'r': /* regex */
			use_regex = 1;
			break;
		case 'h': /* help */
	  		usage(argv[0], 0);
	  		exit(0);
		case 'v': /* version */
	  		printf("\n%s (searchcon ver. %s)\n\n", COPYRIGHT_INFO, SEARCHCON_VERSION_NUM);
	  		exit(0);
		default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}


	if ((tname == NULL) && (uname == NULL) && (path == NULL) && (object == NULL) && !list) {
		fprintf(stderr, "\nYou must specify one of -t|-u|-p|-o\n\n");
		usage(argv[0], 0);
		return -1;
	}
	
	if (sefs_filesystem_data_init(&fsdata) == -1) {
		fprintf(stderr, "sefs_filesystem_data_init failed\n");
		return -1;
	}
	
	if (sefs_filesystem_data_load(&fsdata, filename) == -1) {
		fprintf(stderr, "sefs_filesystem_data_load failed\n");
		return -1;
	}
/*	
	if (sefs_filesystem_data_index(&fsdata) == -1) {
		fprintf(stderr, "sefs_filesystem_data_index failed\n");
		return -1;
	}
*/
	if (list) {
		if (sefs_list_types(&fsdata) == -1) {
			fprintf(stderr, "list_types() returned error\n");
			return -1;
		}
		return 0;
	}

	if (tname != NULL) {
		rc = sefs_search_type(&fsdata, tname, &index_list, &index_list_size, use_regex);

		switch(rc) {
		case -1:
			fprintf(stderr, "search_type() returned an error\n");
			return -1;
		case 1:
			fprintf(stderr, "no matches found for type\n");
			return -1;
		default:
			break;
		}

	}

	if (uname != NULL) {
		rc = sefs_search_user(&fsdata, uname, &index_list, &index_list_size);

		switch(rc) {
		case -1:
			fprintf(stderr, "search_type() returned an error\n");
			return(-1);
		case 1:
			fprintf(stderr, "no matches found for user\n");
			return(-1);
		default:
			break;
		}
	}

	if (object != NULL) {
		if((rc = sefs_is_valid_object_class(object)) == -1) {
			fprintf(stderr, "invalid object class\n\
				use %s --help for list of valid classes\n", argv[0]);
			return -1;
		}

		rc = sefs_search_object_class(&fsdata, rc, &index_list, &index_list_size);

		switch(rc) {
		case -1:
			fprintf(stderr, "search_object_class() returned an error\n");
			return -1;
		case 1:
			fprintf(stderr, "no matches found for object class\n");
			return -1;
		default:
			break;
		}
	}

	if (path != NULL) {
		rc = sefs_search_path(&fsdata, path, &index_list, &index_list_size, use_regex);

		switch(rc) {
		case -1:
			fprintf(stderr, "search_type() returned an error\n");
			return -1;
		case 1: 
			fprintf(stderr, "no matches found in path\n");
			return -1;
		default:
			break;
		}
	}
	print_list(&fsdata, index_list, index_list_size);

	return 0;
}

#include "test.h"
#include "policy.h"
#include "policy-io.h"
#include "perm-map.h"

/*
 * This tests that reloading a perm map fully replaces the perm
 * map. This was prompted by ticket #116.
 *
 * It also tests loading an unknown object class in a perm map
 * file.
 *
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 */

int find_map(policy_t *policy, int obj_class)
{
	int i;

	for (i = 0; i < policy->pmap->num_classes; i++) {
		if (policy->pmap->maps[i].cls_idx == obj_class)
			return i;
	}
	return -1;
}

unsigned char get_mapping(policy_t *policy, int obj_class, int perm_idx)
{
	int i, mapping = -1;
	int map_idx = find_map(policy, obj_class);
	TEST("getting map for object class", map_idx != -1);

	for (i = 0; i < policy->pmap->maps[map_idx].num_perms; i++) {
		if (policy->pmap->maps[map_idx].perm_maps[i].perm_idx == perm_idx) {
			mapping = i;
			break;
		}
	}
	TEST("finding mapping", mapping != -1);
	return policy->pmap->maps[map_idx].perm_maps[i].map;
}

int main(int argc, char **argv)
{
	FILE *fp;
	int perm_idx, obj_class;
	unsigned char map, map2;
	policy_t *policy = NULL;


	init_tests(argc, argv);

	TEST("loading a policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);
	
	obj_class = get_obj_class_idx("lnk_file", policy);
	TEST("getting object class", obj_class != -1);

	perm_idx = get_perm_idx("ioctl", policy);
	TEST("getting perm_idx", perm_idx != -1);

	fp = fopen("policy/tiny.map", "r");
	TEST("opening tiny map", fp != NULL);
	TEST("loading perm map", (load_policy_perm_mappings(policy, fp) & PERMMAP_RET_ERROR) == 0);
	fclose(fp);

	map = get_mapping(policy, obj_class, perm_idx);
	printf("%d\n", map);
	

	fp = fopen("policy/full.map", "r");
	TEST("opening full map", fp != NULL);
	TEST("loading perm map", (load_policy_perm_mappings(policy, fp) & PERMMAP_RET_ERROR) == 0);
	fclose(fp);
	
	map2 = get_mapping(policy, obj_class, perm_idx);
	TEST("mapping changed", map != map2);
	printf("%d %d\n", map, map2);

	map = map2;

	fp = fopen("policy/tiny.map", "r");
	TEST("opening tiny map", fp != NULL);
	TEST("loading perm map", (load_policy_perm_mappings(policy, fp) & PERMMAP_RET_ERROR) == 0);
	fclose(fp);

	map2 = get_mapping(policy, obj_class, perm_idx);
	printf("%d %d\n", map, map2);
	TEST("mapping changed", map != map2);	

	return 0;
}

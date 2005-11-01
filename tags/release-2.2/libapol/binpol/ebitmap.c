
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> 
 *
 * Changed by mayerf@tresys.com to binary policy support in libapol*/

/* FLASK */

/* 
 * Implementation of the extensible bitmap type.
 */

#include "ebitmap.h"
#include "borrowed.h"
#include "fbuf.h"
#include <stdio.h>
#include <malloc.h>
#include <errno.h>

#define EBITMAP_ERR		-8
#define EBITMAP_READ_ERR	-3

int ebitmap_or(ebitmap_t * dst, ebitmap_t * e1, ebitmap_t * e2)
{
	ebitmap_node_t *n1, *n2, *new, *prev;


	ebitmap_init(dst);

	n1 = e1->node;
	n2 = e2->node;
	prev = 0;
	while (n1 || n2) {
		new = (ebitmap_node_t *) kmalloc(sizeof(ebitmap_node_t));
		if (!new) {
			ebitmap_destroy(dst);
			return -ENOMEM;
		}
		memset(new, 0, sizeof(ebitmap_node_t));
		if (n1 && n2 && n1->startbit == n2->startbit) {
			new->startbit = n1->startbit;
			new->map = n1->map | n2->map;
			n1 = n1->next;
			n2 = n2->next;
		} else if (!n2 || (n1 && n1->startbit < n2->startbit)) {
			new->startbit = n1->startbit;
			new->map = n1->map;
			n1 = n1->next;
		} else {
			new->startbit = n2->startbit;
			new->map = n2->map;
			n2 = n2->next;
		}

		new->next = 0;
		if (prev)
			prev->next = new;
		else
			dst->node = new;
		prev = new;
	}

	dst->highbit = (e1->highbit > e2->highbit) ? e1->highbit : e2->highbit;
	return 0;
}


int ebitmap_cmp(ebitmap_t * e1, ebitmap_t * e2)
{
	ebitmap_node_t *n1, *n2;


	if (e1->highbit != e2->highbit)
		return 0;

	n1 = e1->node;
	n2 = e2->node;
	while (n1 && n2 &&
	       (n1->startbit == n2->startbit) &&
	       (n1->map == n2->map)) {
		n1 = n1->next;
		n2 = n2->next;
	}

	if (n1 || n2)
		return 0;

	return 1;
}


int ebitmap_cpy(ebitmap_t * dst, ebitmap_t * src)
{
	ebitmap_node_t *n, *new, *prev;


	ebitmap_init(dst);
	n = src->node;
	prev = 0;
	while (n) {
		new = (ebitmap_node_t *) kmalloc(sizeof(ebitmap_node_t));
		if (!new) {
			ebitmap_destroy(dst);
			return -ENOMEM;
		}
		memset(new, 0, sizeof(ebitmap_node_t));
		new->startbit = n->startbit;
		new->map = n->map;
		new->next = 0;
		if (prev)
			prev->next = new;
		else
			dst->node = new;
		prev = new;
		n = n->next;
	}

	dst->highbit = src->highbit;
	return 0;
}


int ebitmap_contains(ebitmap_t * e1, ebitmap_t * e2)
{
	ebitmap_node_t *n1, *n2;


	if (e1->highbit < e2->highbit)
		return 0;

	n1 = e1->node;
	n2 = e2->node;
	while (n1 && n2 && (n1->startbit <= n2->startbit)) {
		if (n1->startbit < n2->startbit) {
			n1 = n1->next;
			continue;
		}
		if ((n1->map & n2->map) != n2->map)
			return 0;

		n1 = n1->next;
		n2 = n2->next;
	}

	if (n2)
		return 0;

	return 1;
}


int ebitmap_get_bit(ebitmap_t * e, unsigned int bit)
{
	ebitmap_node_t *n;


	if (e->highbit < bit)
		return 0;

	n = e->node;
	while (n && (n->startbit <= bit)) {
		if ((n->startbit + MAPSIZE) > bit) {
			if (n->map & (MAPBIT << (bit - n->startbit)))
				return 1;
			else
				return 0;
		}
		n = n->next;
	}

	return 0;
}


int ebitmap_set_bit(ebitmap_t * e, unsigned int bit, int value)
{
	ebitmap_node_t *n, *prev, *new;


	prev = 0;
	n = e->node;
	while (n && n->startbit <= bit) {
		if ((n->startbit + MAPSIZE) > bit) {
			if (value) {
				n->map |= (MAPBIT << (bit - n->startbit));
			} else {
				n->map &= ~(MAPBIT << (bit - n->startbit));
				if (!n->map) {
					/* drop this node from the bitmap */

					if (!n->next) {
						/*
						 * this was the highest map
						 * within the bitmap
						 */
						if (prev)
							e->highbit = prev->startbit + MAPSIZE;
						else
							e->highbit = 0;
					}
					if (prev)
						prev->next = n->next;
					else
						e->node = n->next;

					kfree(n);
				}
			}
			return 0;
		}
		prev = n;
		n = n->next;
	}

	if (!value)
		return 0;

	new = (ebitmap_node_t *) kmalloc(sizeof(ebitmap_node_t));
	if (!new)
		return -ENOMEM;
	memset(new, 0, sizeof(ebitmap_node_t));

	new->startbit = bit & ~(MAPSIZE - 1);
	new->map = (MAPBIT << (bit - new->startbit));

	if (!n)
		/* this node will be the highest map within the bitmap */
		e->highbit = new->startbit + MAPSIZE;

	if (prev) {
		new->next = prev->next;
		prev->next = new;
	} else {
		new->next = e->node;
		e->node = new;
	}

	return 0;
}


void ebitmap_destroy(ebitmap_t * e)
{
	ebitmap_node_t *n, *temp;


	if (!e)
		return;

	n = e->node;
	while (n) {
		temp = n;
		n = n->next;
		kfree(temp);
	}

	e->highbit = 0;
	e->node = 0;
	return;
}


int ebitmap_read(ap_fbuf_t *fb, ebitmap_t * e, FILE *fp)
{
	int rc = EBITMAP_ERR;
	ebitmap_node_t *n, *l;
	__u32 *buf, mapsize, count, i;
	__u64 map;


	ebitmap_init(e);

	buf = ap_read_fbuf(fb, sizeof(__u32)*3, fp);
	if (!buf) {
		rc = EBITMAP_READ_ERR;
		goto out;
	}

	mapsize = le32_to_cpu(buf[0]);
	e->highbit = le32_to_cpu(buf[1]);
	count = le32_to_cpu(buf[2]);

	if (mapsize != MAPSIZE) {
		printk("security: ebitmap: map size %d does not match my size %zu (high bit was %d)\n", mapsize, MAPSIZE, e->highbit);
		goto out;
	}
	if (!e->highbit) {
		e->node = NULL;
		goto ok;
	}
	if (e->highbit & (MAPSIZE - 1)) {
		printk("security: ebitmap: high bit (%d) is not a multiple of the map size (%zu)\n", e->highbit, MAPSIZE);
		goto bad;
	}
	l = NULL;
	for (i = 0; i < count; i++) {
		buf = ap_read_fbuf(fb, sizeof(__u32), fp);
		if (!buf) {
			printk("security: ebitmap: truncated map\n");
			rc = EBITMAP_READ_ERR;
			goto bad;
		}
		n = (ebitmap_node_t *) kmalloc(sizeof(ebitmap_node_t));
		if (!n) {
			printk("security: ebitmap: out of memory\n");
			rc = -1;
			goto bad;
		}
		memset(n, 0, sizeof(ebitmap_node_t));

		n->startbit = le32_to_cpu(buf[0]);

		if (n->startbit & (MAPSIZE - 1)) {
			printk("security: ebitmap start bit (%d) is not a multiple of the map size (%zu)\n", n->startbit, MAPSIZE);
			goto bad_free;
		}
		if (n->startbit > (e->highbit - MAPSIZE)) {
			printk("security: ebitmap start bit (%d) is beyond the end of the bitmap (%zu)\n", n->startbit, (e->highbit - MAPSIZE));
			goto bad_free;
		}
		buf = ap_read_fbuf(fb, sizeof(__u64), fp);
		if (!buf) {
			printk("security: ebitmap: truncated map\n");
			rc = EBITMAP_READ_ERR;
			goto bad_free;
		}
		memcpy(&map, buf, sizeof(__u64));
		n->map = le64_to_cpu(map);

		if (!n->map) {
			printk("security: ebitmap: null map in ebitmap (startbit %d)\n", n->startbit);
			goto bad_free;
		}
		if (l) {
			if (n->startbit <= l->startbit) {
				printk("security: ebitmap: start bit %d comes after start bit %d\n", n->startbit, l->startbit);
				goto bad_free;
			}
			l->next = n;
		} else
			e->node = n;

		l = n;
	}

ok:
	rc = 0;
out:
	return rc;
bad_free:
	kfree(n);
bad:
	ebitmap_destroy(e);
	goto out;
}

/* FLASK */


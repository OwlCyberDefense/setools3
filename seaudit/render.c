/*
 * Author: Kevin Carr <kcarr@tresys.com>
 * October 10, 2003
 * 
 * render.c
 */

/*
 * functions to render the data in a message as text.
 */

#include "render.h"
#include "auditlog.h"
#include <string.h>
#include <stdlib.h>


static bool_t str_realloc(char *str, int sz)
{
	char *ptr;
	ptr = (char*)realloc(str, sizeof(char) * sz);
	if (ptr == NULL) {
		fprintf(stderr, "Out of memory");
		return FALSE;
	}
	str = ptr;
	return TRUE;
}
	

/*
 * get the rendered avc msg field data and return in str. the calling function must
 * free the returned string when finished */
int get_rendered_avc_data(msg_t *msg, char *str, const int avc_field)
{	
	char *data;
	char *val;
	int i;
	unsigned int ui;
	unsigned long ul;
	int sz;
	if (msg == NULL)
		return -1;
	if (msg->msg_type != AVC_MSG)
		return -2;

	switch (avc_field) {
	case AVC_MSG_FIELD:
		if (msg->msg_data.avc_msg->msg == AVC_DENIED)
			sz = strlen("denied") + strlen("msg=") + 1;
		else /* msg->msg_data.avc_msg->msg == AVC_GRANTED */
			sz = strlen("granted") + strlen("msg=") +1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "msg=");
		if (msg->msg_data.avc_msg->msg == AVC_DENIED)
			str = strcat(str, "denied");
		else /* msg->msg_data.avc_msg->msg == AVC_GRANTED */
			str = strcat(str, "granted");
		break;
	case AVC_EXE_FIELD:
		data = msg->msg_data.avc_msg->exe;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("exe=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "exe=");
		str = strcat(str, data);
		break;
	case AVC_PATH_FIELD:
		data = msg->msg_data.avc_msg->path;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("path=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "path=");
		str = strcat(str, data);
		break;
	case AVC_DEV_FIELD:
		data = msg->msg_data.avc_msg->dev;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("dev=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "dev=");
		str = strcat(str, data);
		break;
	case AVC_OBJ_CLASS_FIELD:
	  //return "tclass=";
	  // TODO: implement rendering of objs/perms
	case AVC_PERM_FIELD:
	  //return "";
	case AVC_INODE_FIELD:
		ul = msg->msg_data.avc_msg->inode;
		sz = strlen("ino=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "ino=");
		ultoa(ul, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_PID_FIELD:
		ui = msg->msg_data.avc_msg->pid;
		sz = strlen("pid=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "pid=");
		utoa(ui, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_SRC_SID_FIELD:
		ui = msg->msg_data.avc_msg->src_sid;
		sz = strlen("ssid=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "ssid=");
		utoa(ui, val, 10);
		str = strcat(str, val);
		free(val);
		break; 
	case AVC_TGT_SID_FIELD:
		ui = msg->msg_data.avc_msg->tgt_sid;
		sz = strlen("tsid=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "tsid=");
		utoa(ui, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_COMM_FIELD:
		data = msg->msg_data.avc_msg->comm;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("comm=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "comm=");
		str = strcat(str, data);
		break;
	case AVC_NETIF_FIELD:
		data = msg->msg_data.avc_msg->netif;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("netif=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "netif=");
		str = strcat(str, data);
		break;
	case AVC_KEY_FIELD:
		i = msg->msg_data.avc_msg->key;
		sz = strlen("key=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "key=");
		itoa(i, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_CAPABILITY_FIELD:
		i = msg->msg_data.avc_msg->capability;
		sz = strlen("capability=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "capability=");
		itoa(i, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_PORT_FIELD:
		i = msg->msg_data.avc_msg->port;
		sz = strlen("port=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "port=");
		itoa(i, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_LPORT_FIELD:
		i = msg->msg_data.avc_msg->lport;
		sz = strlen("lport=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "lport=");
		itoa(i, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_FPORT_FIELD:
		i = msg->msg_data.avc_msg->fport;
		sz = strlen("fport=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "fport=");
		itoa(i, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_DEST_FIELD:
		i = msg->msg_data.avc_msg->dest;
		sz = strlen("dest=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "dest=");
		itoa(i, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_SOURCE_FIELD:
		i = msg->msg_data.avc_msg->fport;
		sz = strlen("source=") + 8*sizeof(int) + 1;
		if (!str_realloc(str, sz))
			return -4;
		if (!str_realloc(val, 8*sizeof(int) + 1))
			return -4;
		strcpy(str, "source=");
		itoa(i, val, 10);
		str = strcat(str, val);
		free(val);
		break;
	case AVC_LADDR_FIELD:
		data = msg->msg_data.avc_msg->laddr;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("laddr=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "laddr=");
		str = strcat(str, data);
		break;
	case AVC_FADDR_FIELD:
		data = msg->msg_data.avc_msg->faddr;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("faddr=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "faddr=");
		str = strcat(str, data);
		break;
	case AVC_DADDR_FIELD:
		data = msg->msg_data.avc_msg->daddr;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("daddr=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "daddr=");
		str = strcat(str, data);
		break;
	case AVC_SADDR_FIELD:
		data = msg->msg_data.avc_msg->saddr;
		if (!data)
			return -3;
		sz = strlen(data) + strlen("saddr=") + 1;
		if (!str_realloc(str, sz))
			return -4;
		strcpy(str, "saddr=");
		str = strcat(str, data);
		break;
	case AVC_SRC_CONTEXT:
	  //return "scontext=";
	case AVC_TGT_CONTEXT:
	  //return "tcontext=";
		break;
	default:
		return -5;
	}	
	return 0;
}

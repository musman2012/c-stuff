/*
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation version 2.1
 *      of the License.
 *
 */

#include <netlink/route/link.h>
#include <netlink/route/tc.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/qdisc/sfq.h>
#include <netlink/route/cls/u32.h>
#include <netlink/route/classifier.h>
#include <netlink/route/class.h>
#include <linux/if_ether.h>

#include <netlink/attr.h>
//#include "include/rtnl_u32.h"

#include <stdio.h>
#include <string.h>
//#include "include/rtnl_u32_addon.h"

#define 	TC_HANDLE(maj, min)   (TC_H_MAJ((maj) << 16) | TC_H_MIN(min))

/* some functions are copied from iproute-tc tool */
void reverse2(char* Str)
{
        int len = strlen(Str) - 1, length = strlen(Str); char temp, temp2;

        for (int i = 0; i < length; i = i+2)
        {
                temp = Str[i];
                temp2 = Str[i+1];
                Str[1 + i] = temp;
                Str[i] = temp2;
        }
}

void reverse(char* Str)
{
        int len = strlen(Str) - 1, length = strlen(Str); char temp, temp2;
        length = length/2;

        for (int i = 0; i < length; i++)
        {
                temp = Str[i];
                temp2 = Str[len - i];
                Str[len - i] = temp;
                Str[i] = temp2;
        }
}

void ip_to_hexa(int addr, char *ptr)
{
    char str[15], temp[15];

    // convert integer to string for reverse
    sprintf(str, "0x%08x", addr);
    sprintf(temp, "%08x", addr);
    reverse(temp);
    reverse2(temp);
    sprintf(str, "0x%s", temp);

    strcpy(ptr, str);
}

int get_u32(__u32 *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFFFFFFFFUL)
		return -1;
	*val = res;
	return 0;
}

int get_u32_handle(__u32 *handle, const char *str)
{
	__u32 htid=0, hash=0, nodeid=0;
	char *tmp = strchr(str, ':');
        
	if (tmp == NULL) {
		if (memcmp("0x", str, 2) == 0)
			return get_u32(handle, str, 16);
		return -1;
	}
	htid = strtoul(str, &tmp, 16);
	if (tmp == str && *str != ':' && *str != 0)
		return -1;
	if (htid>=0x1000)
		return -1;
	if (*tmp) {
		str = tmp+1;
		hash = strtoul(str, &tmp, 16);
		if (tmp == str && *str != ':' && *str != 0)
			return -1;
		if (hash>=0x100)
			return -1;
		if (*tmp) {
			str = tmp+1;
			nodeid = strtoul(str, &tmp, 16);
			if (tmp == str && *str != 0)
				return -1;
			if (nodeid>=0x1000)
				return -1;
		}
	}
	*handle = (htid<<20)|(hash<<12)|nodeid;
	return 0;
}

uint32_t get_u32_parse_handle(const char *cHandle)
{
	uint32_t handle=0;

	if(get_u32_handle(&handle, cHandle)) {
		printf ("Illegal \"ht\"\n");
		return -1;
	}

	if (handle && TC_U32_NODE(handle)) {
		printf("\"link\" must be a hash table.\n");
		return -1;
	}
	return handle;
}

int get_tc_classid(__u32 *h, const char *str)
{
	__u32 maj, min;
	char *p;

	maj = TC_H_ROOT;
	if (strcmp(str, "root") == 0)
		goto ok;
	maj = TC_H_UNSPEC;
	if (strcmp(str, "none") == 0)
		goto ok;
	maj = strtoul(str, &p, 16);
	if (p == str) {
		maj = 0;
		if (*p != ':')
			return -1;
	}
	if (*p == ':') {
		if (maj >= (1<<16))
			return -1;
		maj <<= 16;
		str = p+1;
		min = strtoul(str, &p, 16);
		if (*p != 0)
			return -1;
		if (min >= (1<<16))
			return -1;
		maj |= min;
	} else if (*p != 0)
		return -1;

ok:
	*h = maj;
	return 0;
}

/* 
 * Function that adds a new filter and attach it to a hash table
 *
 
int u32_add_filter_on_ht(struct nl_sock *sock, struct rtnl_link *rtnlLink, uint32_t prio, 
		uint32_t keyval, uint32_t keymask, int keyoff, int keyoffmask,
		uint32_t htid, uint32_t classid
)
{
    struct rtnl_cls *cls;
    int err;

    //printf("Key Val  : 0x%x\n", keyval);
    //printf("Key Mask : 0x%x\n", keymask);

    cls=rtnl_cls_alloc();
    if (!(cls)) {
        printf("Can not allocate classifier\n");
        nl_socket_free(sock);
        exit(1);
    }
    
    rtnl_tc_set_link(TC_CAST(cls), rtnlLink);

    if ((err = rtnl_tc_set_kind(TC_CAST(cls), "u32"))) {
        printf("Can not set classifier as u32\n");
        return 1;
    }

    rtnl_cls_set_prio(cls, prio);
    rtnl_cls_set_protocol(cls, ETH_P_IP);

    rtnl_tc_set_parent(TC_CAST(cls), TC_HANDLE(1, 0));

    rtnl_u32_set_hashtable(cls, htid);

    rtnl_u32_add_key_uint32(cls, keyval, keymask, keyoff, keyoffmask); // 10.0.0.0/8 

    rtnl_u32_set_classid(cls, classid);
    
    rtnl_u32_set_cls_terminal(cls);

    if ((err = rtnl_cls_add(sock, cls, NLM_F_CREATE))) {
        printf("Can not add classifier: %s\n", nl_geterror(err));
        return -1;
    }
    rtnl_cls_put(cls);
    return 0;

}
*/

/*
 * Function that adds a new simple filter and sets the required parameters (Separate code)
 *
 */

int u32_add_filter(struct nl_sock *sock, struct rtnl_link *rtnlLink, uint32_t prio, uint32_t direction, uint32_t ip, uint32_t flow_id)
{
	struct rtnl_cls * pFilter = rtnl_cls_alloc();
	uint32_t parent_handle = 1, flow_handle = 1, err = 0;    // using flow_handle as flow id
	char *pBuffer = NULL;
	rtnl_tc_set_link(TC_CAST(pFilter), rtnlLink);		// rtnl_cls_set_ifindex(pFilter, m_networkDeviceIdx); /* eth0 */

	if ((err = rtnl_tc_set_kind(TC_CAST(pFilter), "u32"))) {
        	printf("Can not set classifier as u32\n");
        	return 1;
    	}
	printf("Set classifier as u32\n");
	
//	rtnl_cls_set_kind(TC_CAST(pFilter), "u32");
	rtnl_cls_set_prio(pFilter, prio);
	rtnl_cls_set_protocol(pFilter, ETH_P_IP);

	// setting parent class id
	rtnl_tc_str2handle("1:0", &parent_handle);   // put parent id here, all filters would be applied on the same parent, i.e. ROOT
//	rtnl_cls_set_parent(TC_CAST(pFilter), parent_handle);
	rtnl_tc_set_parent(TC_CAST(pFilter), TC_HANDLE(1, 0));

	// source port filter (Important thing to note. This is for adding a filter w.r.t source port)
	printf("ATTENTION: Dil thaam kay dekho IP which is %x \n", ip);
	rtnl_u32_add_key_uint16(pFilter, ip, 0xffffffff, direction, 0);

	// rtnl_u32_add_key_uint32(cls, n,  0xffffffff, 12, 0); 12 --> source IP (have to keep first one, and last three as it is. Just put n = IP in 0xNN format)
	// rtnl_u32_add_key_uint32(cls, n,  0xffffffff, 16, 0); 16 --> dest IP
	printf("Filter 1/2\n");

	// setting flowid  --> ToDo: Correct pBuffer
	pBuffer = (char *) malloc( sizeof(char) * ( sizeof(flow_id) + 4 ) );
	sprintf(pBuffer, "1:%i", flow_id); /* flowid 1:20 --- Here parentId would be replaced by LIVE, VOD ID or 15 */
	rtnl_tc_str2handle(pBuffer, &flow_handle);
	printf("Filter str2handler completed.\n");
	rtnl_u32_set_classid(pFilter, flow_handle);
	printf("Filter classid set.\n");

	// add filter
	if ((err = rtnl_cls_add(sock, pFilter, NLM_F_CREATE))){
		// printf("Can not add classifier: %s\n", nl_geterror(err));
		printf("Can not add classifier. /n ");
        	return -1;
    	}
	printf("Added classifier\n");
    	rtnl_cls_put(pFilter);
    	return 0;
}


/* 
 * Function that adds a new filter and attach it to a hash table 
 * and set next hash table link with hash mask
 *
 
int u32_add_filter_on_ht_with_hashmask(struct nl_sock *sock, struct rtnl_link *rtnlLink, uint32_t prio, 
	    uint32_t keyval, uint32_t keymask, int keyoff, int keyoffmask,
	    uint32_t htid, uint32_t htlink, uint32_t hmask, uint32_t hoffset
)
{
    struct rtnl_cls *cls;
    int err;

    //printf("Key Val  : 0x%x\n", keyval);
    //printf("Key Mask : 0x%x\n", keymask);

    cls=rtnl_cls_alloc();
    if (!(cls)) {
        printf("Can not allocate classifier\n");
        nl_socket_free(sock);
        exit(1);
    }
    
    rtnl_tc_set_link(TC_CAST(cls), rtnlLink);

    if ((err = rtnl_tc_set_kind(TC_CAST(cls), "u32"))) {
        printf("Can not set classifier as u32\n");
        return 1;
    }

    rtnl_cls_set_prio(cls, prio);
    rtnl_cls_set_protocol(cls, ETH_P_IP);

    rtnl_tc_set_parent(TC_CAST(cls), TC_HANDLE(1, 0));
    
    if (htid)
	rtnl_u32_set_hashtable(cls, htid);

    rtnl_u32_add_key_uint32(cls, keyval, keymask, keyoff, keyoffmask);

    rtnl_u32_set_hashmask(cls, hmask, hoffset);

    rtnl_u32_set_link(cls, htlink);


    if ((err = rtnl_cls_add(sock, cls, NLM_F_CREATE))) {
        printf("Can not add classifier: %s\n", nl_geterror(err));
        return -1;
    }
    rtnl_cls_put(cls);
    return 0;
}
*/

/* 
 * function that creates a new hash table 
 */
int u32_add_ht(struct nl_sock *sock, struct rtnl_link *rtnlLink, uint32_t prio, uint32_t htid, uint32_t divisor)
{

    int err;
    struct rtnl_cls *cls;

    cls=rtnl_cls_alloc();
    if (!(cls)) {
        printf("Can not allocate classifier\n");
        nl_socket_free(sock);
        exit(1);
    }
    
    rtnl_tc_set_link(TC_CAST(cls), rtnlLink);

    if ((err = rtnl_tc_set_kind(TC_CAST(cls), "u32"))) {
        printf("Can not set classifier as u32\n");
        return 1;
    }

    rtnl_cls_set_prio(cls, prio);
    rtnl_cls_set_protocol(cls, ETH_P_IP);
    rtnl_tc_set_parent(TC_CAST(cls), TC_HANDLE(1, 0));

    rtnl_u32_set_handle(cls, htid, 0x0, 0x0);
    //printf("htid: 0x%X\n", htid);
    rtnl_u32_set_divisor(cls, divisor);

    if ((err = rtnl_cls_add(sock, cls, NLM_F_CREATE))) {
        printf("Can not add classifier: %s\n", nl_geterror(err));
        return -1;
    }
    rtnl_cls_put(cls);
    return 0;
}

/*
 * function that adds a new HTB qdisc and set the default class for unclassified traffic
 */
int qdisc_add_HTB(struct nl_sock *sock, struct rtnl_link *rtnlLink, uint32_t defaultClass)
{
    
    struct rtnl_qdisc *qdisc;
    int err;
    
    /* Allocation of a qdisc object */
    if (!(qdisc = rtnl_qdisc_alloc())) {
        printf("Can not allocate Qdisc\n");
	return -1;
    }

    //rtnl_tc_set_ifindex(TC_CAST(qdisc), master_index);
    rtnl_tc_set_link(TC_CAST(qdisc), rtnlLink);
    rtnl_tc_set_parent(TC_CAST(qdisc), TC_H_ROOT);

    //delete the qdisc
    //printf("Delete current qdisc\n");
    rtnl_qdisc_delete(sock, qdisc);
    //rtnl_qdisc_put(qdisc);

    //add a HTB qdisc
    //printf("Add a new HTB qdisc\n");
    rtnl_tc_set_handle(TC_CAST(qdisc), TC_HANDLE(1,0));

    if ((err = rtnl_tc_set_kind(TC_CAST(qdisc), "htb"))) {
        printf("Can not allocate HTB\n");
	return -1;
    }

    /* Set default class for unclassified traffic */
    //printf("Set default class for unclassified traffic\n");
    rtnl_htb_set_defcls(qdisc, TC_HANDLE(1, defaultClass));
    rtnl_htb_set_rate2quantum(qdisc, 1);

    /* Submit request to kernel and wait for response */
    if ((err = rtnl_qdisc_add(sock, qdisc, NLM_F_CREATE))) {
        printf("Can not allocate HTB Qdisc\n");
	return -1;
    }

    /* Return the qdisc object to free memory resources */
    rtnl_qdisc_put(qdisc);

    return 0;
}

/*
 * function that adds a new HTB class and set its parameters
 */
int class_add_HTB(struct nl_sock *sock, struct rtnl_link *rtnlLink, 
		    uint32_t parentMaj, uint32_t parentMin,
		    uint32_t childMaj,  uint32_t childMin, 
		    uint64_t rate, uint64_t ceil,
		    uint32_t burst, uint32_t cburst, 
		    uint32_t prio
)
{
    int err;
    struct rtnl_class *class;
    //struct rtnl_class *class = (struct rtnl_class *) tc;

    //create a HTB class 
    //class = (struct rtnl_class *)rtnl_class_alloc();
    if (!(class = rtnl_class_alloc())) {
        printf("Can not allocate class object\n");
        return 1;
    }
    //
    rtnl_tc_set_link(TC_CAST(class), rtnlLink);
    //add a HTB qdisc
    //printf("Add a new HTB class with 0x%X:0x%X on parent 0x%X:0x%X\n", childMaj, childMin, parentMaj, parentMin);
    rtnl_tc_set_parent(TC_CAST(class), TC_HANDLE(parentMaj, parentMin));
    rtnl_tc_set_handle(TC_CAST(class), TC_HANDLE(childMaj, childMin));

    if ((err = rtnl_tc_set_kind(TC_CAST(class), "htb"))) {
        printf("Can not set HTB to class\n");
        return 1;
    }

    //printf("set HTB class prio to %u\n", prio);
    rtnl_htb_set_prio((struct rtnl_class *)class, prio);

    if (rate) {
	//rate=rate/8;
	rtnl_htb_set_rate(class, rate);
    }
    if (ceil) {
	//ceil=ceil/8;
	rtnl_htb_set_ceil(class, ceil);
    }
    
    if (burst) {
	//printf ("Class HTB: set rate burst: %u\n", burst);
        rtnl_htb_set_rbuffer(class, burst);
    }
    if (cburst) {
	//printf ("Class HTB: set rate cburst: %u\n", cburst);
        rtnl_htb_set_cbuffer(class, cburst);
    }
    /* Submit request to kernel and wait for response */
    if ((err = rtnl_class_add(sock, class, NLM_F_CREATE))) {
        printf("Can not allocate HTB Qdisc\n");
        return 1;
    }
    rtnl_class_put(class);
    return 0;
}

/*
 * function that adds a HTB root class and set its parameters
 */
int class_add_HTB_root(struct nl_sock *sock, struct rtnl_link *rtnlLink, 
			uint64_t rate, uint64_t ceil,
			uint32_t burst, uint32_t cburst
)
{
    int err;
    struct rtnl_class *class;

    //create a HTB class 
    class = (struct rtnl_class *)rtnl_class_alloc();
    //class = rtnl_class_alloc();
    if (!class) {
        printf("Can not allocate class object\n");
        return 1;
    }
    //
    rtnl_tc_set_link(TC_CAST(class), rtnlLink);
    rtnl_tc_set_parent(TC_CAST(class), TC_H_ROOT);
    //add a HTB class
    //printf("Add a new HTB ROOT class\n");
    rtnl_tc_set_handle(TC_CAST(class), 1);

    if ((err = rtnl_tc_set_kind(TC_CAST(class), "htb"))) {
        printf("Can not set HTB to class\n");
        return 1;
    }

    if (rate) {
	//rate=rate/8;
	rtnl_htb_set_rate(class, rate);
    }
    if (ceil) {
	//ceil=ceil/8;
	rtnl_htb_set_ceil(class, ceil);
    }
    
    if (burst) {
        rtnl_htb_set_rbuffer(class, burst);
    }
    if (cburst) {
        rtnl_htb_set_cbuffer(class, cburst);
    }
    
    /* Submit request to kernel and wait for response */
    if ((err = rtnl_class_add(sock, class, NLM_F_CREATE))) {
        printf("Can not allocate HTB Qdisc\n");
        return 1;
    }
    rtnl_class_put(class);
    return 0;
}

/*
 * function that adds a new SFQ qdisc as a leaf for a HTB class
 */
int qdisc_add_SFQ_leaf(struct nl_sock *sock, struct rtnl_link *rtnlLink,
			uint32_t parentMaj, uint32_t parentMin, 
			int quantum, int limit, int perturb
)
{
    int err;
    struct rtnl_qdisc *qdisc;

    if (!(qdisc = rtnl_qdisc_alloc())) {
        printf("Can not allocate qdisc object\n");
        return 1;
    }
    rtnl_tc_set_link(TC_CAST(qdisc), rtnlLink);
    rtnl_tc_set_parent(TC_CAST(qdisc), TC_HANDLE(parentMaj, parentMin));

    rtnl_tc_set_handle(TC_CAST(qdisc), TC_HANDLE(parentMin,0));

    if ((err = rtnl_tc_set_kind(TC_CAST(qdisc), "sfq"))) {
        printf("Can not set SQF class\n");
        return 1;
    }

    if(quantum) {
//        rtnl_sfq_set_quantum(qdisc, quantum);
    } else {
//        rtnl_sfq_set_quantum(qdisc, 16000); // tc default value
    }
    if(limit) {
        rtnl_sfq_set_limit(qdisc, limit); // default is 127
    }
    if(perturb) {
        rtnl_sfq_set_perturb(qdisc, perturb); // default never perturb the hash
    }

    /* Submit request to kernel and wait for response */
    if ((err = rtnl_qdisc_add(sock, qdisc, NLM_F_CREATE))) {
        printf("Can not allocate SFQ qdisc\n");
	return -1;
    }

    /* Return the qdisc object to free memory resources */
    rtnl_qdisc_put(qdisc);
    return 0;
}




void make_tc_tree()
{
    struct nl_sock *sock;
    struct rtnl_link *link;

    //struct rtnl_qdisc *qdisc;
    //struct rtnl_class *class;
    //struct rtnl_cls   *cls;

    uint32_t ht, htlink, htid, direction, classid;
    //uint32_t hash, hashmask, nodeid, divisor, handle;
    //struct rtnl_u32 *f_u32;
    char chashlink[16]="";
    int vod_found = 0, live_found = 0;					// found = 0 means it was not found. 1 means service found
    uint32_t root_class_rate = 12500000, root_class_ceil = 12500000;
    uint32_t internet_rate = 10000, internet_ceil = 10000;			// needs to be Internet
    uint32_t live_rate = 200000, live_ceil = 200000;			// needs to be VoD
    uint32_t vod_rate = 100000, vod_ceil = 100000;			// needs to be LIVE
    uint32_t burst = 25000, c_burst = 25000, src = 12, dst = 16;
    uint32_t quantum = 16000, perturb = 10, limit = 0; 					// quantum = how much bytes to serve from leaf at once
    uint32_t live_class_id = 0x5, live_ip = 0xac1ee601;					// 0xac1ee601 = 172.30.230.1
    uint32_t vod_class_id = 0x6, vod_ip = 0xac1edc01;                                 	// 0xac1edc01 = 172.30.220.1

    char* ip_str_live = "172.30.230.1"; char* ip_str_vod = "172.30.220.76";
    int addr_live = inet_addr(ip_str_live);
    int addr_vod = inet_addr(ip_str_vod);

    char *hex_addr_live = NULL;
    hex_addr_live = (char *) malloc( sizeof(char) * ( 20 ) );
    ip_to_hexa(addr_live, hex_addr_live);
    live_ip = (int) strtol(hex_addr_live, NULL, 0);
//    live_ip = hex_addr_live;
    printf("IP in hex form is>>>>>>>>>>>>>>>>>>> %x\n", live_ip);

    char *hex_addr_vod = NULL;
    hex_addr_vod = (char *) malloc( sizeof(char) * ( 20 ) );
    ip_to_hexa(addr_vod, hex_addr_vod);
    vod_ip = (int) strtol(hex_addr_vod, NULL, 0);
//    live_ip = hex_addr_live;
    printf("IP in hex form is>>>>>>>>>>>>>>>>>>> %x\n", vod_ip);

    // Here parse attributes to see if LIVE and VoD present and set values equal to 1
    vod_found = 1;
    live_found = 1;

    if(vod_found = 0) {
	vod_rate = 1;
    }
    if(live_found = 0) {
	live_rate = 1;
    }

    //uint64_t drops, qlen;

    //int master_index;
    int err;

    //uint64_t rate=0, ceil=0;

    struct nl_cache *link_cache;

    if (!(sock = nl_socket_alloc())) {
        printf("Unable to allocate netlink socket\n");
        exit(1);
    }
    printf("Allocated netlink socket\n");

    if ((err = nl_connect(sock, NETLINK_ROUTE)) < 0 ) {
        printf("Nu s-a putut conecta la NETLINK!\n");
        nl_socket_free(sock);
        exit(1);
    }
    printf("Conntected la NETLINK!\n");

    if ((err = rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache)) < 0) {
        printf("Unable to allocate link cache: %s\n",
                             nl_geterror(err));
        nl_socket_free(sock);
        exit(1);
    }
    printf("Allocate link cache.\n");

    /* lookup interface index of eth0 */
    if (!(link = rtnl_link_get_by_name(link_cache, "ppp0"))) { 		// Instead of ifb0, get the if name from the code itself
        /* error */
        printf("Interface not founda  \n");
        nl_socket_free(sock);
        exit(1);
    }
    printf("Interface found >>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<< \n");

    err=qdisc_add_HTB(sock, link, 0xffff);				// set 0xffff = 65535 (ALL ONES) as default class, use internet rate there
    
    //printf("Add ROOT HTB class\n");
    err = class_add_HTB_root(sock, link, root_class_rate, root_class_ceil, burst, c_burst);
    err = class_add_HTB(sock, link, 1, 0, 1, 0xffff, internet_rate, internet_ceil, burst, c_burst, 5);
    err = qdisc_add_SFQ_leaf(sock, link, 1, 0xffff, quantum, limit, perturb);
    err = class_add_HTB(sock, link, 1, 1, 1, live_class_id, live_rate, live_ceil, burst, c_burst, 5);		// live  0x5 = 5
    err = qdisc_add_SFQ_leaf(sock, link, 1, live_class_id, quantum, limit, perturb);
    err = class_add_HTB(sock, link, 1, 1, 1, vod_class_id, vod_rate, vod_ceil, burst, c_burst, 5);	// vod 0x6 = 6
    err = qdisc_add_SFQ_leaf(sock, link, 1, vod_class_id, quantum, limit, perturb);
    // int u32_add_filter(struct nl_sock *sock, struct rtnl_link *rtnlLink, uint32_t prio,
	//                 uint32_t direction, uint32_t ip, uint32_t flow_id)
    printf("Adding filters now.....\n");
    // adding filters now
    err = u32_add_filter(sock, link, 1, src, live_ip, live_class_id);
    err = u32_add_filter(sock, link, 1, dst, live_ip, live_class_id);
//    err = u32_add_filter(sock, link2, 1, dst, live_ip, live_class_id); (repeat for IFB_IF)
    printf("Filter one added\n");
    err = u32_add_filter(sock, link, 1, src, vod_ip, vod_class_id);
    printf("Filter two added\n");

    //printf("Add main hash table\n");

    direction = 16;
}

int main()
{
    make_tc_tree();
    return 0;
}


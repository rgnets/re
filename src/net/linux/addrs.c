/**
 * @file linux/addrs.c Get interface addresses (See rtnetlink(7))
 *
 * Copyright (C) 2024 Sebastian Reimers
 */

#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include <re_types.h>
#include <re_fmt.h>
#include <re_list.h>
#include <re_mem.h>
#include <re_sa.h>
#include <re_net.h>
#include "macros.h"

#define DEBUG_MODULE "linuxaddrs"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

enum { RE_NETLINK_BUFSZ = 8192 };

struct iff_up_e {
	struct le le;
	uint32_t ifi_index;
};

/* Define the interface bindings structure */
struct interface_bindings {
	struct list bindings_list;  /* List of bindings */
};

/* Structure for each binding entry */
struct binding_entry {
	struct le le;              /* List entry */
	uint32_t if_index;
	struct sa addr;
	uint32_t table;
};

/* Function to check if a binding is valid */
static bool is_valid_binding(const struct interface_bindings *bindings,
			   uint32_t if_index, const struct sa *addr)
{
	struct le *le;

	if (!bindings || !addr)
		return true;  /* If no bindings defined, allow all */

	LIST_FOREACH(&bindings->bindings_list, le) {
		struct binding_entry *bind = le->data;
		if (bind->if_index == if_index &&
		    sa_cmp(&bind->addr, addr, SA_ADDR))
			return true;
	}
	return false;
}




static void parse_rtattr(struct rtattr *tb[], struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (IFA_MAX + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= IFA_MAX) {
			tb[rta->rta_type] = rta;
		}
		rta = RTA_NEXT(rta, len);
	}
}


static bool is_ipv6_deprecated(uint32_t flags)
{
	if (flags & (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC | IFA_F_DADFAILED |
		     IFA_F_DEPRECATED))
		return true;

	return false;
}


static int parse_msg_link(struct nlmsghdr *msg, ssize_t len,
			  struct list *iff_up_l)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;

	for (nlh = msg; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type == NLMSG_DONE) {
			return 0;
		}
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			DEBUG_WARNING("netlink recv error\n");
			return EBADMSG;
		}

		ifi = NLMSG_DATA(nlh);

		if (!(ifi->ifi_flags & IFF_UP))
			continue;

		struct iff_up_e *e = mem_zalloc(sizeof(struct iff_up_e), NULL);
		if (!e)
			return ENOMEM;

		e->ifi_index = ifi->ifi_index;

		list_append(iff_up_l, &e->le, e);
	}

	return EALREADY;
}


static int parse_msg_addr(struct nlmsghdr *msg, ssize_t len, net_ifaddr_h *ifh,
			 struct list *iff_up_l, void *arg,
			 const struct interface_bindings *bindings)
{
	struct nlmsghdr *nlh;
	for (nlh = msg; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct sa sa;
		uint32_t flags;
		bool iff_up = false;
		void *addr;
		char if_name[IF_NAMESIZE];

		if (nlh->nlmsg_type == NLMSG_DONE) {
			return 0;
		}
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			DEBUG_WARNING("netlink recv error\n");
			return EBADMSG;
		}

		struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
		struct rtattr *rta_tb[IFA_MAX + 1];

		parse_rtattr(rta_tb, IFA_RTA(ifa),
			     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

		if (!rta_tb[IFA_ADDRESS])
			continue;

		struct le *le;
		LIST_FOREACH(iff_up_l, le)
		{
			struct iff_up_e *e = le->data;
			if (ifa->ifa_index == e->ifi_index) {
				iff_up = true;
				break;
			}
		}

		if (!iff_up)
			continue;

		if (rta_tb[IFA_FLAGS] && ifa->ifa_family == AF_INET6) {
			flags = *(uint32_t *)RTA_DATA(rta_tb[IFA_FLAGS]);
			if (is_ipv6_deprecated(flags))
				continue;
		}

		if (rta_tb[IFA_LOCAL])
			/* looks like point-to-point network, use local
			 * address, instead of peer */
			addr = RTA_DATA(rta_tb[IFA_LOCAL]);
		else
			addr = RTA_DATA(rta_tb[IFA_ADDRESS]);

		if (ifa->ifa_family == AF_INET) {
			sa_init(&sa, AF_INET);
			sa.u.in.sin_addr.s_addr = *(uint32_t *)addr;
		}
		else if (ifa->ifa_family == AF_INET6) {
			sa_set_in6(&sa, addr, 0);
			sa_set_scopeid(&sa, ifa->ifa_index);
		}
		else
			continue;

		if (!if_indextoname(ifa->ifa_index, if_name))
			continue;

		if (bindings && !is_valid_binding(bindings, ifa->ifa_index, &sa))
			continue;

		if (ifh(if_name, &sa, arg))
			return 0;
	}

	return EALREADY;
}



static int net_netlink_addrs_ext(net_ifaddr_h *ifh, void *arg, uint32_t table)
{
	int err = 0;
	re_sock_t sock;
	ssize_t len;
	struct list iff_up_l = LIST_INIT;
	struct interface_bindings bindings;

	/* Initialize the bindings list */
	list_init(&bindings.bindings_list);


	struct {
		struct nlmsghdr nlh;
		union {
			struct ifinfomsg ifi;
			struct ifaddrmsg ifa;
			struct rtmsg rtm;
		} u;
		char buf[1024];
	} req;

	if (!ifh)
		return EINVAL;

	void *buffer = mem_zalloc(RE_NETLINK_BUFSZ, NULL);
	if (!buffer)
		return ENOMEM;

	if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		err = errno;
		DEBUG_WARNING("socket failed %m\n", err);
		return err;
	}

	struct timeval timeout = {5, 0};
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	/* First get routes to check interface bindings */
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type = RTM_GETROUTE;
	req.u.rtm.rtm_family = AF_UNSPEC;
	req.u.rtm.rtm_table = table;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		err = errno;
		goto out;
	}

	/* Process route responses to build interface binding map */
	while ((len = recv(sock, buffer, RE_NETLINK_BUFSZ, 0)) > 0) {
		struct nlmsghdr *nlh;
		for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len);
		     nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_type == NLMSG_DONE)
				break;

			struct rtmsg *rtm = NLMSG_DATA(nlh);
			struct rtattr *rta_tb[RTA_MAX + 1];
			parse_rtattr(rta_tb, RTM_RTA(rtm),
				    RTM_PAYLOAD(nlh));

			/* Store interface binding info */
			/* When processing routes: */
	if (rta_tb[RTA_OIF] && rta_tb[RTA_PREFSRC]) {
		struct binding_entry *binding;
		binding = mem_zalloc(sizeof(*binding), NULL);
		if (!binding)
			continue;

		binding->if_index = *(uint32_t *)RTA_DATA(rta_tb[RTA_OIF]);
		binding->table = rtm->rtm_table;
		/* Set the preferred source address */
		if (rtm->rtm_family == AF_INET) {
			sa_init(&binding->addr, AF_INET);
			binding->addr.u.in.sin_addr.s_addr =
				*(uint32_t *)RTA_DATA(rta_tb[RTA_PREFSRC]);
		}
		else if (rtm->rtm_family == AF_INET6) {
			sa_set_in6(&binding->addr,
				  RTA_DATA(rta_tb[RTA_PREFSRC]), 0);
		}

		list_append(&bindings.bindings_list, &binding->le, binding);
	}

		}
	}

	/* Continue with GETLINK */
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type = RTM_GETLINK;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		err = errno;
		DEBUG_WARNING("GETLINK send failed %m\n", err);
		goto out;
	}

	while ((len = recv(sock, buffer, RE_NETLINK_BUFSZ, 0)) > 0) {
		err = parse_msg_link((struct nlmsghdr *)buffer, len, &iff_up_l);
		if (err != EALREADY)
			break;
	}
	if (err)
		goto out;

	if (len < 0) {
		err = errno;
		DEBUG_WARNING("GETLINK recv failed %m\n", err);
		goto out;
	}

	/* GETADDR */
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_type = RTM_GETADDR;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		err = errno;
		DEBUG_WARNING("GETADDR send failed %m\n", err);
		goto out;
	}

	while ((len = recv(sock, buffer, RE_NETLINK_BUFSZ, 0)) > 0) {
			err = parse_msg_addr((struct nlmsghdr *)buffer, len, ifh,
			    &iff_up_l, arg,
			    list_count(&bindings.bindings_list) > 0 ? &bindings : NULL);

		if (err != EALREADY)
			break;
	}
	if (err)
		goto out;

	if (len < 0) {
		err = errno;
		DEBUG_WARNING("GETADDR recv failed %m\n", err);
	}

out:
	close(sock);
	list_flush(&iff_up_l);
	/* Free the bindings list */
	list_flush(&bindings.bindings_list);
	mem_deref(buffer);

	return err;
}


/* Wrapper that tries multiple routing tables */
int net_netlink_addrs(net_ifaddr_h *ifh, void *arg)
{
	int err;
	const char *custom_table_str;
	unsigned long custom_table;
	char *endptr;

	/* Check for environment variable defining custom table */
	custom_table_str = getenv("RE_NETLINK_ROUTE_TABLE");
	if (custom_table_str && *custom_table_str) {
		errno = 0;  /* To distinguish success/failure */
		custom_table = strtoul(custom_table_str, &endptr, 10);

		/* Check for conversion errors */
		if (errno == 0 && *endptr == '\0' &&
		    custom_table <= UINT32_MAX) {
			/* Try custom table first */
			err = net_netlink_addrs_ext(ifh, arg, (uint32_t)custom_table);
			if (!err)
				return 0;
		}
		/* Silently fall through on invalid values */
	}

	/* Try main table */
	err = net_netlink_addrs_ext(ifh, arg, RT_TABLE_MAIN);
	if (!err)
		return 0;

	/* Try local table */
	err = net_netlink_addrs_ext(ifh, arg, RT_TABLE_LOCAL);
	if (!err)
		return 0;

	/* Try all tables */
	return net_netlink_addrs_ext(ifh, arg, RT_TABLE_UNSPEC);
}


// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_DSR		1
#define DSR_ENCAP_GENEVE	3
#define ENABLE_HOST_ROUTING

#define ENABLE_SKIP_FIB		1

#define CLIENT_IP	{ .addr = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define CLIENT_PORT	__bpf_htons(111)

#define FRONTEND_IP	{ .addr = { 0x2, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define FRONTEND_PORT	tcp_svc_one

#define BACKEND_IP	{ .addr = { 0x3, 0x0, 0x0, 0x0, 0x0, 0x0 } }
#define BACKEND_PORT	__bpf_htons(8080)

#define BACKEND_EP_ID		127

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[BACKEND_EP_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#include "bpf_host.c"

#include "lib/endpoint.h"
#include "lib/ipcache.h"

#define FROM_NETDEV	0
#define TO_NETDEV	1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

/* Test that a remote node
 * - doesn't touch a DSR request,
 * - redirects it to the pod (as ENABLE_HOST_ROUTING is set)
 * - creates a matching CT entry, and SNAT entry from the DSR info
 */
PKTGEN("tc", "tc_nodeport_dsr_backend")
int nodeport_dsr_backend_pktgen(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP;
	union v6addr backend_ip = BACKEND_IP;
	union v6addr client_ip = CLIENT_IP;
	struct dsr_opt_v6 *opt;
	struct pktgen builder;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv6_packet(&builder, (__u8 *)client_mac, (__u8 *)node_mac,
				      (__u8 *)&client_ip, (__u8 *)&backend_ip);
	if (!l3)
		return TEST_ERROR;

	ipv6_addr_copy((union v6addr *)&l3->saddr, &client_ip);
	ipv6_addr_copy((union v6addr *)&l3->daddr, &backend_ip);

	opt = (struct dsr_opt_v6 *)pktgen__append_ipv6_extension_header(&builder,
									NEXTHDR_DEST,
									sizeof(*opt));
	if (!opt)
		return TEST_ERROR;

	opt->opt_type = DSR_IPV6_OPT_TYPE;
	opt->opt_len = DSR_IPV6_OPT_LEN;
	ipv6_addr_copy_unaligned((union v6addr *)&opt->addr, &frontend_ip);
	opt->port = FRONTEND_PORT;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = BACKEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_dsr_backend")
int nodeport_dsr_backend_setup(struct __ctx_buff *ctx)
{
	union v6addr backend_ip = BACKEND_IP;

	/* add local backend */
	endpoint_v6_add_entry(&backend_ip, 0, BACKEND_EP_ID, 0, 0,
			      (__u8 *)backend_mac, (__u8 *)node_mac);

	ipcache_v6_add_entry(&backend_ip, 0, 112233, 0, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_dsr_backend")
int nodeport_dsr_backend_check(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP;
	union v6addr backend_ip = BACKEND_IP;
	union v6addr client_ip = CLIENT_IP;
	struct dsr_opt_v6 *opt;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	opt = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)opt + sizeof(*opt) > data_end)
		test_fatal("l3 DSR option out of bounds");

	l4 = (void *)opt + sizeof(*opt);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)backend_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the endpoint MAC")

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &client_ip))
		test_fatal("src IP has changed");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &backend_ip))
		test_fatal("dst IP has changed");

	if (l3->nexthdr != NEXTHDR_DEST)
		test_fatal("nexthdr in IPv6 header has changed")

	if (opt->hdr.nexthdr != IPPROTO_TCP)
		test_fatal("nexthdr in DSR extension has changed")
	if (opt->hdr.hdrlen != DSR_IPV6_EXT_LEN)
		test_fatal("length in DSR extension has changed")
	if (opt->opt_type != DSR_IPV6_OPT_TYPE)
		test_fatal("opt_type in DSR extension has changed")
	if (opt->opt_len != DSR_IPV6_OPT_LEN)
		test_fatal("opt_len in DSR extension has changed")

	if (opt->port != FRONTEND_PORT)
		test_fatal("port in DSR extension has changed")
	if (!ipv6_addr_equals((union v6addr *)&opt->addr, &frontend_ip))
		test_fatal("addr in DSR extension has changed")

	if (l4->source != CLIENT_PORT)
		test_fatal("src port has changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port has changed");

	struct ipv6_ct_tuple tuple __align_stack_8;
	struct ct_entry *ct_entry;
	fraginfo_t fraginfo;
	int l3_off, l4_off, ret;

	l3_off = sizeof(*status_code) + ETH_HLEN;

	tuple.nexthdr = l3->nexthdr;
	ret = ipv6_hdrlen_offset(ctx, l3_off, &tuple.nexthdr, &fraginfo);
	if (ret < 0)
		return ret;

	l4_off = l3_off + ret;

	ret = lb6_extract_tuple(ctx, l3, fraginfo, l4_off, &tuple);
	assert(!IS_ERR(ret));

	tuple.flags = TUPLE_F_IN;
	ipv6_ct_tuple_reverse(&tuple);

	ct_entry = map_lookup_elem(get_ct_map6(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no CT entry for DSR found");
	if (!ct_entry->dsr_internal)
		test_fatal("CT entry doesn't have the .dsr_internal flag set");

	struct ipv6_nat_entry *nat_entry;

	tuple.sport = BACKEND_PORT;
	tuple.dport = CLIENT_PORT;

	nat_entry = snat_v6_lookup(&tuple);
	if (!nat_entry)
		test_fatal("no SNAT entry for DSR found");
	if (!ipv6_addr_equals((union v6addr *)&nat_entry->to_saddr, &frontend_ip))
		test_fatal("SNAT entry has wrong address");
	if (nat_entry->to_sport != FRONTEND_PORT)
		test_fatal("SNAT entry has wrong port");

	test_finish();
}

static __always_inline
int build_reply(struct __ctx_buff *ctx)
{
	union v6addr backend_ip = BACKEND_IP;
	union v6addr client_ip = CLIENT_IP;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)node_mac, (__u8 *)client_mac,
					  (__u8 *)&backend_ip, (__u8 *)&client_ip,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

static __always_inline
int check_reply(const struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IP;
	union v6addr client_ip = CLIENT_IP;
	void *data, *data_end;
	__u32 *status_code;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct ipv6hdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct ipv6hdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client MAC")

	if (!ipv6_addr_equals((union v6addr *)&l3->saddr, &frontend_ip))
		test_fatal("src IP hasn't been RevNATed to frontend IP");

	if (!ipv6_addr_equals((union v6addr *)&l3->daddr, &client_ip))
		test_fatal("dst IP has changed");

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	if (l4->check != bpf_htons(0x2dbc))
		test_fatal("L4 checksum is invalid: %x", bpf_htons(l4->check));

	test_finish();
}

/* Test that the backend node revDNATs a reply from the
 * DSR backend, and sends the reply back to the client.
 */
PKTGEN("tc", "tc_nodeport_dsr_backend_reply")
int nodeport_dsr_backend_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_reply(ctx);
}

SETUP("tc", "tc_nodeport_dsr_backend_reply")
int nodeport_dsr_backend_reply_reply_setup(struct __ctx_buff *ctx)
{
	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_dsr_backend_reply")
int nodeport_dsr_backend_reply_reply_check(const struct __ctx_buff *ctx)
{
	return check_reply(ctx);
}

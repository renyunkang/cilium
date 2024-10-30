
#include "bpf/types_mapper.h"
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include <ep_config.h>
#include <node_config.h>

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/edt.h"
#include "lib/qm.h"
#include "lib/arp.h"


// int tail_handle_arp(struct __ctx_buff *ctx)
// {
// 	union macaddr mac = THIS_INTERFACE_MAC;
// 	union macaddr smac;
// 	__be32 sip;
// 	__be32 tip;

// 	/* Pass any unknown ARP requests to the Linux stack */
// 	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
// 		return CTX_ACT_OK;

// 	/*
// 	 * The endpoint is expected to make ARP requests for its gateway IP.
// 	 * Most of the time, the gateway IP configured on the endpoint is
// 	 * IPV4_GATEWAY but it may not be the case if after cilium agent reload
// 	 * a different gateway is chosen. In such a case, existing endpoints
// 	 * will have an old gateway configured. Since we don't know the IP of
// 	 * previous gateways, we answer requests for all IPs with the exception
// 	 * of the LXC IP (to avoid specific problems, like IP duplicate address
// 	 * detection checks that might run within the container).
// 	 */
// 	if (tip == LXC_IPV4)
// 		return CTX_ACT_OK;

// 	return arp_respond(ctx, &mac, tip, &smac, sip, 0);
// }


__section_entry
int cil_from_container(struct __ctx_buff *ctx)
{
    __u16 proto;
	__s8 ext_err = 0;
	int ret;

	bpf_clear_meta(ctx);
	reset_queue_mapping(ctx);

    if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		edt_set_aggregate(ctx, LXC_ID);
		ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_LXC, &ext_err);
		break;
#ifdef ENABLE_ARP_PASSTHROUGH
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#elif defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		// ret = tail_handle_arp(ctx);
		break;
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
	}

out:

    return ret;
}


BPF_LICENSE("Dual BSD/GPL");
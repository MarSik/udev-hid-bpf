// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Benjamin Tissoires
 */

#include "vmlinux.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

SEC("fmod_ret/hid_bpf_rdesc_fixup")
int BPF_PROG(hid_fix_rdesc, struct hid_bpf_ctx *hctx)
{
	const u8 offsets[] = {84, 112, 140};
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 4096 /* size */);

	if (!data)
		return 0; /* EPERM check */

	/* if not Keyboard */
	if (data[3] != 0x06)
		return 0;

	for (int idx = 0; idx < sizeof(offsets)/sizeof(offsets[0]); idx++) {
		u8 offset = offsets[idx];

		/* if Input (Cnst,Var,Abs) , make it Input (Data,Var,Abs) */
		if (data[offset] == 0x81 && data[offset + 1] == 0x03) {
			data[offset +1] = 0x02;
		}
	}

	return 0;
}

SEC("syscall")
int probe(struct probe_args *ctx)
{
	/* only bind to the keyboard interface */
	ctx->retval = ctx->rdesc_size != 213;
	if (ctx->retval)
		ctx->retval = -22;

	return 0;
}

char _license[] SEC("license") = "GPL";

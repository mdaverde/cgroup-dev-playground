#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// These enums actually exist in <linux/bpf.h> but when we #include them we get
// multiple redefinition issues due to the fact the redundant types live in vmlinux.h,
// which we also #include. Why don't these exist in vmlinux.h already? Seems that
// support for 64 bit enum in BTF just got added in 06/22:
// https://lwn.net/ml/bpf/20220603015855.1187538-1-yhs@fb.com/
// https://lwn.net/Articles/905738/
enum {
	BPF_DEVCG_ACC_MKNOD	= (1ULL << 0),
	BPF_DEVCG_ACC_READ	= (1ULL << 1),
	BPF_DEVCG_ACC_WRITE	= (1ULL << 2),
};

enum {
	BPF_DEVCG_DEV_BLOCK	= (1ULL << 0),
	BPF_DEVCG_DEV_CHAR	= (1ULL << 1),
};

SEC("cgroup/dev")
int bpf_prog1(struct bpf_cgroup_dev_ctx *ctx)
{
	bpf_printk("hello from cgroup: %d\n", bpf_get_current_cgroup_id());

	short type = ctx->access_type & 0xFFFF;
	if (ctx->major != 1) {
		return 0;
	}

	switch (ctx->minor) {
		case 3: /* 1:3 /dev/null */
		case 5: /* 1:5 /dev/zero */
		case 9: /* 1:9 /dev/urandom */
			return 1;
	}


	return 0;
}


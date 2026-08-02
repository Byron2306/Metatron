#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define OVERLAYFS_SUPER_MAGIC 0x794C764F

struct arda_identity {
    unsigned long inode;
    unsigned int dev;
};

// Exec allowlist: keyed by {inode, dev}, value 1 = harmonic (permitted).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct arda_identity);
    __type(value, __u32);
} arda_harmony_map SEC(".maps");

// Global enforcement toggle: index 0 = 0 (audit/pass) or 1 (enforce).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} arda_state_map SEC(".maps");

// Cumulative denial counter for telemetry/evidence. Index 0 = total vetoes.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} arda_deny_count SEC(".maps");

// Network veto map: keyed by PID (u32), value 1 = deny all outbound connects.
// Populated by Tulkas on CONTAIN/PURGE/EXILE postures for fallen nodes.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} arda_network_deny_map SEC(".maps");

// ── Exec gate (bprm_check_security) ─────────────────────────────────────────

SEC("lsm/bprm_check_security")
int BPF_PROG(arda_sovereign_ignition, struct linux_binprm *bprm, int ret)
{
    if (ret != 0) return ret;

    struct arda_identity key = {0};
    key.inode = bprm->file->f_inode->i_ino;
    key.dev = bprm->file->f_inode->i_sb->s_dev;

    __u32 index = 0;
    __u32 *state = bpf_map_lookup_elem(&arda_state_map, &index);

    // AUDIT mode (default) — never block, even if unlisted.
    // Prevents lockout when seeding is incomplete.
    if (!state || *state == 0) {
        return 0;
    }

    __u32 *harmonic = bpf_map_lookup_elem(&arda_harmony_map, &key);
    if (!harmonic || *harmonic == 0) {
        __u32 cidx = 0;
        __u64 *cnt = bpf_map_lookup_elem(&arda_deny_count, &cidx);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        }
        bpf_printk("ARDA_VETO: execve denied ino=%lu dev=%u\n", key.inode, key.dev);
        return -1; /* -EPERM */
    }

    return 0;
}

// ── Network gate (socket_connect) ───────────────────────────────────────────
// Blocks outbound connect() for any PID explicitly marked fallen by Tulkas.
// Only active when arda_network_deny_map has an entry for the calling PID.
// The exec gate guards what runs; this guards where fallen processes can reach.

SEC("lsm/socket_connect")
int BPF_PROG(arda_network_veto, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *deny = bpf_map_lookup_elem(&arda_network_deny_map, &pid);
    if (deny && *deny) {
        __u32 cidx = 0;
        __u64 *cnt = bpf_map_lookup_elem(&arda_deny_count, &cidx);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        }
        bpf_printk("ARDA_NET_VETO: connect denied for PID %u\n", pid);
        return -1; /* -EPERM */
    }
    return 0;
}

char _license[] SEC("license") = "GPL";

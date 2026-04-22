#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define OVERLAYFS_SUPER_MAGIC 0x794C764F

struct arda_identity {
    unsigned long inode;
    unsigned int dev;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct arda_identity);
    __type(value, __u32);
} arda_harmony_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} arda_state_map SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(arda_sovereign_ignition, struct linux_binprm *bprm, int ret)
{
    if (ret != 0) return ret;

    struct arda_identity key = {0};
    key.inode = bprm->file->f_inode->i_ino;
    key.dev = bprm->file->f_inode->i_sb->s_dev;

    __u32 index = 0;
    __u32 *state = bpf_map_lookup_elem(&arda_state_map, &index);
    
    // Default to AUDIT (0) if state map is empty or set to 0. 
    // This prevents the "Universal Veto" during recovery.
    if (!state || *state == 0) {
        return 0; 
    }

    __u32 *harmonic = bpf_map_lookup_elem(&arda_harmony_map, &key);
    if (!harmonic || *harmonic == 0) {
        bpf_printk("ARDA_VETO: Denied %lu on %u (OverlayFS Mismatch?)\n", key.inode, key.dev);
        return -1; // -EPERM
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

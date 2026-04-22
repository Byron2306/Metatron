/*
 * ARDA LSM Loader — Creates a BPF link for the LSM program.
 * bpftool can load LSM programs but on some kernels doesn't auto-attach.
 * This loader uses the BPF syscall directly to create a BPF_LINK.
 *
 * Usage: arda_lsm_loader <path_to_bpf_object.o>
 * The program stays alive while the link is active. Kill it to detach.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int running = 1;
static struct bpf_object *obj = NULL;
static struct bpf_link *bpf_lnk = NULL;

void cleanup(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object.o> [--pin /sys/fs/bpf/arda_lsm]\n", argv[0]);
        return 1;
    }

    const char *obj_path = argv[1];
    const char *pin_path = NULL;
    if (argc >= 4 && strcmp(argv[2], "--pin") == 0)
        pin_path = argv[3];

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    /* Open the BPF object */
    obj = bpf_object__open(obj_path);
    if (!obj) {
        fprintf(stderr, "ERROR: Failed to open BPF object: %s\n", obj_path);
        return 1;
    }

    /* Load (verify) the BPF programs */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("BPF object loaded successfully.\n");

    /* Find the LSM program */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "arda_sovereign_ignition");
    if (!prog) {
        fprintf(stderr, "ERROR: Program 'arda_sovereign_ignition' not found in object.\n");
        bpf_object__close(obj);
        return 1;
    }
    printf("Found LSM program: arda_sovereign_ignition\n");

    /* Attach as LSM — this creates a bpf_link */
    bpf_lnk = bpf_program__attach(prog);
    if (!bpf_lnk || libbpf_get_error(bpf_lnk)) {
        fprintf(stderr, "ERROR: Failed to attach LSM: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("LSM hook ATTACHED — arda_sovereign_ignition is now enforcing.\n");

    /* Pin the link if requested */
    if (pin_path) {
        if (bpf_link__pin(bpf_lnk, pin_path)) {
            fprintf(stderr, "WARNING: Failed to pin link to %s: %s\n", pin_path, strerror(errno));
        } else {
            printf("Link pinned to %s\n", pin_path);
        }
    }

    /* Find and report the map */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "arda_harmony_map");
    if (map) {
        int map_fd = bpf_map__fd(map);
        printf("Harmony map FD: %d (use bpftool map show id <id> to inspect)\n", map_fd);

        /* Report map ID for seeding */
        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        if (bpf_map_get_info_by_fd(map_fd, &info, &len) == 0) {
            printf("MAP_ID=%u\n", info.id);
        }
    }

    /* Print the program FD for external use */
    printf("PROG_FD=%d\n", bpf_program__fd(prog));
    fflush(stdout);

    /* Stay alive — the link is active as long as this process runs */
    printf("LSM is ACTIVE. Press Ctrl+C or kill this process to detach.\n");
    while (running) {
        sleep(1);
    }

    printf("\nDetaching LSM hook...\n");
    if (bpf_lnk) bpf_link__destroy(bpf_lnk);
    if (obj) bpf_object__close(obj);
    printf("LSM hook detached. System is back to normal.\n");
    return 0;
}

/* Fuzz the iccpd mclagsyncd socket input: iccp_mclagsyncd_msg_handler(), which reads framed
 * messages (IccpSyncdHDr + TLVs: FDB entries, MC-LAG domain / interface / unique-IP config,
 * VLAN membership, ...) that mclagsyncd sends over sys->sync_fd. Domain 1 is configured first so
 * the per-domain handlers have a CSM to act on. */
#include "iccpd_fuzz_common.h"
#include <signal.h>

static struct System *g_sys;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);
    g_sys = fuzz_iccpd_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 512 * 1024)
        return -1; /* larger than the socket buffer the harness can queue */
    fuzz_iccpd_configure_domain();
    int fd = fuzz_iccpd_feed_socket(data, size);
    if (fd < 0) abort();
    g_sys->sync_fd = fd;
    /* The daemon calls the handler once per readable event until the socket reports EOF/error. */
    int guard = 0;
    while (g_sys->sync_fd > 0 && iccp_mclagsyncd_msg_handler(g_sys) != MCLAG_ERROR && guard++ < 100000)
        ;
    fuzz_iccpd_reset(g_sys);
    return 0;
}

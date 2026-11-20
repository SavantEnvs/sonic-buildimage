/* Fuzz the iccpd peer-session input: the ICCP/mLACP message stream the MC-LAG peer switch sends
 * over the ICCP TCP session. Bytes arrive on the CSM's socket and are read by the daemon's own
 * receive callback, scheduler_csm_read_callback() (LDP header framing + body), then processed by
 * the same three state machines scheduler_transit_fsm() runs: iccp_csm_transit() (ICCP message
 * validation), app_csm_transit() and mlacp_fsm_transit() (mLACP TLV handlers in mlacp_fsm.c /
 * mlacp_sync_update.c).
 *
 * Setup: domain 1 is configured through the config-line parser; the TCP connect/accept and the
 * capability / RG-connect handshake are skipped by marking the session OPERATIONAL (ICCP and
 * application layer), the state the daemon reaches after a successful handshake, so the input's
 * messages reach the mLACP handlers. mLACP itself starts in INIT and advances through its own
 * FSM as the input drives it. */
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

static void transit_all(void)
{
    struct CSM *csm;
    LIST_FOREACH(csm, &g_sys->csm_list, next) {
        iccp_csm_transit(csm);
        app_csm_transit(csm);
        mlacp_fsm_transit(csm);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 512 * 1024)
        return -1; /* larger than the socket buffer the harness can queue */
    fuzz_iccpd_configure_domain();
    struct CSM *csm = LIST_FIRST(&g_sys->csm_list);
    if (!csm) abort();
    int fd = fuzz_iccpd_feed_socket(data, size);
    if (fd < 0) abort();
    csm->sock_fd = fd;
    csm->current_state = ICCP_OPERATIONAL;
    csm->iccp_info.sender_capability_flag = 1;
    csm->iccp_info.peer_capability_flag = 1;
    csm->iccp_info.sender_rg_connect_flag = 1;
    csm->iccp_info.peer_rg_connect_flag = 1;
    csm->app_csm.current_state = APP_OPERATIONAL;

    /* One FSM pass per received message, as the daemon's event loop does; the callback
     * disconnects the session (and returns an error) at EOF or on a framing error. */
    int guard = 0;
    while (csm->sock_fd > 0 && scheduler_csm_read_callback(csm) == 1 && guard++ < 100000)
        transit_all();
    transit_all();
    fuzz_iccpd_reset(g_sys);
    return 0;
}

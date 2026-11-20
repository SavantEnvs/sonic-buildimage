/* Shared setup/reset for the iccpd fuzz harnesses (mayhem layer, not upstream code).
 *
 * The daemon keeps all state in the System singleton (system_get_instance()). It is created once;
 * after every input the harness tears down everything an input can create (CSMs, local
 * interfaces, pending VLAN members, unique-IP interfaces, the mclagsyncd fd) using the daemon's
 * own finalizers, mirroring system_finalize() minus freeing the singleton and its netlink sockets,
 * so each input starts from the same empty daemon.
 */
#ifndef ICCPD_FUZZ_COMMON_H
#define ICCPD_FUZZ_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <signal.h>

#include "../../src/iccpd/include/system.h"
#include "../../src/iccpd/include/iccp_csm.h"
#include "../../src/iccpd/include/iccp_cmd.h"
#include "../../src/iccpd/include/iccp_cli.h"
#include "../../src/iccpd/include/iccp_ifm.h"
#include "../../src/iccpd/include/port.h"
#include "../../src/iccpd/include/logger.h"
#include "../../src/iccpd/include/scheduler.h"
#include "../../src/iccpd/include/mlacp_link_handler.h"
#include "../../src/iccpd/include/mlacp_fsm.h"
#include "../../src/iccpd/include/app_csm.h"

int iccp_config_from_command(char *line);

static struct System *fuzz_iccpd_init(void)
{
    struct System *sys = system_get_instance();
    logger_set_configuration(CRITICAL_LOG_LEVEL);
    return sys;
}

static void fuzz_iccpd_reset(struct System *sys)
{
    struct CSM *csm;
    struct LocalInterface *lif;
    struct Unq_ip_If_info *uif;

    while (!LIST_EMPTY(&sys->csm_list)) {
        csm = LIST_FIRST(&sys->csm_list);
        iccp_csm_finalize(csm);
    }
    while (!LIST_EMPTY(&sys->lif_list)) {
        lif = LIST_FIRST(&sys->lif_list);
        LIST_REMOVE(lif, system_next);
        local_if_finalize(lif);
    }
    while (!LIST_EMPTY(&sys->lif_purge_list)) {
        lif = LIST_FIRST(&sys->lif_purge_list);
        LIST_REMOVE(lif, system_purge_next);
        local_if_finalize(lif);
    }
    del_all_pending_vlan_mbr_ifs(sys);
    while (!LIST_EMPTY(&sys->unq_ip_if_list)) {
        uif = LIST_FIRST(&sys->unq_ip_if_list);
        LIST_REMOVE(uif, if_next);
        free(uif);
    }
    if (sys->sync_fd > 0) {
        close(sys->sync_fd);
        sys->sync_fd = -1;
    }
}

/* Configure MC-LAG domain 1 through the daemon's own config-line parser (what `iccpd -f` reads). */
static void fuzz_iccpd_configure_domain(void)
{
    static const char *lines[] = {
        "mclag_id:1\n", "local_ip:10.0.0.1\n", "peer_ip:10.0.0.2\n",
        "system_mac:00:11:22:33:44:55\n",
    };
    for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%s", lines[i]);
        iccp_config_from_command(buf);
    }
}

/* A connected socket pair; `data` is queued on the far end, which is then shut for writing so
 * the daemon reads exactly `data` followed by EOF. Returns the daemon's end (non-blocking, so the
 * daemon's own replies never block on a full buffer), or -1. */
static int fuzz_iccpd_feed_socket(const uint8_t *data, size_t size)
{
    int sv[2];
    int sz = 1 << 20;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(sv[1], data + off, size - off);
        if (n <= 0)
            break;
        off += (size_t)n;
    }
    shutdown(sv[1], SHUT_WR);
    /* Keep sv[1] open for reading-side replies until the caller closes the daemon's end;
     * closing it now would make the daemon's replies fail with EPIPE/SIGPIPE. */
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL) | O_NONBLOCK);
    static int peer = -1;
    if (peer >= 0)
        close(peer);
    peer = sv[1];
    return sv[0];
}

#endif

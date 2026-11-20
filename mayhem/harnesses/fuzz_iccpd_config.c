/* Fuzz the iccpd configuration file parser: iccp_config_from_file(), i.e. `iccpd -f <file>`.
 * Reaches iccp_cmd.c's line parser and the iccp_cli.c setters (mclag_id, local_ip, peer_ip,
 * peer_link, mclag_interface, system_mac). */
#include "iccpd_fuzz_common.h"

static struct System *g_sys;
static char g_path[4096];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);
    g_sys = fuzz_iccpd_init();
    const char *tmp = getenv("TMPDIR");
    snprintf(g_path, sizeof(g_path), "%s/iccpd-fuzz-XXXXXX", tmp && *tmp ? tmp : "/tmp");
    int fd = mkstemp(g_path);
    if (fd < 0) abort();
    close(fd);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE *f = fopen(g_path, "wb");
    if (!f) abort();
    fwrite(data, 1, size, f);
    fclose(f);
    /* iccp_config_from_command() keeps the current domain id in a function-static `mid`
     * (iccp_cmd.c:80), so a line without a preceding mclag_id: would act on the previous
     * input's id. Reset it to its initial 0 through the parser itself, then drop the domain
     * that line created, so every input starts from the same state. */
    char reset_line[] = "mclag_id:0\n";
    iccp_config_from_command(reset_line);
    fuzz_iccpd_reset(g_sys);
    iccp_config_from_file(g_path);
    fuzz_iccpd_reset(g_sys);
    return 0;
}

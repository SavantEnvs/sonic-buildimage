/* Fuzz the libnss-radius configuration parser: parse_nss_config() + unparse_nss_config()
 * (src/radius/nss/libnss-radius/nss_radius_common.c), what the NSS module and cache_radius run
 * on /etc/radius_nss.conf for every passwd lookup. Built with upstream's own TEST_RADIUS_NSS
 * switch (as its test_nss_radius.c uses), which reads the config from the cwd-relative path
 * "radius_nss.conf"; the harness writes each input there (Mayhem's cwd is writable).
 * The buffer size matches the callers (nss_radius.c / cache_radius.c: RADIUS_MAX_NSS_CONF_SZ). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "../../src/radius/nss/libnss-radius/nss_radius_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static char file_buf[RADIUS_MAX_NSS_CONF_SZ];
    RADIUS_NSS_CONF_B conf;
    int err = 0, lockfd = -1;
    FILE *f = fopen(RADIUS_NSS_CONF, "wb");
    if (!f) abort();
    fwrite(data, 1, size, f);
    fclose(f);
    parse_nss_config(&conf, "fuzz_nss_radius_conf", file_buf, sizeof(file_buf), &err, &lockfd);
    unparse_nss_config(&conf, &err, &lockfd);
    return 0;
}

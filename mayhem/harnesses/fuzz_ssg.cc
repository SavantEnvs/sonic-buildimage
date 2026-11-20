// Fuzz systemd-sonic-generator: ssg_main(), the systemd generator that reads
// /etc/sonic/generated_services.conf, each listed unit file (its [Install]/[Unit] sections),
// /host/machine.conf, the platform's asic.conf and platform.json (json-c), then installs
// symlinks and per-instance unit files into the output directory.
//
// The generator's own unit-test hooks (-D_SSG_UNITTEST, as ssg-test.cc uses) point those paths
// into a private scratch tree. The input is split on NUL bytes into up to five files:
//   0: generated_services.conf     1: unit file written as both test.service and test@.service
//   2: machine.conf                3: device/<platform>/platform.json   4: device/<platform>/asic.conf
// (<platform> is the fixed name "fuzzplat"; seeds use onie_platform=fuzzplat). The scratch tree
// is wiped and rewritten for every input, and ssg_main() resets its own caches on entry.
//
// The generator exit()s on several malformed-input paths (e.g. an [Install] line with an empty
// target), so this is built as an AFL file-input target (Mayhemfile `afl: true`, input file @@):
// the main() below reads one input file and runs it once; an exit() is then an ordinary exit.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include "systemd-sonic-generator.h"

namespace fs = std::filesystem;
static std::string g_root, g_unit_dir, g_out, g_conf, g_machine, g_asic_fmt, g_plat_fmt, g_pconf_fmt;

static void write_file(const std::string &p, const uint8_t *d, size_t n) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char *>(d), (std::streamsize)n);
}

static int ssg_fuzz_init(int *argc, char ***argv) {
    (void)argc; (void)argv;
    const char *tmp = getenv("TMPDIR");
    std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") + "/ssg-fuzz-XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (!mkdtemp(buf.data())) abort();
    g_root = buf.data();
    g_unit_dir = g_root + "/lib/system/";
    g_out = g_root + "/out";
    g_conf = g_root + "/generated_services.conf";
    g_machine = g_root + "/machine.conf";
    g_asic_fmt = g_root + "/device/%s/asic.conf";
    g_plat_fmt = g_root + "/device/%s/platform.json";
    g_pconf_fmt = g_root + "/device/%s/services.conf";
    static std::string lib = g_root + "/lib";
    static std::string etc = g_root + "/etc";
    g_lib_systemd = lib.c_str();
    g_etc_systemd = etc.c_str();
    g_unit_file_prefix = g_unit_dir.c_str();
    g_config_file = g_conf.c_str();
    g_machine_config_file = g_machine.c_str();
    g_asic_conf_format = g_asic_fmt.c_str();
    g_platform_file_format = g_plat_fmt.c_str();
    g_platform_conf_format = g_pconf_fmt.c_str();
    return 0;
}

static int ssg_fuzz_one(const uint8_t *data, size_t size) {
    std::error_code ec;
    for (const char *d : {"/lib", "/etc", "/out", "/device"})
        fs::remove_all(g_root + d, ec);
    fs::remove(g_conf, ec);
    fs::remove(g_machine, ec);
    fs::create_directories(g_unit_dir, ec);
    fs::create_directories(g_root + "/etc/system", ec);
    fs::create_directories(g_out, ec);
    fs::create_directories(g_root + "/device/fuzzplat", ec);

    std::vector<std::pair<const uint8_t *, size_t>> parts;
    size_t start = 0;
    for (size_t i = 0; i <= size && parts.size() < 5; i++) {
        if (i == size || data[i] == 0) {
            parts.emplace_back(data + start, i - start);
            start = i + 1;
        }
    }
    const std::string files[5] = {g_conf, g_unit_dir + "test.service", g_machine,
                                  g_root + "/device/fuzzplat/platform.json",
                                  g_root + "/device/fuzzplat/asic.conf"};
    // Every file exists (empty when the input has fewer parts): a missing machine.conf or
    // services.conf makes the generator exit() by design, which is not input-dependent.
    while (parts.size() < 5)
        parts.emplace_back(data, 0);
    for (size_t i = 0; i < parts.size(); i++) {
        write_file(files[i], parts[i].first, parts[i].second);
        if (i == 1)
            write_file(g_unit_dir + "test@.service", parts[i].first, parts[i].second);
    }

    std::string prog = "systemd-sonic-generator";
    std::vector<char *> argv = {prog.data(), g_out.data(), g_out.data(), g_out.data(), nullptr};
    ssg_main(4, argv.data());
    return 0;
}


#include <iterator>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    std::ifstream in(argv[1], std::ios::binary);
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    ssg_fuzz_init(&argc, &argv);
    ssg_fuzz_one(buf.data(), buf.size());
    std::error_code ec;
    fs::remove_all(g_root, ec);
    return 0;
}


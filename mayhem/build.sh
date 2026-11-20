#!/usr/bin/env bash
# mayhem/build.sh — build the sonic-buildimage fuzz harnesses and the oracle test suites.
#
# The top-level SONiC image build (make/slave.mk, sonic-slave docker, ~50 submodules) is not
# involved: the in-tree C/C++ that reads untrusted data is built standalone from its own sources,
# the same way upstream's per-component Makefiles do:
#   * src/iccpd                    — MC-LAG ICCP daemon (C, autotools upstream; compiled directly
#                                    here from the same iccpd_SOURCES minus iccp_main.c)
#   * src/systemd-sonic-generator  — systemd generator (C++20, plain Makefile upstream)
# All outputs go to mayhem/build/ (gitignored by mayhem/.gitignore). Re-runnable and offline:
# every dependency is an apt -dev package installed by mayhem/Dockerfile.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"

cd "$SRC"
OUT="$SRC/mayhem/build"
H="$SRC/mayhem/harnesses"
ICCPD="$SRC/src/iccpd"
SSG="$SRC/src/systemd-sonic-generator"
mkdir -p "$OUT/iccpd-obj" "$OUT/tests"

ICCPD_SRCS="app_csm.c cmd_option.c iccp_cli.c iccp_cmd_show.c iccp_cmd.c iccp_csm.c iccp_ifm.c
  logger.c port.c scheduler.c system.c iccp_consistency_check.c iccp_utils.c mlacp_link_handler.c
  mlacp_sync_prepare.c mlacp_sync_update.c mlacp_fsm.c iccp_netlink.c iccp_netlink_utils.c
  openbsd_tree.c"
ICCPD_INC="-I$ICCPD/include -I/usr/include/libnl3"
ICCPD_LIBS="-lnl-genl-3 -lnl-route-3 -lnl-3 -lpthread"
# -fno-sanitize=function: iccpd registers its fd getters through a table of `int (*)(struct System*)`
# pointers whose targets take `void` (iccp_netlink.c:2160 -> scheduler.c iccp_get_server_sock_fd),
# which UBSan's -fsanitize=function reports at daemon start-up, before any input is read. Only
# that check is relaxed; ASan and the rest of UBSan stay on and halting.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -Wno-unused-result"
case "$SANITIZER_FLAGS" in *undefined*) FUZZ_CFLAGS="$FUZZ_CFLAGS -fno-sanitize=function" ;; esac
# -fno-sanitize=alignment (iccpd sources + iccpd harnesses only): iccpd parses its wire formats
# by casting packed byte buffers to structs at arbitrary offsets (e.g. mlacp_link_handler.c:3496
# reads `struct IccpSyncdHDr` at `msg_buf[pos]` after an odd-length message), which UBSan's
# alignment check reports on nearly every input, so the fuzzer never got past it (0 edges in
# Mayhem). Unaligned loads are fine on the switch CPUs iccpd runs on (x86-64, arm64). Only that
# check is relaxed; ASan and the rest of UBSan stay on and halting.
# -D__compiler_offsetof=__builtin_offsetof: src/iccpd/include/openbsd_tree.h defines offsetof as
# `&((TYPE *)0)->MEMBER` unless __compiler_offsetof is set, and halting UBSan reports that
# expression as "member access within null pointer" (mlacp_fsm.c:1400, the mLACP aggregator-config
# TLV handler), aborting every input that reaches it. Pointing the header at its own
# __compiler_offsetof branch gives the same constant without the UB; no sanitizer check is relaxed.
ICCPD_CFLAGS="$FUZZ_CFLAGS -D__compiler_offsetof=__builtin_offsetof"
case "$SANITIZER_FLAGS" in *undefined*) ICCPD_CFLAGS="$ICCPD_CFLAGS -fno-sanitize=alignment" ;; esac

# --- 1) iccpd daemon sources, instrumented (every source except iccp_main.c, which holds main) ---
objs=()
for s in $ICCPD_SRCS; do
  o="$OUT/iccpd-obj/${s%.c}.o"
  objs+=("$o")
  echo "$CC -c $ICCPD/src/$s"
  $CC $ICCPD_CFLAGS $ICCPD_INC -c "$ICCPD/src/$s" -o "$o" &
  while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
done
wait
rm -f "$OUT/libiccpd.a"
ar rcs "$OUT/libiccpd.a" "${objs[@]}"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# --- 2) iccpd harnesses: libFuzzer binary + standalone reproducer each ---
for h in fuzz_iccpd_config fuzz_iccpd_peer fuzz_iccpd_mclagsyncd; do
  $CC $ICCPD_CFLAGS $ICCPD_INC -c "$H/$h.c" -o "$OUT/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$h.o" "$OUT/lsan_off.o" \
    "$OUT/libiccpd.a" $ICCPD_LIBS -o "$OUT/$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$h.o" "$OUT/lsan_off.o" \
    "$OUT/libiccpd.a" $ICCPD_LIBS -o "$OUT/$h-standalone"
done

# --- 2b) libnss-radius config parser (nss_radius_common.c), with upstream's TEST_RADIUS_NSS
#         switch (cwd-relative radius_nss.conf), instrumented ---
NSSR="$SRC/src/radius/nss/libnss-radius"
$CC $FUZZ_CFLAGS -DTEST_RADIUS_NSS -c "$NSSR/nss_radius_common.c" -o "$OUT/nss_radius_common.o"
$CC $FUZZ_CFLAGS -DTEST_RADIUS_NSS -c "$H/fuzz_nss_radius_conf.c" -o "$OUT/fuzz_nss_radius_conf.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/fuzz_nss_radius_conf.o" \
  "$OUT/nss_radius_common.o" "$OUT/lsan_off.o" -o "$OUT/fuzz_nss_radius_conf"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/fuzz_nss_radius_conf.o" \
  "$OUT/nss_radius_common.o" "$OUT/lsan_off.o" -o "$OUT/fuzz_nss_radius_conf-standalone"

# --- 3) systemd-sonic-generator, with its unit-test path hooks (-D_SSG_UNITTEST), as an AFL
#        file-input target (the generator exit()s on malformed input): afl-clang-fast++ instruments
#        the generator and the driver; the binary is its own reproducer (no -standalone). ---
SSG_CXXFLAGS="-std=c++20 -D_GNU_SOURCE -D_SSG_UNITTEST -I$SSG"
AFL_CXX="${AFL_CXX:-afl-clang-fast++}"
SSG_SANFLAGS="$SANITIZER_FLAGS"
AFL_QUIET=1 $AFL_CXX $SSG_SANFLAGS $DEBUG_FLAGS $SSG_CXXFLAGS -c "$SSG/systemd-sonic-generator.cpp" -o "$OUT/ssg-afl.o"
AFL_QUIET=1 $AFL_CXX $SSG_SANFLAGS $DEBUG_FLAGS $SSG_CXXFLAGS -c "$H/fuzz_ssg.cc" -o "$OUT/fuzz_ssg.o"
AFL_QUIET=1 $AFL_CXX $SSG_SANFLAGS $DEBUG_FLAGS "$OUT/fuzz_ssg.o" "$OUT/ssg-afl.o" "$OUT/lsan_off.o" \
  -ljson-c -o "$OUT/fuzz_ssg"

# --- 4) the upstream test suites, NORMAL flags (no sanitizers), for mayhem/test.sh ---
#   iccpd: `make check` programs (iccp_utils_test, iccp_netlink_utils_test; assert-based).
$CC -g -O1 $COVERAGE_FLAGS -Wno-unused-result $ICCPD_INC "$ICCPD/src/tests/iccp_utils_test.c" \
  "$ICCPD/src/iccp_utils.c" -o "$OUT/tests/iccp_utils_test"
$CC -g -O1 $COVERAGE_FLAGS -Wno-unused-result $ICCPD_INC "$ICCPD/src/tests/iccp_netlink_utils_test.c" \
  "$ICCPD/src/iccp_netlink_utils.c" -o "$OUT/tests/iccp_netlink_utils_test"
#   systemd-sonic-generator: `make test` (gtest ssg_test), same flags as upstream's Makefile.
$CXX -std=c++20 -D_GNU_SOURCE -I"$SSG" -g $COVERAGE_FLAGS -D_SSG_UNITTEST -c "$SSG/systemd-sonic-generator.cpp" \
  -o "$OUT/tests/systemd-sonic-generator.o"
$CXX -std=c++20 -D_GNU_SOURCE -I"$SSG" -g $COVERAGE_FLAGS "$SSG/ssg-test.cc" "$OUT/tests/systemd-sonic-generator.o" \
  -o "$OUT/tests/ssg_test" -lpthread -lboost_filesystem -lboost_system -lgtest -ljson-c $COVERAGE_FLAGS

echo "build.sh: done"; ls -l "$OUT"

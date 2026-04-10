#!/bin/bash

## Copyright (C) 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Dry-run test suite for Whonix firewall scripts.
## Runs each firewall script with --dry-run under various configurations,
## verifies exit codes, and checks the generated nft script for expected
## rules. Does not require a running nftables kernel module.
##
## Usage:
##   sudo ./tests/test_firewall_dry_run.sh [output_dir]
##
## The generated nft scripts are saved to output_dir (default: ./test-output)
## for manual review and diffing against baselines.

set -e -o pipefail

## ---------------------------------------------------------------------------
## Helpers
## ---------------------------------------------------------------------------

tests_run=0
tests_passed=0
tests_failed=0

pass() {
  tests_passed=$((tests_passed + 1))
  echo "  PASS: $1"
}

fail() {
  tests_failed=$((tests_failed + 1))
  echo "  FAIL: $1" >&2
}

assert_exit_zero() {
  local label="$1"
  shift
  if "$@" ; then
    pass "${label}: exit 0"
  else
    fail "${label}: exited $?"
  fi
}

assert_file_not_empty() {
  local label="$1" file="$2"
  if [ -s "$file" ]; then
    pass "${label}: nft script non-empty"
  else
    fail "${label}: nft script is empty or missing"
  fi
}

## Check that a pattern exists in the generated nft script.
assert_contains() {
  local label="$1" file="$2" pattern="$3"
  if grep -q -- "$pattern" "$file" 2>/dev/null; then
    pass "${label}: contains '${pattern}'"
  else
    fail "${label}: missing '${pattern}'"
  fi
}

## Check that a pattern does NOT exist in the generated nft script.
assert_not_contains() {
  local label="$1" file="$2" pattern="$3"
  if grep -q -- "$pattern" "$file" 2>/dev/null; then
    fail "${label}: unexpectedly contains '${pattern}'"
  else
    pass "${label}: correctly omits '${pattern}'"
  fi
}

## ---------------------------------------------------------------------------
## Setup
## ---------------------------------------------------------------------------

output_dir="${1:-./test-output}"
mkdir -p "$output_dir"

nft_script="/var/lib/whonix-firewall/firewall.nft"

## Install files to system paths (required because scripts use absolute paths).
install_files() {
  echo "==> Installing firewall files to system paths..."
  cp -a usr/bin/whonix_firewall /usr/bin/
  cp -a usr/bin/whonix-gateway-firewall /usr/bin/
  cp -a usr/bin/whonix-workstation-firewall /usr/bin/
  cp -a usr/bin/whonix-host-firewall /usr/bin/
  chmod +x /usr/bin/whonix_firewall /usr/bin/whonix-gateway-firewall \
    /usr/bin/whonix-workstation-firewall /usr/bin/whonix-host-firewall

  mkdir -p /usr/libexec/whonix-firewall
  cp -a usr/libexec/whonix-firewall/firewall-common /usr/libexec/whonix-firewall/

  mkdir -p /etc/whonix_firewall.d
  ## Start with no config files to avoid interference.
  rm -f /etc/whonix_firewall.d/*.conf

  mkdir -p /var/lib/whonix-firewall
  mkdir -p /run/whonix_firewall
}

create_users() {
  echo "==> Creating system users..."
  local user_list="clearnet tunnel notunnel systemcheck sdwdate updatesproxycheck"
  for u in $user_list; do
    if ! id "$u" >/dev/null 2>&1; then
      adduser --home "/run/$u" --no-create-home --quiet --system \
        --group --shell /bin/false "$u" 2>/dev/null || true
    fi
  done
}

cleanup_markers() {
  rm -f /usr/share/anon-gw-base-files/gateway
  rm -f /usr/share/anon-ws-base-files/workstation
  rm -f /usr/share/libvirt-dist/marker
  rm -rf /run/sdwdate
  rm -f /run/whonix_firewall/first_run_current_boot.status
  rm -f /run/whonix_firewall/consecutive_run.status
}

set_gateway_marker() {
  mkdir -p /usr/share/anon-gw-base-files
  touch /usr/share/anon-gw-base-files/gateway
}

set_workstation_marker() {
  mkdir -p /usr/share/anon-ws-base-files
  touch /usr/share/anon-ws-base-files/workstation
}

set_host_marker() {
  mkdir -p /usr/share/libvirt-dist
  touch /usr/share/libvirt-dist/marker
}

set_sdwdate_success() {
  mkdir -p /run/sdwdate
  touch /run/sdwdate/first_success
}

write_config() {
  echo "$1" > /etc/whonix_firewall.d/50_test.conf
}

clear_config() {
  rm -f /etc/whonix_firewall.d/50_test.conf
}

save_nft_script() {
  local name="$1"
  if [ -f "$nft_script" ]; then
    cp "$nft_script" "${output_dir}/${name}.nft"
  fi
}

## ---------------------------------------------------------------------------
## Test cases
## ---------------------------------------------------------------------------

run_test() {
  local name="$1" cmd="$2"
  tests_run=$((tests_run + 1))
  echo ""
  echo "--- Test: ${name} ---"
  rm -f "$nft_script"
  rm -f /run/whonix_firewall/first_run_current_boot.status
  rm -f /run/whonix_firewall/consecutive_run.status
  local cmd_exit=0
  bash -c "$cmd" >/dev/null 2>&1 || cmd_exit=$?
  if [ "$cmd_exit" -eq 0 ]; then
    pass "${name}: exit 0"
  else
    fail "${name}: exited ${cmd_exit}"
  fi
  save_nft_script "$name"
}

test_gateway_default() {
  cleanup_markers
  set_gateway_marker
  write_config "firewall_mode=full"

  run_test "gateway-default" "whonix-gateway-firewall --dry-run"
  local f="${output_dir}/gateway-default.nft"
  assert_file_not_empty "gateway-default" "$f"
  assert_contains "gateway-default" "$f" "add table inet filter"
  assert_contains "gateway-default" "$f" "add table inet nat"
  assert_contains "gateway-default" "$f" 'policy drop'
  assert_contains "gateway-default" "$f" 'iifname lo counter accept'
  assert_contains "gateway-default" "$f" 'oifname lo counter accept'
  assert_contains "gateway-default" "$f" "ct state established counter accept"
  assert_contains "gateway-default" "$f" "counter reject"
  ## Transparent proxy rules (full mode).
  assert_contains "gateway-default" "$f" "redirect to :9040"
  assert_contains "gateway-default" "$f" "redirect to :5300"
  ## SOCKS ports input rules.
  assert_contains "gateway-default" "$f" "tcp dport 9050 counter accept"
  assert_contains "gateway-default" "$f" "tcp dport 9150 counter accept"
  ## ICMPv6 ND.
  assert_contains "gateway-default" "$f" "nd-neighbor-solicit"
}

test_gateway_vpn() {
  cleanup_markers
  set_gateway_marker
  write_config "firewall_mode=full
VPN_FIREWALL=1"

  run_test "gateway-vpn" "whonix-gateway-firewall --dry-run"
  local f="${output_dir}/gateway-vpn.nft"
  assert_file_not_empty "gateway-vpn" "$f"
  assert_contains "gateway-vpn" "$f" 'oifname tun0 counter accept'
}

test_gateway_timesync() {
  cleanup_markers
  set_gateway_marker
  rm -rf /run/sdwdate
  write_config "firewall_mode=timesync-fail-closed"

  run_test "gateway-timesync" "whonix-gateway-firewall --dry-run"
  local f="${output_dir}/gateway-timesync.nft"
  assert_file_not_empty "gateway-timesync" "$f"
  ## In timesync-fail-closed, SOCKS ports should be rejected (except 9108).
  assert_contains "gateway-timesync" "$f" "tcp dport 9050 counter reject"
  assert_not_contains "gateway-timesync" "$f" "tcp dport 9108 counter reject"
  ## Transparent proxy rules should NOT be present (skipped in timesync-fail-closed).
  assert_not_contains "gateway-timesync" "$f" "redirect to :9040"
}

test_gateway_timesync_sdwdate_success() {
  cleanup_markers
  set_gateway_marker
  set_sdwdate_success
  write_config "firewall_mode=timesync-fail-closed"

  run_test "gateway-timesync-sdwdate-ok" "whonix-gateway-firewall --dry-run"
  local f="${output_dir}/gateway-timesync-sdwdate-ok.nft"
  assert_file_not_empty "gateway-timesync-sdwdate-ok" "$f"
  ## After sdwdate success, should be in full mode.
  assert_contains "gateway-timesync-sdwdate-ok" "$f" "redirect to :9040"
  assert_not_contains "gateway-timesync-sdwdate-ok" "$f" "tcp dport 9050 counter reject"
}

test_gateway_socksified_disabled() {
  cleanup_markers
  set_gateway_marker
  write_config "firewall_mode=full
WORKSTATION_ALLOW_SOCKSIFIED=0"

  run_test "gateway-no-socks" "whonix-gateway-firewall --dry-run"
  local f="${output_dir}/gateway-no-socks.nft"
  assert_file_not_empty "gateway-no-socks" "$f"
  ## Should still have basic rules (loopback, established).
  assert_contains "gateway-no-socks" "$f" 'oifname lo counter accept'
  ## Transparent proxy should still work.
  assert_contains "gateway-no-socks" "$f" "redirect to :9040"
}

test_workstation_default() {
  cleanup_markers
  set_workstation_marker
  write_config "firewall_mode=full"

  run_test "workstation-default" "whonix-workstation-firewall --dry-run"
  local f="${output_dir}/workstation-default.nft"
  assert_file_not_empty "workstation-default" "$f"
  assert_contains "workstation-default" "$f" "add table inet filter"
  assert_contains "workstation-default" "$f" 'policy drop'
  assert_contains "workstation-default" "$f" 'oifname lo counter accept'
  assert_contains "workstation-default" "$f" "ct state established counter accept"
  ## DNS to gateway.
  assert_contains "workstation-default" "$f" "udp dport 53 counter accept"
  ## Non-TCP reject (IPv4).
  assert_contains "workstation-default" "$f" "ip protocol != tcp counter reject"
  ## Accept all in full mode.
  assert_contains "workstation-default" "$f" "counter accept"
  ## Final reject.
  assert_contains "workstation-default" "$f" "counter reject"
}

test_workstation_tunnel() {
  cleanup_markers
  set_workstation_marker
  write_config "firewall_mode=full
TUNNEL_FIREWALL_ENABLE=true"

  run_test "workstation-tunnel" "whonix-workstation-firewall --dry-run"
  local f="${output_dir}/workstation-tunnel.nft"
  assert_file_not_empty "workstation-tunnel" "$f"
  assert_contains "workstation-tunnel" "$f" 'oifname tun0 counter accept'
  ## Final reject should be present even in tunnel mode.
  assert_contains "workstation-tunnel" "$f" "counter reject"
}

test_workstation_timesync() {
  cleanup_markers
  set_workstation_marker
  rm -rf /run/sdwdate
  write_config "firewall_mode=timesync-fail-closed"

  run_test "workstation-timesync" "whonix-workstation-firewall --dry-run"
  local f="${output_dir}/workstation-timesync.nft"
  assert_file_not_empty "workstation-timesync" "$f"
  ## SOCKS ports rejected (except 9108).
  assert_contains "workstation-timesync" "$f" "tcp dport 9050 counter reject"
  assert_not_contains "workstation-timesync" "$f" "tcp dport 9108 counter reject"
  ## DNS should NOT be allowed.
  assert_not_contains "workstation-timesync" "$f" "udp dport 53 counter accept"
}

test_workstation_outgoing_ip_list() {
  cleanup_markers
  set_workstation_marker
  write_config 'firewall_mode=full
outgoing_allow_ip_list="198.51.100.1 203.0.113.5"'

  run_test "workstation-ip-list" "whonix-workstation-firewall --dry-run"
  local f="${output_dir}/workstation-ip-list.nft"
  assert_file_not_empty "workstation-ip-list" "$f"
  assert_contains "workstation-ip-list" "$f" "ip daddr 198.51.100.1 counter accept"
  assert_contains "workstation-ip-list" "$f" "ip daddr 203.0.113.5 counter accept"
}

test_host_default() {
  cleanup_markers
  set_host_marker
  write_config "firewall_mode=full"

  run_test "host-default" "whonix-host-firewall --dry-run"
  local f="${output_dir}/host-default.nft"
  assert_file_not_empty "host-default" "$f"
  assert_contains "host-default" "$f" "add table inet filter"
  assert_contains "host-default" "$f" 'policy drop'
  assert_contains "host-default" "$f" 'oifname lo counter accept'
  assert_contains "host-default" "$f" "nd-neighbor-solicit"
  assert_contains "host-default" "$f" "counter reject"
}

test_host_vpn() {
  cleanup_markers
  set_host_marker
  write_config "firewall_mode=full
VPN_FIREWALL=1"

  run_test "host-vpn" "whonix-host-firewall --dry-run"
  local f="${output_dir}/host-vpn.nft"
  assert_file_not_empty "host-vpn" "$f"
  assert_contains "host-vpn" "$f" 'oifname tun0 counter accept'
}

test_cli_mode_full() {
  cleanup_markers
  set_gateway_marker
  rm -rf /run/sdwdate
  write_config "firewall_mode=timesync-fail-closed"

  ## --mode full should override config.
  run_test "cli-mode-full" "whonix-gateway-firewall --dry-run --mode full"
  local f="${output_dir}/cli-mode-full.nft"
  assert_file_not_empty "cli-mode-full" "$f"
  ## Should be in full mode despite config saying timesync-fail-closed.
  assert_contains "cli-mode-full" "$f" "redirect to :9040"
  assert_not_contains "cli-mode-full" "$f" "tcp dport 9050 counter reject"
}

test_cli_mode_timesync() {
  cleanup_markers
  set_gateway_marker
  rm -rf /run/sdwdate
  write_config "firewall_mode=full"

  ## --mode timesync-fail-closed should override config.
  run_test "cli-mode-timesync" "whonix-gateway-firewall --dry-run --mode timesync-fail-closed"
  local f="${output_dir}/cli-mode-timesync.nft"
  assert_file_not_empty "cli-mode-timesync" "$f"
  ## Should be in timesync-fail-closed despite config saying full.
  assert_contains "cli-mode-timesync" "$f" "tcp dport 9050 counter reject"
  assert_not_contains "cli-mode-timesync" "$f" "redirect to :9040"
}

## ---------------------------------------------------------------------------
## Main
## ---------------------------------------------------------------------------

echo "============================================="
echo "Whonix Firewall Dry-Run Test Suite"
echo "============================================="

install_files
create_users

test_gateway_default
test_gateway_vpn
test_gateway_timesync
test_gateway_timesync_sdwdate_success
test_gateway_socksified_disabled
test_workstation_default
test_workstation_tunnel
test_workstation_timesync
test_workstation_outgoing_ip_list
test_host_default
test_host_vpn
test_cli_mode_full
test_cli_mode_timesync

cleanup_markers
clear_config

echo ""
echo "============================================="
echo "Results: ${tests_passed} passed, ${tests_failed} failed (${tests_run} tests)"
echo "Generated nft scripts saved to: ${output_dir}/"
echo "============================================="

if [ "$tests_failed" -gt 0 ]; then
  exit 1
fi

#!/usr/bin/python3

# Copyright (c) 2020 SUSE LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Script which returns the percentage of BPF maps memory usage (as an integer).
If it's about to reach 100, bpf-map-dynamic-size-ratio (or bpf-policy-map-max,
if dynamic size ratio is not used) has to be increased.

The way this script works depends on Cilium configuration.

If bpf-map-dynamic-size-ratio is used, this script checks limits for all
dynamically allocated BPF maps (conntrack, nat, policy) based on that ratio,
then checks the usage percentage for each of them and returns the highest one.

If bpf-map-dynamic-size-ratio is not used, this script checks the limit set by
bpf-policy-map-max, checks the number of elements in each policy map and returns
the percentage based on the highest number of elements (so it returns the
percentage of the most heavily used BPF map).

In both cases, that percentage is counted only on the single node. This script
is supposed to be used on all nodes (both control plane and workers).
"""

import argparse
import glob
import logging
import os
import re
import subprocess

# Size of CT key: 38
# Size of CT entry: 56
# 38 + 56 = 94
SIZEOF_CT = 94
# Size of NAT key: 38
# Size of NAT entry: 56
# 38 + 56 = 94
SIZEOF_NAT = 94
# Size of policy key: 8
# Size of policy entry: 24
# 8 + 24 = 32
SIZEOF_POLICY = 32

CTMAP_ENTRIES_GLOBAL_TCP_DEFAULT = 2 << 18
CTMAP_ENTRIES_GLOBAL_ANY_DEFAULT = 2 << 17
NATMAP_ENTRIES_GLOBAL_DEFAULT = (CTMAP_ENTRIES_GLOBAL_TCP_DEFAULT + CTMAP_ENTRIES_GLOBAL_ANY_DEFAULT) * 2 / 3
POLICYMAP_ENTRIES_DEFAULT = 16384

LIMIT_TABLE_MIN = 1 << 10
LIMIT_TABLE_MAX = 1 << 24

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(os.path.basename(__file__))


def get_configmap(field: str, klass: type):
    log.debug(f"checking the field '{field}' in the configmap")
    b_val = subprocess.check_output(["kubectl", "-n", "kube-system",
                                     "get", "configmap", "cilium-config",
                                     "-o", f"jsonpath={{.data.{field}}}"])
    if not b_val:
        raise KeyError(
            f"configmap cilium-config doesn't have the field '{field}'")
    return klass(b_val)


def get_mem_total() -> int:
    with open("/proc/meminfo") as f:
        for l in f.readlines():
            if l.startswith("MemTotal"):
                # return bytes, not kilobytes
                return int(l.split()[1]) * 1024


def bpftool_map_elements(map_path: str) -> int:
    out = subprocess.check_output(["bpftool", "map", "dump", "pinned",
                                   map_path])
    matched = re.search(r"Found (\d+) elements", out.decode("utf-8"))
    if matched:
        return int(matched.groups()[0])

    raise ValueError("could not get number of elements from bpftool")


def percentage_ctmap_tcp(limit_ctmap_entries_global_tcp: int) -> int:
    num_entries_ipv4 = bpftool_map_elements(
        "/sys/fs/bpf/tc/globals/cilium_ct4_global")
    log.debug(f"number of ctmap tcp entries (ipv4): {num_entries_ipv4}")
    num_entries_ipv6 = bpftool_map_elements(
        "/sys/fs/bpf/tc/globals/cilium_ct6_global")
    log.debug(f"number of ctmap tcp entries (ipv6): {num_entries_ipv6}")
    num_entries = max([num_entries_ipv4, num_entries_ipv6])
    p = int(num_entries / limit_ctmap_entries_global_tcp * 100)
    log.debug(f"percentage of ctmap tcp usage (highest): {p}")
    return p


def percentage_ctmap_any(limit_ctmap_entries_global_any: int) -> int:
    num_entries_ipv4 = bpftool_map_elements(
        "/sys/fs/bpf/tc/globals/cilium_ct_any4_global")
    log.debug(f"number of ctmap entries (ipv4): {num_entries_ipv4}")
    num_entries_ipv6 = bpftool_map_elements(
        "/sys/fs/bpf/tc/globals/cilium_ct_any6_global")
    log.debug(f"number of ctmap entries (ipv6): {num_entries_ipv6}")
    num_entries = max([num_entries_ipv4, num_entries_ipv6])
    log.debug(f"number of ctmap entries (highest): {num_entries}")
    p = int(num_entries / limit_ctmap_entries_global_any * 100)
    log.debug(f"percentage of ctmap usage (highest): {p}")
    return p


def percentage_natmap(limit_natmap_entries_global: int) -> int:
    num_entries_ipv4 = bpftool_map_elements(
        "/sys/fs/bpf/tc/globals/cilium_snat_v4_external")
    log.debug(f"number of natmap entries (ipv4): {num_entries_ipv4}")
    num_entries_ipv6 = bpftool_map_elements(
        "/sys/fs/bpf/tc/globals/cilium_snat_v6_external")
    log.debug(f"number of natmap entries (ipv6): {num_entries_ipv6}")
    num_entries = max([num_entries_ipv4, num_entries_ipv6])
    log.debug(f"number of natmap entries (highest): {num_entries}")
    p = int(num_entries / limit_natmap_entries_global * 100)
    log.debug(f"percentage of natmap usage (highest): {p}")
    return p


def policymap_entries() -> int:
    policymaps = glob.glob("/sys/fs/bpf/tc/globals/cilium_policy*")
    log.debug(f"found pinned policymaps: {policymaps}")
    # Lookup for elements in all policy maps and pick the highest number.
    num_entries = max(map(bpftool_map_elements, policymaps))
    log.debug(f"number of policymap entries (highest): {num_entries}")
    return num_entries


def percentage_policymaps(limit_policymap_entries: int) -> int:
    num_entries = policymap_entries()
    p = int(num_entries / limit_policymap_entries * 100)
    log.debug(f"percentage of policymap entries (highest): {p}")
    return p


def percentage_dynamic_maps(dynamic_size_ratio: float):
    mem_for_maps = get_mem_total() * dynamic_size_ratio
    total_map_mem_default = CTMAP_ENTRIES_GLOBAL_TCP_DEFAULT * SIZEOF_CT + \
        CTMAP_ENTRIES_GLOBAL_ANY_DEFAULT * SIZEOF_CT + \
        NATMAP_ENTRIES_GLOBAL_DEFAULT * SIZEOF_NAT + \
        POLICYMAP_ENTRIES_DEFAULT * SIZEOF_POLICY

    def get_entries(entries_default: int, min_entries: int,
                    max_entries: int) -> int:
        entries = (entries_default * mem_for_maps) / total_map_mem_default
        if entries < min_entries:
            entries = min_entries
        elif entries > max_entries:
            entries = max_entries
        return entries

    limit_ctmap_entries_global_tcp = get_entries(
        CTMAP_ENTRIES_GLOBAL_TCP_DEFAULT,
        LIMIT_TABLE_MIN, LIMIT_TABLE_MAX)
    limit_ctmap_entries_global_any = get_entries(
        CTMAP_ENTRIES_GLOBAL_ANY_DEFAULT,
        LIMIT_TABLE_MIN, LIMIT_TABLE_MAX)
    limit_natmap_entries_global = get_entries(
        NATMAP_ENTRIES_GLOBAL_DEFAULT,
        LIMIT_TABLE_MIN, LIMIT_TABLE_MAX)
    limit_policymap_entries = get_entries(
        POLICYMAP_ENTRIES_DEFAULT,
        LIMIT_TABLE_MIN, LIMIT_TABLE_MAX)

    p_ctmap_tcp = percentage_ctmap_tcp(limit_ctmap_entries_global_tcp)
    p_ctmap_any = percentage_ctmap_any(limit_ctmap_entries_global_any)
    p_natmap = percentage_natmap(limit_natmap_entries_global)
    p_policymaps = percentage_policymaps(limit_policymap_entries)

    # Pick the highest percentage.
    return max([p_ctmap_tcp, p_ctmap_any, p_natmap, p_policymaps])


def percentage_fixed_policymap():
    limit_policymap_entries = get_configmap("bpf-policy-map-max", int)
    log.debug(f"limit of poilicymap entries: {limit_policymap_entries}")
    num_entries = policymap_entries()

    return int(num_entries / limit_policymap_entries * 100)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--debug", help="enable debug log messages",
                        action="store_true")
    args = parser.parse_args()

    if not args.debug:
        # Disable logger entirely.
        log.propagate = False

    try:
        dynamic_size_ratio = get_configmap("bpf-map-dynamic-size-ratio", float)
    except KeyError:
        log.debug("bpf-map-dynamic-size-ratio not set, checking only policymaps")
        p = percentage_fixed_policymap()
    else:
        log.debug("bpf-map-dynamic-size-ratio is set, checking all dynamically "
                  "allocated maps")
        p = percentage_dynamic_maps(dynamic_size_ratio)
    print(p)


if __name__ == "__main__":
    main()

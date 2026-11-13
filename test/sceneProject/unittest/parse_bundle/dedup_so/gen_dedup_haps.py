#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Device Co., Ltd.
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
"""
Packs the config/ fixture manifests into the minimal .hap zip containers
consumed by the dedup so test suites: ParseDedupFiles does zip-level reads
only, so a plain zip container is a valid stand-in for a packaged HAP.
Usage: gen_dedup_haps.py <config-dir> <out-dir>
"""

import argparse
import os
import sys
import zipfile

# The fixture variants. Every variant maps to config/<variant>.json except
# the synthesized ones: dedup_over_limit (MAX_DEDUP_SO_FILES + 1 entries),
# dedup_max_valid and dedup_size_over_limit (65535 entries padded to exactly
# MAX_DEDUP_FILES_SIZE / +1 bytes) and dedup_depth_bomb (bare open brackets,
# unbounded nesting depth under the size limit). Keep dedup_path_backup_suffix
# in sync with ServiceConstants::DEDUP_SO_BACKUP_SUFFIX.
VARIANTS = [
    "dedup_valid", "dedup_valid_alt_sha", "dedup_valid_multi", "dedup_invalid_json",
    "dedup_json_array", "dedup_no_version", "dedup_no_removed", "dedup_removed_not_array",
    "dedup_item_not_object", "dedup_no_path", "dedup_no_sha", "dedup_path_not_string",
    "dedup_path_traversal", "dedup_path_absolute", "dedup_path_bad_prefix",
    "dedup_path_backup_suffix", "dedup_path_no_so_suffix", "dedup_sha_invalid",
    "dedup_over_limit", "dedup_no_manifest", "dedup_max_valid", "dedup_size_over_limit",
    "dedup_fulldedup_keepdir", "dedup_fulldedup_libsonly", "dedup_fulldedup_stripped",
    "dedup_fulldedup_stripped_mismatch", "dedup_duplicate_entry", "dedup_cross_conflict",
    "dedup_depth_bomb",
]

# Keep in sync with MAX_DEDUP_SO_FILES in services/bundlemgr/src/bundle_parser.cpp.
MAX_DEDUP_SO_FILES = 65535
# Keep in sync with MAX_DEDUP_FILES_SIZE in bundle_extractor.h: the strict
# parser and the loose abi-prefix probe share the single policy constant.
MAX_DEDUP_FILES_SIZE = 16 * 1024 * 1024
FIXED_SHA256 = "31b7479487ad9f817f0fd66f6dcb1c2957e7ca68b432b6f95f1f56bfc976bd60"

# dedup_cross_conflict also carries the very so entry the manifest declares
# as removed, so the manifest-against-container cross check has a real zip
# entry to hit; the parse fails closed before the payload is ever read.
CROSS_CONFLICT_SO_ENTRY = "libs/arm64-v8a/libcross_conflict.so"
CROSS_CONFLICT_SO_PAYLOAD = b"\x7fELF cross-conflict stand-in payload"

# The stage fixtures carry a known-good module.json entry with the dedup
# packaging flags (compressed, non-lib-isolated), so the parse-time abi
# derivation takes the same UpdateNativeSoAttrs branch a real dedup-built
# package takes.
STAGE_MODULE_PROFILE_NAME = "module.json"
STAGE_VARIANTS = ("dedup_fulldedup_libsonly", "dedup_fulldedup_stripped", "dedup_fulldedup_stripped_mismatch")
STAGE_MODULE_JSON = """{
    "app": {
        "bundleName": "com.example.dedupso", "debug": true,
        "icon": "$media:app_icon", "iconId": 16777220,
        "label": "$string:app_name", "labelId": 16777216,
        "minAPIVersion": 9, "minMinorAPIVersion": 0,
        "minPatchAPIVersion": 0, "targetAPIVersion": 9,
        "vendor": "example", "versionCode": 1000000,
        "versionName": "1.0.0"
    },
    "module": {
        "deliveryWithInstall": true,
        "description": "$string:entry_desc", "descriptionId": 16777219,
        "deviceTypes": ["default"],
        "abilities": [{
            "description": "$string:MainAbility_desc", "descriptionId": 16777217,
            "icon": "$media:icon", "iconId": 16777221,
            "label": "$string:MainAbility_label", "labelId": 16777218,
            "name": "MainAbility", "launchType": "standard",
            "orientation": "unspecified",
            "skills": [{
                "actions": ["action.thirdparty.home"],
                "entities": ["entity.system.home", "flag.home.intent.from.system"]
            }],
            "srcEntrance": "./ets/MainAbility/MainAbility.ts", "visible": true
        }],
        "name": "entry", "installationFree": false, "mainElement": "MainAbility",
        "pages": "$profile:main_pages", "srcEntrance": "./ets/Application/AbilityStage.ts",
        "type": "entry", "virtualMachine": "ark0.0.0.3",
        "compressNativeLibs": true, "isLibIsolated": false
    }
}
"""


def build_over_limit_payload():
    entries = ",".join(
        '{"originalPathInHap":"libs/arm64-v8a/libx%05d.so","originalSha256":"%s"}'
        % (index, FIXED_SHA256)
        for index in range(MAX_DEDUP_SO_FILES + 1))
    return ('{"version":"1.0","removedSoFiles":[' + entries + "]}").encode("utf-8")


def build_depth_bomb_payload():
    """~15MB of bare open brackets: under the size limit, near-nothing after
    the zip compression, unbounded depth - pins the pre-DOM depth scan."""
    return b"[" * (15 * 1024 * 1024)


def build_padded_manifest_payload(target_size):
    """Builds a manifest of exactly target_size bytes holding
    MAX_DEDUP_SO_FILES valid entries: pins the declared-size boundary."""
    entry_count = MAX_DEDUP_SO_FILES
    header = '{"version":"1.0","removedSoFiles":['
    footer = "]}"
    entry_prefix = '{"originalPathInHap":"libs/arm64-v8a/libc%05d'
    entry_suffix = '.so","originalSha256":"%s"}' % FIXED_SHA256
    # fixed bytes = header + footer + (entry_count - 1) commas
    fixed = len(header) + len(footer) + entry_count - 1
    entry_bytes = target_size - fixed
    assert entry_bytes > 0, "target_size too small"
    # every index below entry_count formats to the same 5-digit width
    unpadded = len(entry_prefix % 0) + len(entry_suffix)
    pad_total = entry_bytes - entry_count * unpadded
    assert pad_total >= 0, "target_size below the minimum manifest size"
    # distribute the pad evenly; the first pad_total % entry_count entries
    # take one extra byte so the total is exact
    pad_even = pad_total // entry_count
    pad_extra = pad_total % entry_count
    pieces = [header]
    for index in range(entry_count):
        pad = pad_even + (1 if index < pad_extra else 0)
        pieces.append(entry_prefix % index)
        if pad > 0:
            pieces.append("p" * pad)
        pieces.append(entry_suffix)
        if index != entry_count - 1:
            pieces.append(",")
    pieces.append(footer)
    payload = "".join(pieces).encode("utf-8")
    assert len(payload) == target_size, "padded payload is %d, want %d" % (
        len(payload), target_size)
    return payload

# dedup_no_manifest mimics a HAP without a dedupfiles.json: its payload is
# stored as a plain config.json entry the parser does not look for.
DEFAULT_ENTRY = "dedupfiles.json"
ENTRY_NAMES = {"dedup_no_manifest": "config.json"}

# Fixed entry timestamp keeps the generated containers bit-reproducible.
FIXED_DATE_TIME = (2026, 1, 1, 0, 0, 0)


def pack(config_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for variant in VARIANTS:
        entry_name = ENTRY_NAMES.get(variant, DEFAULT_ENTRY)
        if variant == "dedup_over_limit":
            payload = build_over_limit_payload()
        elif variant == "dedup_max_valid":
            payload = build_padded_manifest_payload(MAX_DEDUP_FILES_SIZE)
        elif variant == "dedup_size_over_limit":
            payload = build_padded_manifest_payload(MAX_DEDUP_FILES_SIZE + 1)
        elif variant == "dedup_depth_bomb":
            payload = build_depth_bomb_payload()
        else:
            config_path = os.path.join(config_dir, variant + ".json")
            if not os.path.isfile(config_path):
                print("missing fixture config: %s" % config_path, file=sys.stderr)
                return 1
            with open(config_path, "rb") as config_file:
                payload = config_file.read()
        info = zipfile.ZipInfo(entry_name, date_time=FIXED_DATE_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        hap_path = os.path.join(out_dir, variant + ".hap")
        with zipfile.ZipFile(hap_path, "w") as hap:
            if variant in STAGE_VARIANTS or variant == "dedup_cross_conflict":
                # the stage containers mirror the real packing_tool full-dedup
                # output shape (module.json + manifest, no libs entries);
                # cross_conflict carries the same module.json entry too
                module_info = zipfile.ZipInfo(
                    STAGE_MODULE_PROFILE_NAME, date_time=FIXED_DATE_TIME)
                module_info.compress_type = zipfile.ZIP_DEFLATED
                hap.writestr(module_info, STAGE_MODULE_JSON)
            hap.writestr(info, payload)
            if variant == "dedup_cross_conflict":
                # the three-entry container: the manifest's originalPathInHap
                # also exists as a real zip entry, so the cross check rejects it
                so_info = zipfile.ZipInfo(
                    CROSS_CONFLICT_SO_ENTRY, date_time=FIXED_DATE_TIME)
                so_info.compress_type = zipfile.ZIP_DEFLATED
                hap.writestr(so_info, CROSS_CONFLICT_SO_PAYLOAD)
            if variant == "dedup_fulldedup_keepdir":
                # the fully deduped form that keeps the empty libs/ and
                # libs/<abi>/ dir entries (zero so files)
                for dir_entry in ("libs/", "libs/arm64-v8a/"):
                    hap.writestr(zipfile.ZipInfo(dir_entry, date_time=FIXED_DATE_TIME), b"")
            if variant == "dedup_fulldedup_libsonly":
                # keeps only the top-level libs/ dir entry, so only the
                # manifest abi set can drive the parse-time abi choice
                hap.writestr(zipfile.ZipInfo("libs/", date_time=FIXED_DATE_TIME), b"")
    print("packed %d dedup so fixture containers into %s" % (len(VARIANTS), out_dir))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config_dir", help="directory holding the fixture json files")
    parser.add_argument("out_dir", help="directory the fixture .hap containers are packed into")
    args = parser.parse_args()
    sys.exit(pack(args.config_dir, args.out_dir))


if __name__ == "__main__":
    main()

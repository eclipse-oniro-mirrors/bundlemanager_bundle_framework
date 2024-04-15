/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "sem_ver.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr char PRE_RELEASE_SEPARATOR = '-';
constexpr char BUILD_META_SEPARATOR = '+';
constexpr char DOT = '.';
const size_t NUM_ONE = 1;
const size_t NUM_TWO = 2;
}

SemVer::SemVer(std::string version_string) : raw(version_string)
{
    if (version_string.empty()) {
        return;
    }
    size_t pos1 = version_string.find(PRE_RELEASE_SEPARATOR);
    size_t pos2 = version_string.find(BUILD_META_SEPARATOR);
    std::string base;
    if (pos1 != std::string::npos) {
        base = version_string.substr(0, pos1);
    } else if (pos2 != std::string::npos) {
        base = version_string.substr(0, pos2);
    } else {
        base = version_string;
    }
    std::string preRel = "";
    std::string build = "";
    if (pos1 != std::string::npos) {
        if (pos2 != std::string::npos) {
            preRel = version_string.substr(pos1 + 1, pos2 - pos1 - 1);
            build = version_string.substr(pos2 + 1);
        } else {
            preRel = version_string.substr(pos1 + 1);
        }
    } else if (pos2 != std::string::npos) {
        build = version_string.substr(pos2 + 1);
    }
    std::istringstream issBase(base);
    std::string segment;
    std::vector<std::string> segments;
    while (std::getline(issBase, segment, DOT)) {
        segments.push_back(segment);
    }
    if (!segments.empty()) {
        major = segments[0];
    }
    if (segments.size() > NUM_ONE) {
        minor = segments[NUM_ONE];
    }
    if (segments.size() > NUM_TWO) {
        patch = segments[NUM_TWO];
    }

    std::istringstream issPreRel(preRel);
    std::string segmentPreRel;
    while (std::getline(issPreRel, segmentPreRel, DOT)) {
        prerelease.push_back(segmentPreRel);
    }
    std::istringstream issBuild(build);
    std::string segmentBuild;
    while (std::getline(issBuild, segmentBuild, DOT)) {
        buildMeta.push_back(segmentBuild);
    }
}
} // namespace AppExecFwk
} // namespace OHOS
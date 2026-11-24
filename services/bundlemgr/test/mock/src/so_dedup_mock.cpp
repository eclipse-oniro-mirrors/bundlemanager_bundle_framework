/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <string>

#include "so_dedup/so_dedup.h"

namespace OHOS {
namespace AppExecFwk {
// Injectable knobs of the link-time libc OH_LinkDedupedSo stub: the extern "C"
// definition below shadows the libc symbol, keeping the passthrough deterministic.
uint32_t g_muslLinkDedupedSoResult = 0;
int32_t g_muslLinkDedupedSoCallCount = 0;
std::string g_muslLinkDedupedSoLastPath;
std::string g_muslLinkDedupedSoLastSha;
} // namespace AppExecFwk
} // namespace OHOS

extern "C" uint32_t OH_LinkDedupedSo(const char *library_path, const char *original_sha256)
{
    using namespace OHOS::AppExecFwk;
    ++g_muslLinkDedupedSoCallCount;
    g_muslLinkDedupedSoLastPath = (library_path == nullptr) ? "" : library_path;
    g_muslLinkDedupedSoLastSha = (original_sha256 == nullptr) ? "" : original_sha256;
    return g_muslLinkDedupedSoResult;
}

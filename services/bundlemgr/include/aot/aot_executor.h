/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_EXECUTOR
#define FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_EXECUTOR

#include <mutex>
#include <nlohmann/json.hpp>
#include <unordered_map>

#include "aot/aot_args.h"
#include "appexecfwk_errors.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
struct AOTState {
    bool running = false;
    std::string outputPath;
};

class AOTExecutor final {
public:
    static AOTExecutor& GetInstance();
    void ExecuteAOT(const AOTArgs &aotArgs, ErrCode &ret, std::vector<uint8_t> &pendSignData);
    ErrCode PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData) const;
    ErrCode StopAOT();
private:
    AOTExecutor() = default;
    ~AOTExecutor() = default;
    DISALLOW_COPY_AND_MOVE(AOTExecutor);

    std::string DecToHex(uint32_t decimal) const;
    bool CheckArgs(const AOTArgs &aotArgs) const;
    bool GetAbcFileInfo(const std::string &hapPath, uint32_t &offset, uint32_t &length) const;
    ErrCode PrepareArgs(const AOTArgs &aotArgs, AOTArgs &completeArgs) const;
    nlohmann::json GetSubjectInfo(const AOTArgs &aotArgs) const;
    void MapArgs(const AOTArgs &aotArgs, std::unordered_map<std::string, std::string> &argsMap);
    ErrCode EnforceCodeSign(const std::string &anFileName, const std::vector<uint8_t> &signData) const;
    ErrCode StartAOTCompiler(const AOTArgs &aotArgs, std::vector<uint8_t> &signData);
    void InitState(const AOTArgs &aotArgs);
    void ResetState();
private:
    mutable std::mutex stateMutex_;
    AOTState state_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_EXECUTOR

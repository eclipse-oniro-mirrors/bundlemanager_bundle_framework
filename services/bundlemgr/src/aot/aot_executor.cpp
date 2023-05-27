/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "aot/aot_executor.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_extractor.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string ABC_RELATIVE_PATH = "ets/modules.abc";
const std::string HEX_PREFIX = "0x";
}

AOTExecutor& AOTExecutor::GetInstance()
{
    static AOTExecutor executor;
    return executor;
}

std::string AOTExecutor::DecToHex(uint32_t decimal) const
{
    return "";
}

bool AOTExecutor::CheckArgs(const AOTArgs &aotArgs) const
{
    return false;
}

bool AOTExecutor::GetAbcFileInfo(const std::string &hapPath, uint32_t &offset, uint32_t &length) const
{
    return false;
}

ErrCode AOTExecutor::PrepareArgs(const AOTArgs &aotArgs, AOTArgs &completeArgs) const
{
    return ERR_OK;
}

void AOTExecutor::ExecuteInChildProcess(const AOTArgs &aotArgs) const
{
}

void AOTExecutor::ExecuteInParentProcess(pid_t childPid, ErrCode &ret) const
{
}

void AOTExecutor::ExecuteAOT(const AOTArgs &aotArgs, ErrCode &ret) const
{
}
}  // namespace AppExecFwk
}  // namespace OHOS

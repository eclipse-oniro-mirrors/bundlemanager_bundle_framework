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

#include "aot/aot_handler.h"

#include <vector>

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "parameter.h"
#include "parameters.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
AOTHandler& AOTHandler::GetInstance()
{
    static AOTHandler handler;
    return handler;
}

bool AOTHandler::IsSupportARM64() const
{
    return false;
}

std::string AOTHandler::GetArkProfilePath(const std::string &bundleName, const std::string &moduleName) const
{
    return Constants::EMPTY_STRING;
}

std::optional<AOTArgs> AOTHandler::BuildAOTArgs(
    const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const
{
    return std::nullopt;
}

void AOTHandler::HandleInstall(const InnerBundleInfo &info, const std::string &compileMode) const
{
}

void AOTHandler::HandleInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
}

void AOTHandler::ResetAOTFlags() const
{
}

void AOTHandler::HandleOTA() const
{
}

void AOTHandler::HandleIdleWithSingleHap(
    const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const
{
}

void AOTHandler::HandleIdle() const
{
}
}  // namespace AppExecFwk
}  // namespace OHOS

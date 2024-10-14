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

#include "mock_installd_proxy.h"

namespace {
static OHOS::ErrCode isExistFileCode_ = OHOS::ERR_OK;
static OHOS::ErrCode isExistDirCode_ = OHOS::ERR_OK;
static OHOS::ErrCode mkdirCode_ = OHOS::ERR_OK;
static OHOS::ErrCode pendSignAOT_ = OHOS::ERR_OK;
}

void SetIsExistFileCode(OHOS::ErrCode isExistFileCode)
{
    isExistFileCode_ = isExistFileCode;
}

void SetIsExistDirCode(OHOS::ErrCode isExistDirCode)
{
    isExistDirCode_ = isExistDirCode;
}

void SetMkdirCode(OHOS::ErrCode mkdirCode)
{
    mkdirCode_ = mkdirCode;
}

void SetPendSignAOTCode(OHOS::ErrCode pendSignAOT)
{
    pendSignAOT_ = pendSignAOT;
}
namespace OHOS {
namespace AppExecFwk {
MockInstalldProxy::MockInstalldProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IInstalld>(object)
{}

MockInstalldProxy::~MockInstalldProxy()
{}

ErrCode MockInstalldProxy::IsExistFile(const std::string &path, bool &isExist)
{
    return isExistFileCode_;
}

ErrCode MockInstalldProxy::IsExistDir(const std::string &dir, bool &isExist)
{
    return isExistDirCode_;
}

ErrCode MockInstalldProxy::Mkdir(
    const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid)
{
    return mkdirCode_;
}

ErrCode MockInstalldProxy::PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData)
{
    return pendSignAOT_;
}
} // AppExecFwk
} // OHOS
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_INSTALLD_PROXY_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_INSTALLD_PROXY_H

#include "iremote_proxy.h"
#include "ipc/installd_interface.h"

namespace OHOS {
namespace AppExecFwk {
class MockInstalldProxy : public IRemoteProxy<IInstalld> {
public:
    MockInstalldProxy(const sptr<IRemoteObject> &object);
    virtual ~MockInstalldProxy() override;
    virtual ErrCode IsExistFile(const std::string &path, bool &isExist) override;
    virtual ErrCode IsExistDir(const std::string &dir, bool &isExist) override;
    virtual ErrCode Mkdir(
        const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid) override;
    virtual ErrCode PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData) override;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_INSTALLD_PROXY_H

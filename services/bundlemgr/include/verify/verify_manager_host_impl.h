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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_VERIFY_VERIFY_MANAGER_PROXY_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_VERIFY_VERIFY_MANAGER_PROXY_H

#include "verify_manager_host.h"

namespace OHOS {
namespace AppExecFwk {
class VerifyManagerHostImpl : public VerifyManagerHost {
public:
    VerifyManagerHostImpl();
    virtual ~VerifyManagerHostImpl();

    ErrCode Verify(const std::vector<std::string> &abcPaths,
        const std::vector<std::string> &abcNames, bool flag) override;

    ErrCode CreateFd(const std::string &fileName, int32_t &fd, std::string &path) override;
    ErrCode DeleteAbc(const std::string &path) override;

private:
    ErrCode InnerVerify(const std::vector<std::string> &abcPaths,
        const std::vector<std::string> &abcNames, bool flag);
    bool VerifyAbc(const std::vector<std::string> &abcPaths);
    bool MoveAbc(const std::vector<std::string> &abcPaths,
        const std::vector<std::string> &abcNames, const std::string &pathDir);
    void Rollback(const std::vector<std::string> &paths);
    bool GetFileName(const std::string &sourcePath, std::string &fileName);
    bool GetFileDir(const std::string &sourcePath, std::string &fileDir);
    void RemoveTempFiles(const std::vector<std::string> &paths);
    ErrCode MkdirIfNotExist(const std::string &dir);

    std::atomic<uint32_t> id_ = 0;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_VERIFY_VERIFY_MANAGER_PROXY_H

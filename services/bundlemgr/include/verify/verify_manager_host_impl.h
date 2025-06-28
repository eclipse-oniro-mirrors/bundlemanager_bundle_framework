/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <mutex>
#include <shared_mutex>
#include "bundle_memory_guard.h"
#include "verify_manager_stub.h"

namespace OHOS {
namespace AppExecFwk {
class VerifyManagerHostImpl : public VerifyManagerStub {
public:
    VerifyManagerHostImpl();
    virtual ~VerifyManagerHostImpl();

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;

    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

    ErrCode Verify(const std::vector<std::string> &abcPaths, int32_t &funcResult) override;

    ErrCode DeleteAbc(const std::string &path, int32_t &funcResult) override;

private:
    ErrCode InnerVerify(const std::string &bundleName,
        const std::vector<std::string> &abcPaths);
    bool CopyFilesToTempDir(const std::string &bundleName, int32_t userId,
        const std::vector<std::string> &abcPaths);
    bool VerifyAbc(const std::vector<std::string> &abcPaths);
    bool MoveAbc(const std::string &bundleName,
        const std::vector<std::string> &abcPaths);
    void Rollback(const std::vector<std::string> &paths);
    bool GetFileName(const std::string &sourcePath, std::string &fileName);
    bool GetFileDir(const std::string &sourcePath, std::string &fileDir);
    void RemoveTempFiles(const std::string &bundleName);
    void RemoveTempFiles(const std::vector<std::string> &paths);
    bool VerifyAbc(
        const std::string &rootDir, const std::vector<std::string> &names);
    bool CheckFileParam(const std::vector<std::string> &abcPaths);
    void Rollback(const std::string &rootDir, const std::vector<std::string> &names);
    ErrCode MkdirIfNotExist(const std::string &dir);
    std::mutex &GetBundleMutex(const std::string &bundleName);
    std::string GetRealPath(const std::string &bundleName,
        int32_t userId, const std::string &relativePath);
    bool GetCallingBundleName(std::string &bundleName);
    ErrCode VerifyDeleteAbcPermission(const std::string &path);

    std::atomic<uint32_t> id_ = 0;
    mutable std::shared_mutex bundleMutex_;
    // using for locking by bundleName
    std::unordered_map<std::string, std::mutex> bundleMutexMap_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_VERIFY_VERIFY_MANAGER_PROXY_H

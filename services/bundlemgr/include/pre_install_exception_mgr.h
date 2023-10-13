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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PREINSTALL_EXCEPTION_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PREINSTALL_EXCEPTION_MGR_H

#include <mutex>
#include <set>
#include <string>

namespace OHOS {
namespace AppExecFwk {
class PreInstallExceptionMgr {
public:
    PreInstallExceptionMgr();
    ~PreInstallExceptionMgr();

    bool GetAllPreInstallExceptionInfo(
        std::set<std::string> &exceptionPaths, std::set<std::string> &exceptionBundleNames);
    void SavePreInstallExceptionPath(const std::string &path);
    void DeletePreInstallExceptionPath(const std::string &path);
    void SavePreInstallExceptionBundleName(const std::string &bundleName);
    void DeletePreInstallExceptionBundleName(const std::string &bundleName);
    void ClearAll();

private:
    bool LoadPreInstallExceptionInfosFromDb();
    void SavePreInstallExceptionInfosToDb();
    void DeletePreInstallExceptionInfosFromDb();

    std::mutex preInstallExceptionMutex_;
    std::set<std::string> exceptionPaths_;
    std::set<std::string> exceptionBundleNames_;
    bool hasInit_ = false;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PREINSTALL_EXCEPTION_MGR_H
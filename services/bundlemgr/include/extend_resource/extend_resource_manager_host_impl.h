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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_EXTEND_RESOURCE_MANAGER_HOST_IMPL_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_EXTEND_RESOURCE_MANAGER_HOST_IMPL_H

#include "extend_resource_manager_host.h"
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class ExtendResourceManagerHostImpl : public ExtendResourceManagerHost {
public:
    ExtendResourceManagerHostImpl();
    virtual ~ExtendResourceManagerHostImpl();

    ErrCode AddExtResource(
        const std::string &bundleName, const std::vector<std::string> &filePaths) override;
    ErrCode RemoveExtResource(
        const std::string &bundleName, const std::vector<std::string> &moduleNames) override;
    ErrCode GetExtResource(
        const std::string &bundleName, std::vector<std::string> &moduleNames) override;
    virtual ErrCode EnableDynamicIcon(
        const std::string &bundleName, const std::string &moduleName,
        const int32_t userId, const int32_t appIndex) override;
    virtual ErrCode DisableDynamicIcon(const std::string &bundleName,
        const int32_t userId, const int32_t appIndex) override;
    virtual ErrCode GetDynamicIcon(
        const std::string &bundleName, const int32_t userId, const int32_t appIndex, std::string &moduleName) override;

    ErrCode CreateFd(const std::string &fileName, int32_t &fd, std::string &path) override;

private:
    ErrCode BeforeAddExtResource(
        const std::string &bundleName, const std::vector<std::string> &filePaths);
    bool CheckFileParam(const std::string &filePath);
    ErrCode ProcessAddExtResource(
        const std::string &bundleName, const std::vector<std::string> &filePaths);
    ErrCode CopyToTempDir(const std::string &bundleName,
        const std::vector<std::string> &oldFilePaths, std::vector<std::string> &newFilePaths);
    bool GetInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info);
    void RollBack(const std::vector<std::string> &filePaths);
    ErrCode MkdirIfNotExist(const std::string &dir);
    ErrCode ParseExtendResourceFile(
        const std::string &bundleName,
        const std::vector<std::string> &filePaths,
        std::vector<ExtendResourceInfo> &extendResourceInfos);
    bool UpateExtResourcesDb(const std::string &bundleName,
        const std::vector<ExtendResourceInfo> &extendResourceInfos);
    bool RemoveExtResourcesDb(
        const std::string &bundleName, const std::vector<std::string> &moduleNames);
    void InnerSaveExtendResourceInfo(
        const std::string &bundleName, const std::vector<std::string> &filePaths,
        const std::vector<ExtendResourceInfo> &extendResourceInfos);
    ErrCode CheckModuleExist(
        const std::string &bundleName, const std::vector<std::string> &moduleNames,
        std::vector<ExtendResourceInfo> &collectorExtResourceInfos);
    void InnerRemoveExtendResources(
        const std::string &bundleName, const std::vector<std::string> &moduleNames,
        std::vector<ExtendResourceInfo> &extResourceInfos);
    ErrCode GetExtendResourceInfo(const std::string &bundleName,
        const std::string &moduleName, ExtendResourceInfo &extendResourceInfo,
        const int32_t userId = Constants::ALL_USERID, const int32_t appIndex = Constants::ALL_USERID);
    bool ParseBundleResource(
        const std::string &bundleName, const ExtendResourceInfo &extendResourceInfo,
        const int32_t userId = Constants::ALL_USERID, const int32_t appIndex = Constants::ALL_USERID);
    void SendBroadcast(const std::string &bundleName, bool isEnableDynamicIcon,
        const int32_t userId = Constants::ALL_USERID, const int32_t appIndex = Constants::ALL_USERID);
    void SaveCurDynamicIcon(const std::string &bundleName, const std::string &moduleName,
        const int32_t userId = Constants::ALL_USERID, const int32_t appIndex = Constants::ALL_USERID);
    bool ResetBundleResourceIcon(const std::string &bundleName,
        const int32_t userId = Constants::ALL_USERID, const int32_t appIndex = Constants::ALL_USERID);
    ErrCode CheckParamInvalid(const InnerBundleInfo &bundleInfo,
        const int32_t userId, const int32_t appIndex);

    std::atomic<uint32_t> id_ = 0;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICE_BUNDLEMGR_INCLUDE_EXTEND_RESOURCE_MANAGER_HOST_IMPL_H

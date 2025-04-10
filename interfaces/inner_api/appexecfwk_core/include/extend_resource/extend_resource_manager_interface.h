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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_EXTEND_RESOURCE_MGR_INTERFACE_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_EXTEND_RESOURCE_MGR_INTERFACE_H

#include <vector>
#include <string>

#include "appexecfwk_errors.h"
#include "dynamic_icon_info.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {
class IExtendResourceManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleManager.ExtendResourceManager");

    virtual ErrCode AddExtResource(
        const std::string &bundleName, const std::vector<std::string> &filePaths)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode RemoveExtResource(
        const std::string &bundleName, const std::vector<std::string> &moduleNames)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetExtResource(
        const std::string &bundleName, std::vector<std::string> &moduleNames)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode EnableDynamicIcon(
        const std::string &bundleName, const std::string &moduleName)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode EnableDynamicIcon(
        const std::string &bundleName, const std::string &moduleName, const int32_t userId, const int32_t appIndex)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode DisableDynamicIcon(const std::string &bundleName)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode DisableDynamicIcon(const std::string &bundleName, const int32_t userId, const int32_t appIndex)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetDynamicIcon(const std::string &bundleName, std::string &moduleName)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetDynamicIcon(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex, std::string &moduleName)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode CopyFiles(
        const std::vector<std::string> &sourceFiles, std::vector<std::string> &destFiles)
    {
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    virtual ErrCode GetAllDynamicIconInfo(std::vector<DynamicIconInfo> &dynamicInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetAllDynamicIconInfo(const int32_t userId, std::vector<DynamicIconInfo> &dynamicInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_EXTEND_RESOURCE_MGR_INTERFACE_H
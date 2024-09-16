/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALL_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALL_PARAM_H

#include <map>
#include <string>
#include <vector>

#include "application_info.h"
#include "bundle_constants.h"
#include "parcel.h"
namespace OHOS {
namespace AppExecFwk {
enum class InstallFlag : int8_t {
    NORMAL = 0,
    // Allow to replace the existing bundle when the new version isn't lower than the old one.
    // If the bundle does not exist, just like normal flag.
    REPLACE_EXISTING = 1,
    FREE_INSTALL = 0x10,
};

enum class InstallLocation : int8_t {
    INTERNAL_ONLY = 1,
    PREFER_EXTERNAL = 2,
};

enum class PermissionStatus : int8_t {
    NOT_VERIFIED_PERMISSION_STATUS = 0,
    HAVE_PERMISSION_STATUS,
    NON_HAVE_PERMISSION_STATUS
};

// provides parameters required for installing or uninstalling an application
struct InstallParam : public Parcelable {
    InstallFlag installFlag = InstallFlag::NORMAL;
    InstallLocation installLocation = InstallLocation::INTERNAL_ONLY;
    int64_t crowdtestDeadline = Constants::INVALID_CROWDTEST_DEADLINE; // for crowdtesting type hap
    int32_t userId = Constants::UNSPECIFIED_USERID;
    // is keep user data while uninstall.
    bool isKeepData = false;
    bool needSavePreInstallInfo = false;
    bool isPreInstallApp = false;
    bool removable = true;
    // the profile-guided optimization(PGO) file path
    std::map<std::string, std::string> pgoParams;
    // whether need copy hap to install path
    bool copyHapToInstallPath = true;
    // is aging Cause uninstall.
    bool isAgingUninstall = false;
    bool needSendEvent = true;
    bool withCopyHaps = false;
    // for MDM self update
    bool isSelfUpdate = false;
    std::map<std::string, std::string> hashParams;
    // shared bundle directory paths
    std::vector<std::string> sharedBundleDirPaths;
    // status of install bundle permission
    PermissionStatus installBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of install enterprise bundle permission
    PermissionStatus installEnterpriseBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of install enterprise normal bundle permission
    PermissionStatus installEtpNormalBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of install enterprise mdm bundle permission
    PermissionStatus installEtpMdmBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of install internaltesting bundle permission
    PermissionStatus installInternaltestingBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // status of mdm update bundle for self
    PermissionStatus installUpdateSelfBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;
    // is shell token
    bool isCallByShell = false;
    // for AOT
    bool isOTA = false;
    bool concentrateSendEvent = false;
    bool isRemoveUser = false;
    bool allUser = false;
    // Indicates the distribution type
    std::string specifiedDistributionType = "";
    // Indicates the additional Info
    std::string additionalInfo = "";
    // utilizing for code-signature
    std::map<std::string, std::string> verifyCodeParams;
    ApplicationInfoFlag preinstallSourceFlag = ApplicationInfoFlag::FLAG_INSTALLED;
    // the parcel object function is not const.
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static InstallParam *Unmarshalling(Parcel &parcel);

private:
    // should force uninstall when delete userinfo.
    bool forceExecuted = false;
    // OTA upgrade skips the killing process
    bool killProcess = true;
    // system app can be uninstalled when uninstallUpdates
    bool isUninstallAndRecover = false;

public:
    bool GetForceExecuted() const
    {
        return forceExecuted;
    }

    void SetForceExecuted(bool value)
    {
        if (CheckPermission()) {
            forceExecuted = value;
        }
    }

    bool GetKillProcess() const
    {
        return killProcess;
    }

    void SetKillProcess(bool value)
    {
        if (CheckPermission()) {
            killProcess = value;
        }
    }

    bool GetIsUninstallAndRecover() const
    {
        return isUninstallAndRecover;
    }

    void SetIsUninstallAndRecover(bool value)
    {
        if (CheckPermission()) {
            isUninstallAndRecover = value;
        }
    }

private:
    bool CheckPermission() const;
};

struct UninstallParam : public Parcelable {
    std::string bundleName;
    std::string moduleName;
    int32_t versionCode = Constants::ALL_VERSIONCODE;
    int32_t userId = Constants::UNSPECIFIED_USERID;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static UninstallParam *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INSTALL_PARAM_H

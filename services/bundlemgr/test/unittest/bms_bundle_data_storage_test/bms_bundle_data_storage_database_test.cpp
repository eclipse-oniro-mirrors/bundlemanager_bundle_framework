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

#include <fstream>
#include <gtest/gtest.h>

#include "app_log_wrapper.h"
#include "ability_info.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "inner_bundle_user_info.h"
#include "inner_bundle_info.h"
#include "json_constants.h"
#include "json_serializer.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::JsonConstants;

namespace {
const std::string NORMAL_BUNDLE_NAME{"com.example.test"};
}  // namespace

class BmsBundleDataStorageDatabaseTest : public testing::Test {
public:
    BmsBundleDataStorageDatabaseTest();
    ~BmsBundleDataStorageDatabaseTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    enum class InfoType {
        BUNDLE_INFO,
        APPLICATION_INFO,
        ABILITY_INFO,
    };
    void CheckInvalidPropDeserialize(const nlohmann::json infoJson, const InfoType infoType) const;

protected:
    nlohmann::json innerBundleInfoJson_ = R"(
        {
            "allowedAcls": [],
            "appFeature": "ohos_system_app",
            "appType": 0,
            "baseAbilityInfos": {
                "com.ohos.launcher.com.ohos.launcher.com.ohos.launcher.MainAbility": {
                    "applicationInfo": {
                        "accessTokenId": 0,
                        "accessible": false,
                        "apiCompatibleVersion": 0,
                        "apiReleaseType": "",
                        "apiTargetVersion": 0,
                        "appPrivilegeLevel": "normal",
                        "arkNativeFileAbi": "",
                        "arkNativeFilePath": "",
                        "bundleName": "",
                        "bundleType": 0,
                        "cacheDir": "",
                        "codePath": "",
                        "cpuAbi": "",
                        "dataBaseDir": "",
                        "dataDir": "",
                        "debug": false,
                        "description": "",
                        "descriptionId": 0,
                        "descriptionResource": {
                            "bundleName": "",
                            "id": 0,
                            "moduleName": ""
                        },
                        "deviceId": "",
                        "distributedNotificationEnabled": true,
                        "enabled": false,
                        "entityType": "",
                        "entryDir": "",
                        "entryModuleName": "",
                        "flags": 0,
                        "icon": "",
                        "iconId": 0,
                        "iconPath": "",
                        "iconResource": {
                            "bundleName": "",
                            "id": 0,
                            "moduleName": ""
                        },
                        "fingerprint": "",
                        "isCompressNativeLibs": true,
                        "isLauncherApp": false,
                        "isSystemApp": false,
                        "keepAlive": false,
                        "label": "",
                        "labelId": 0,
                        "labelResource": {
                            "bundleName": "",
                            "id": 0,
                            "moduleName": ""
                        },
                        "asanEnabled": false,
                        "asanLogPath": "",
                        "metaData": {},
                        "metadata": {},
                        "minCompatibleVersionCode": 0,
                        "moduleInfos": [],
                        "moduleSourceDirs": [],
                        "name": "",
                        "nativeLibraryPath": "",
                        "permissions": [],
                        "targetBundleList": [
                        ],
                        "isFreeInstallApp": false,
                        "process": "",
                        "removable": true,
                        "signatureKey": "",
                        "split": false,
                        "multiProjects":false,
                        "singleton": false,
                        "supportedModes": 0,
                        "uid": -1,
                        "userDataClearable": true,
                        "vendor": "",
                        "versionCode": 0,
                        "versionName": "",
                        "appDistributionType": "none",
                        "appProvisionType": "release",
                        "appQuickFix": {
                            "bundleName": "",
                            "deployedAppqfInfo": {
                                "cpuAbi": "",
                                "hqfInfos": [],
                                "nativeLibraryPath": "",
                                "type": 0,
                                "versionCode": 0,
                                "versionName": ""
                            },
                            "deployingAppqfInfo": {
                                "cpuAbi": "",
                                "hqfInfos": [],
                                "nativeLibraryPath": "",
                                "type": 0,
                                "versionCode": 0,
                                "versionName": ""
                            },
                            "versionCode": 0,
                            "versionName": ""
                        },
                        "crowdtestDeadline": -1,
                        "runningResourcesApply": false,
                        "associatedWakeUp": false,
                        "hideDesktopIcon": false,
                        "formVisibleNotify": false,
                        "allowCommonEvent": [],
                        "needAppDetail": false,
                        "appDetailAbilityLibraryPath": ""
                    },
                    "extensionAbilityType": 9,
                    "priority": 0,
                    "startWindowIcon":"",
                    "startWindowIconId":0,
                    "startWindowBackground":"",
                    "startWindowBackgroundId":0,
                    "supportWindowMode": [],
                    "maxWindowRatio":0,
                    "minWindowRatio":0,
                    "maxWindowWidth":0,
                    "minWindowWidth":0,
                    "maxWindowHeight":0,
                    "minWindowHeight":0,
                    "uid": -1,
                    "applicationName": "com.ohos.launcher",
                    "backgroundModes": 0,
                    "bundleName": "com.ohos.launcher",
                    "codePath": "",
                    "compileMode": 0,
                    "configChanges": [
                    ],
                    "continuable": false,
                    "defaultFormHeight": 0,
                    "defaultFormWidth": 0,
                    "description": "$string:mainability_description",
                    "descriptionId": 218103837,
                    "deviceCapabilities": [
                    ],
                    "deviceTypes": [
                        "phone"
                    ],
                    "enabled": true,
                    "formEnabled": false,
                    "formEntity": 0,
                    "iconId": 218103847,
                    "iconPath": "$media:icon",
                    "isLauncherAbility": true,
                    "removeMissionAfterTerminate":false,
                    "excludeFromMissions":false,
                    "isModuleJson": false,
                    "isNativeAbility": false,
                    "isStageBasedModel": true,
                    "kind": "page",
                    "label": "$string:entry_MainAbility",
                    "labelId": 218103828,
                    "launchMode": 0,
                    "metaData": {
                        "customizeData": [
                            {
                                "extra": "",
                                "name": "",
                                "value": ""
                            }
                        ]
                    },
                    "metadata": [
                    ],
                    "minFormHeight": 0,
                    "minFormWidth": 0,
                    "moduleName": "phone",
                    "name": "com.ohos.launcher.MainAbility",
                    "orientation": 0,
                    "package": "com.ohos.launcher",
                    "permissions": [
                    ],
                    "process": "",
                    "readPermission": "",
                    "resourcePath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher/assets/phone/resources.index",
                    "hapPath" : "",
                    "srcEntrance": "",
                    "srcLanguage": "ets",
                    "srcPath": "MainAbility",
                    "supportPipMode": false,
                    "targetAbility": "",
                    "theme": "",
                    "type": 1,
                    "uri": "",
                    "visible": true,
                    "writePermission": ""
                },
                "com.ohos.launcher.com.ohos.launcher.recents.com.ohos.launcher.recents.MainAbility": {
                    "applicationName": "com.ohos.launcher",
                    "backgroundModes": 0,
                    "bundleName": "com.ohos.launcher",
                    "codePath": "",
                    "configChanges": [
                    ],
                    "continuable": false,
                    "defaultFormHeight": 0,
                    "defaultFormWidth": 0,
                    "description": "$string: mainability_description",
                    "descriptionId": 251658241,
                    "deviceCapabilities": [
                    ],
                    "deviceId": "",
                    "deviceTypes": [
                        "phone"
                    ],
                    "enabled": true,
                    "formEnabled": false,
                    "formEntity": 0,
                    "iconId": 251658246,
                    "iconPath": "$media: icon",
                    "isLauncherAbility": false,
                    "removeMissionAfterTerminate":false,
                    "excludeFromMissions":false,
                    "isModuleJson": false,
                    "isNativeAbility": false,
                    "isStageBasedModel": true,
                    "kind": "page",
                    "label": "$string: recents_MainAbility",
                    "labelId": 251658242,
                    "launchMode": 0,
                    "libPath": "",
                    "metaData": {
                        "customizeData": [
                            {
                                "extra": "",
                                "name": "",
                                "value": ""
                            }
                        ]
                    },
                    "metadata": [
                    ],
                    "minFormHeight": 0,
                    "minFormWidth": 0,
                    "moduleName": "recents",
                    "name": "com.ohos.launcher.recents.MainAbility",
                    "orientation": 0,
                    "package": "com.ohos.launcher.recents",
                    "permissions": [
                    ],
                    "process": "",
                    "readPermission": "",
                    "resourcePath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher.recents/assets/recents/resources.index",
                    "hapPath" : "",
                    "srcEntrance": "",
                    "srcLanguage": "ets",
                    "srcPath": "MainAbility",
                    "supportPipMode": false,
                    "targetAbility": "",
                    "theme": "",
                    "type": 1,
                    "uri": "",
                    "visible": true,
                    "writePermission": ""
                },
                "com.ohos.launcher.com.ohos.launcher.settings.com.ohos.launcher.settings.MainAbility": {
                    "applicationName": "com.ohos.launcher",
                    "backgroundModes": 0,
                    "bundleName": "com.ohos.launcher",
                    "codePath": "",
                    "configChanges": [
                    ],
                    "continuable": false,
                    "defaultFormHeight": 0,
                    "defaultFormWidth": 0,
                    "description": "$string: mainability_description",
                    "descriptionId": 285212677,
                    "deviceCapabilities": [
                    ],
                    "deviceId": "",
                    "deviceTypes": [
                        "phone"
                    ],
                    "enabled": true,
                    "formEnabled": false,
                    "formEntity": 0,
                    "iconId": 285212682,
                    "iconPath": "$media: icon",
                    "isLauncherAbility": false,
                    "removeMissionAfterTerminate":false,
                    "excludeFromMissions":false,
                    "isModuleJson": false,
                    "isNativeAbility": false,
                    "isStageBasedModel": true,
                    "kind": "page",
                    "label": "$string: settings_MainAbility",
                    "labelId": 285212679,
                    "launchMode": 0,
                    "libPath": "",
                    "metaData": {
                        "customizeData": [
                        ]
                    },
                    "metadata": [
                    ],
                    "minFormHeight": 0,
                    "minFormWidth": 0,
                    "moduleName": "settings",
                    "name": "com.ohos.launcher.settings.MainAbility",
                    "orientation": 0,
                    "package": "com.ohos.launcher.settings",
                    "permissions": [
                    ],
                    "process": "",
                    "readPermission": "",
                    "resourcePath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher.settings/assets/settings/resources.index",
                    "hapPath" : "",
                    "srcEntrance": "",
                    "srcLanguage": "ets",
                    "srcPath": "MainAbility",
                    "supportPipMode": false,
                    "targetAbility": "",
                    "theme": "",
                    "type": 1,
                    "uri": "",
                    "visible": true,
                    "writePermission": ""
                }
            },
            "baseApplicationInfo": {
                "accessTokenId": 0,
                "accessible": false,
                "apiCompatibleVersion": 8,
                "apiReleaseType": "Beta1",
                "apiTargetVersion": 8,
                "appPrivilegeLevel": "normal",
                "appQuickFix": {
                    "bundleName": "",
                    "versionCode": 0,
                    "versionName": "",
                    "deployedAppqfInfo": {
                        "cpuAbi": "",
                        "hqfInfos": [],
                        "nativeLibraryPath": "",
                        "type": 0,
                        "versionCode": 0,
                        "versionName": ""
                    },
                    "deployingAppqfInfo": {
                        "cpuAbi": "",
                        "hqfInfos": [],
                        "nativeLibraryPath": "",
                        "type": 0,
                        "versionCode": 0,
                        "versionName": ""
                    }
                },
                "arkNativeFileAbi": "",
                "arkNativeFilePath": "",
                "asanEnabled": false,
                "bundleType": "app",
                "asanLogPath": "",
                "bundleName": "com.ohos.launcher",
                "bundleType": 0,
                "cacheDir": "/data/app/el2/100/base/com.ohos.launcher/cache",
                "codePath": "/data/app/el1/bundle/public/com.ohos.launcher",
                "cpuAbi": "armeabi-v7a",
                "dataBaseDir": "/data/app/el2/100/database/com.ohos.launcher",
                "dataDir": "/data/app/el2/100/base/com.ohos.launcher",
                "debug": false,
                "description": "$string: mainability_description",
                "descriptionId": 218103837,
                "descriptionResource": {
                    "bundleName": "",
                    "id": 0,
                    "moduleName": ""
                },
                "deviceId": "PHONE-001",
                "distributedNotificationEnabled": true,
                "enabled": true,
                "entityType": "unspecified",
                "entryDir": "",
                "entryModuleName": "",
                "flags": 0,
                "icon": "",
                "iconId": 218103847,
                "iconPath": "$media: icon",
                "iconResource": {
                    "bundleName": "",
                    "id": 0,
                    "moduleName": ""
                },
                "fingerprint":"",
                "isCompressNativeLibs": true,
                "isLauncherApp": true,
                "isSystemApp": true,
                "keepAlive": false,
                "label": "$string: entry_MainAbility",
                "labelId": 218103828,
                "labelResource": {
                    "bundleName": "",
                    "id": 0,
                    "moduleName": ""
                },
                "metaData": {
                },
                "metadata": {
                },
                "minCompatibleVersionCode": 1000000,
                "moduleInfos": [
                ],
                "moduleSourceDirs": [
                ],
                "name": "com.ohos.launcher",
                "nativeLibraryPath": "",
                "permissions": [
                ],
                "targetBundleList": [
                ],
                "isFreeInstallApp": false,
                "process": "",
                "removable": false,
                "signatureKey": "",
                "multiProjects":false,
                "singleton": false,
                "split": false,
                "supportedModes": 0,
                "uid": -1,
                "userDataClearable": true,
                "vendor": "ohos",
                "versionCode": 1000000,
                "versionName": "1.0.0",
                "appDistributionType": "none",
                "appProvisionType": "release",
                "appQuickFix": {
                    "bundleName": "",
                    "deployedAppqfInfo": {
                        "cpuAbi": "",
                        "hqfInfos": [],
                        "nativeLibraryPath": "",
                        "type": 0,
                        "versionCode": 0,
                        "versionName": ""
                    },
                    "deployingAppqfInfo": {
                        "cpuAbi": "",
                        "hqfInfos": [],
                        "nativeLibraryPath": "",
                        "type": 0,
                        "versionCode": 0,
                        "versionName": ""
                    },
                    "versionCode": 0,
                    "versionName": ""
                },
                "crowdtestDeadline": -1,
                "runningResourcesApply": false,
                "associatedWakeUp": false,
                "hideDesktopIcon": false,
                "formVisibleNotify": false,
                "allowCommonEvent": [],
                "needAppDetail": false,
                "appDetailAbilityLibraryPath": ""
            },
            "baseBundleInfo": {
                "asanEnabled": false,
                "abilityInfos": [
                ],
                "appId": "com.ohos.launcher_BNtg4JBClbl92Rgc3jm/RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=",
                "applicationInfo": {
                    "accessTokenId": 0,
                    "accessible": false,
                    "apiCompatibleVersion": 0,
                    "apiReleaseType": "",
                    "apiTargetVersion": 0,
                    "appPrivilegeLevel": "normal",
                    "arkNativeFileAbi": "",
                    "arkNativeFilePath": "",
                    "bundleName": "",
                    "bundleType": 0,
                    "cacheDir": "",
                    "codePath": "",
                    "cpuAbi": "",
                    "dataBaseDir": "",
                    "dataDir": "",
                    "debug": false,
                    "description": "",
                    "descriptionId": 0,
                    "asanEnabled": false,
                    "asanLogPath": "",
                    "descriptionResource": {
                        "bundleName": "",
                        "id": 0,
                        "moduleName": ""
                    },
                    "deviceId": "",
                    "distributedNotificationEnabled": true,
                    "enabled": false,
                    "entityType": "",
                    "entryDir": "",
                    "entryModuleName": "",
                    "flags": 0,
                    "icon": "",
                    "iconId": 0,
                    "iconPath": "",
                    "iconResource": {
                        "bundleName": "",
                        "id": 0,
                        "moduleName": ""
                    },
                    "fingerprint":"",
                    "isCompressNativeLibs": true,
                    "isLauncherApp": false,
                    "isSystemApp": false,
                    "keepAlive": false,
                    "label": "",
                    "labelId": 0,
                    "labelResource": {
                        "bundleName": "",
                        "id": 0,
                        "moduleName": ""
                    },
                    "metaData": {
                    },
                    "metadata": {
                    },
                    "minCompatibleVersionCode": 0,
                    "moduleInfos": [
                    ],
                    "moduleSourceDirs": [
                    ],
                    "name": "",
                    "nativeLibraryPath": "",
                    "permissions": [
                    ],
                    "targetBundleList": [
                    ],
                    "isFreeInstallApp": false,
                    "process": "",
                    "removable": true,
                    "signatureKey": "",
                    "multiProjects":false,
                    "singleton": false,
                    "split":false,
                    "supportedModes": 0,
                    "uid": -1,
                    "userDataClearable": true,
                    "vendor": "",
                    "versionCode": 0,
                    "versionName": "",
                    "appDistributionType": "none",
                    "appProvisionType": "release",
                    "appQuickFix": {
                        "bundleName": "",
                        "deployedAppqfInfo": {
                            "cpuAbi": "",
                            "hqfInfos": [],
                            "nativeLibraryPath": "",
                            "type": 0,
                            "versionCode": 0,
                            "versionName": ""
                        },
                        "deployingAppqfInfo": {
                            "cpuAbi": "",
                            "hqfInfos": [],
                            "nativeLibraryPath": "",
                            "type": 0,
                            "versionCode": 0,
                            "versionName": ""
                        },
                        "versionCode": 0,
                        "versionName": ""
                    },
                    "crowdtestDeadline": -1,
                    "runningResourcesApply": false,
                    "associatedWakeUp": false,
                    "hideDesktopIcon": false,
                    "formVisibleNotify": false,
                    "allowCommonEvent": [],
                    "needAppDetail": false,
                    "appDetailAbilityLibraryPath": ""
                },
                "compatibleVersion": 8,
                "cpuAbi": "",
                "defPermissions": [
                ],
                "description": "",
                "entryInstallationFree": true,
                "entryModuleName": "phone",
                "extensionAbilityInfo": [
                ],
                "gid": -1,
                "hapModuleInfos": [
                ],
                "hapModuleNames": [
                ],
                "installTime": 0,
                "isDifferentName": false,
                "isKeepAlive": false,
                "isNativeApp": false,
                "isPreInstallApp": true,
                "jointUserId": "",
                "label": "",
                "mainEntry": "com.ohos.launcher",
                "maxSdkVersion": -1,
                "minCompatibleVersionCode": 1000000,
                "minSdkVersion": -1,
                "moduleDirs": [
                ],
                "moduleNames": [
                ],
                "modulePublicDirs": [
                ],
                "moduleResPaths": [
                ],
                "name": "com.ohos.launcher",
                "releaseType": "Beta1",
                "reqPermissionDetails": [
                ],
                "reqPermissionStates": [
                ],
                "reqPermissions": [
                ],
                "signatureInfo": {
                    "appId": "",
                    "fingerprint": ""
                },
                "seInfo": "",
                "singleton": false,
                "targetVersion": 8,
                "uid": -1,
                "updateTime": 0,
                "appIndex": 0,
                "vendor": "ohos",
                "versionCode": 1000000,
                "versionName": "1.0.0"
            },
            "baseDataDir": "/data/app/el2/100/base/com.ohos.launcher",
            "baseExtensionInfos_": {
            },
            "bundleStatus": 1,
            "commonEvents": {
            },
            "extensionSkillInfos_": {
            },
            "formInfos": {
                "com.ohos.launcher.com.ohos.launcher.com.ohos.launcher.MainAbility": [
                ],
                "com.ohos.launcher.com.ohos.launcher.recents.com.ohos.launcher.recents.MainAbility": [
                ],
                "com.ohos.launcher.com.ohos.launcher.settings.com.ohos.launcher.settings.MainAbility": [
                ]
            },
            "gid": -1,
            "hasAtomicServiceConfig ": true,
            "hasEntry": true,
            "innerBundleUserInfos": {
                "com.ohos.launcher_100": {
                    "accessTokenId": 537510556,
                    "bundleName": "com.ohos.launcher",
                    "bundleUserInfo": {
                        "abilities": [
                        ],
                        "disabledAbilities": [
                        ],
                        "enabled": true,
                        "userId": 100
                    },
                    "gids": [
                        20010012
                    ],
                    "installTime": 1503988035,
                    "uid": 20010012,
                    "updateTime": 1503988036
                }
            },
            "innerModuleInfos": {
                "com.ohos.launcher": {
                    "abilityKeys": [
                        "com.ohos.launcher.com.ohos.launcher.com.ohos.launcher.MainAbility"
                    ],
                    "atomicServiceModuleType": 0,
                    "colorMode": -1,
                    "defPermissions": [
                    ],
                    "definePermissions": [
                    ],
                    "description": "",
                    "descriptionId": 0,
                    "deviceTypes": [
                    ],
                    "distro": {
                        "deliveryWithInstall": true,
                        "installationFree": true,
                        "moduleName": "phone",
                        "moduleType": "entry"
                    },
                    "extensionKeys": [
                    ],
                    "extensionSkillKeys": [
                    ],
                    "hapPath": "/data/app/el1/bundle/public/com.ohos.launcher/com_ohos_launcher.hap",
                    "hashValue": "",
                    "installationFree": true,
                    "isEntry": true,
                    "isModuleJson": false,
                    "isStageBasedModel": true,
                    "label": "$string: entry_MainAbility",
                    "labelId": 218103828,
                    "mainAbility": "com.ohos.launcher.MainAbility",
                    "metaData": {
                        "customizeData": [
                        ]
                    },
                    "metadata": [
                    ],
                    "moduleDataDir": "/data/app/el2/100/base/com.ohos.launcher/haps/com.ohos.launcher",
                    "moduleName": "phone",
                    "modulePackage": "com.ohos.launcher",
                    "modulePath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher",
                    "moduleResPath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher/assets/phone/resources.index",
                    "pages": "",
                    "preloads":[],
                    "process": "",
                    "reqCapabilities": [
                    ],
                    "requestPermissions": [
                        {
                            "name": "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED",
                            "reason": "",
                            "reasonId": 0,
                            "usedScene": {
                                "abilities": [
                                ],
                                "when": ""
                            }
                        },
                        {
                            "name": "ohos.permission.INSTALL_BUNDLE",
                            "reason": "",
                            "reasonId": 0,
                            "usedScene": {
                                "abilities": [
                                ],
                                "when": ""
                            }
                        },
                        {
                            "name": "ohos.permission.LISTEN_BUNDLE_CHANGE",
                            "reason": "",
                            "reasonId": 0,
                            "usedScene": {
                                "abilities": [
                                ],
                                "when": ""
                            }
                        },
                        {
                            "name": "ohos.permission.MANAGE_MISSIONS",
                            "reason": "",
                            "reasonId": 0,
                            "usedScene": {
                                "abilities": [
                                ],
                                "when": ""
                            }
                        },
                        {
                            "name": "ohos.permission.REQUIRE_FORM",
                            "reason": "",
                            "reasonId": 0,
                            "usedScene": {
                                "abilities": [
                                ],
                                "when": ""
                            }
                        }
                    ],
                    "skillKeys": [
                        "com.ohos.launcher.com.ohos.launcher.com.ohos.launcher.MainAbility"
                    ],
                    "srcEntrance": "",
                    "srcPath": "",
                    "uiSyntax": "",
                    "virtualMachine": ""
                },
                "com.ohos.launcher.recents": {
                    "abilityKeys": [
                        "com.ohos.launcher.com.ohos.launcher.recents.com.ohos.launcher.recents.MainAbility"
                    ],
                    "atomicServiceModuleType": 0,
                    "colorMode": -1,
                    "defPermissions": [
                    ],
                    "definePermissions": [
                    ],
                    "description": "",
                    "descriptionId": 0,
                    "deviceTypes": [
                    ],
                    "distro": {
                        "deliveryWithInstall": true,
                        "installationFree": true,
                        "moduleName": "recents",
                        "moduleType": "feature"
                    },
                    "extensionKeys": [
                    ],
                    "extensionSkillKeys": [
                    ],
                    "hapPath": "/data/app/el1/bundle/public/com.ohos.launcher/com_ohos_launcher_recents.hap",
                    "hashValue": "",
                    "installationFree": true,
                    "isEntry": false,
                    "isModuleJson": false,
                    "isStageBasedModel": true,
                    "label": "",
                    "labelId": 0,
                    "mainAbility": "com.ohos.launcher.recents.MainAbility",
                    "metaData": {
                        "customizeData": [
                        ]
                    },
                    "metadata": [
                    ],
                    "moduleDataDir": "/data/app/el2/100/base/com.ohos.launcher/haps/com.ohos.launcher.recents",
                    "moduleName": "recents",
                    "modulePackage": "com.ohos.launcher.recents",
                    "modulePath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher.recents",
                    "moduleResPath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher.recents/assets/recents/resources.index",
                    "pages": "",
                    "preloads":[],
                    "process": "",
                    "reqCapabilities": [
                    ],
                    "requestPermissions": [
                    ],
                    "skillKeys": [
                        "com.ohos.launcher.com.ohos.launcher.recents.com.ohos.launcher.recents.MainAbility"
                    ],
                    "srcEntrance": "",
                    "srcPath": "",
                    "uiSyntax": "",
                    "virtualMachine": ""
                },
                "com.ohos.launcher.settings": {
                    "abilityKeys": [
                        "com.ohos.launcher.com.ohos.launcher.settings.com.ohos.launcher.settings.MainAbility"
                    ],
                    "atomicServiceModuleType": 0,
                    "colorMode": -1,
                    "defPermissions": [
                    ],
                    "definePermissions": [
                    ],
                    "description": "",
                    "descriptionId": 0,
                    "deviceTypes": [
                    ],
                    "distro": {
                        "deliveryWithInstall": true,
                        "installationFree": true,
                        "moduleName": "settings",
                        "moduleType": "feature"
                    },
                    "extensionKeys": [
                    ],
                    "extensionSkillKeys": [
                    ],
                    "hapPath": "/data/app/el1/bundle/public/com.ohos.launcher/com_ohos_launcher_settings.hap",
                    "hashValue": "",
                    "installationFree": true,
                    "isEntry": false,
                    "isModuleJson": false,
                    "isStageBasedModel": true,
                    "label": "",
                    "labelId": 0,
                    "mainAbility": "com.ohos.launcher.settings.MainAbility",
                    "metaData": {
                        "customizeData": [
                        ]
                    },
                    "metadata": [
                    ],
                    "moduleDataDir": "/data/app/el2/100/base/com.ohos.launcher/haps/com.ohos.launcher.settings",
                    "moduleName": "settings",
                    "modulePackage": "com.ohos.launcher.settings",
                    "modulePath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher.settings",
                    "moduleResPath": "/data/app/el1/bundle/public/com.ohos.launcher/com.ohos.launcher.settings/assets/settings/resources.index",
                    "pages": "",
                    "preloads":[],
                    "process": "",
                    "reqCapabilities": [
                    ],
                    "requestPermissions": [
                    ],
                    "skillKeys": [
                        "com.ohos.launcher.com.ohos.launcher.settings.com.ohos.launcher.settings.MainAbility"
                    ],
                    "srcEntrance": "",
                    "srcPath": "",
                    "uiSyntax": "",
                    "virtualMachine": ""
                }
            },
            "installMark": {
                "installMarkBundle": "com.ohos.launcher",
                "installMarkPackage": "com.ohos.launcher.settings",
                "installMarkStatus": 2
            },
            "isNewVersion_": false,
            "isSupportBackup": false,
            "mainAbility": "com.ohos.launcher.com.ohos.launcher.com.ohos.launcher.MainAbility",
            "mainAbilityName": "com.ohos.launcher.MainAbility",
            "mainAtomicModuleName":"",
            "shortcutInfos": {
            },
            "skillInfos": {
                "com.ohos.launcher.com.ohos.launcher.com.ohos.launcher.MainAbility": [
                    {
                        "actions": [
                            "action.system.home",
                            "com.ohos.action.main"
                        ],
                        "entities": [
                            "entity.system.home",
                            "flag.home.intent.from.system"
                        ],
                        "uris": [
                        ]
                    }
                ],
                "com.ohos.launcher.com.ohos.launcher.recents.com.ohos.launcher.recents.MainAbility": [
                ],
                "com.ohos.launcher.com.ohos.launcher.settings.com.ohos.launcher.settings.MainAbility": [
                ]
            },
            "uid": -1,
            "userId_": 100
        }
    )"_json;

    nlohmann::json moduleInfoJson_ = R"(
        {
            "moduleName": "entry",
            "moduleSourceDir": "",
            "preloads": []
        }
    )"_json;
    const std::string BASE_ABILITY_INFO = "baseAbilityInfos";
    // need modify with innerBundleInfoJson_
    const std::string abilityName = "com.ohos.launcher.com.ohos.launcher.com.ohos.launcher.MainAbility";
    const std::string BASE_BUNDLE_INFO = "baseBundleInfo";
    const std::string BASE_APPLICATION_INFO = "baseApplicationInfo";
};

BmsBundleDataStorageDatabaseTest::BmsBundleDataStorageDatabaseTest()
{}

BmsBundleDataStorageDatabaseTest::~BmsBundleDataStorageDatabaseTest()
{}

void BmsBundleDataStorageDatabaseTest::CheckInvalidPropDeserialize(
    const nlohmann::json infoJson, const InfoType infoType) const
{
    APP_LOGI("deserialize infoJson = %{public}s", infoJson.dump().c_str());
    nlohmann::json innerBundleInfoJson;
    nlohmann::json bundleInfoJson = innerBundleInfoJson_.at(BASE_BUNDLE_INFO);

    switch (infoType) {
        case InfoType::BUNDLE_INFO: {
            bundleInfoJson = infoJson;
            BundleInfo bundleInfo = infoJson;
            break;
        }
        case InfoType::APPLICATION_INFO: {
            bundleInfoJson["appInfo"] = infoJson;
            ApplicationInfo applicationInfo = infoJson;
            break;
        }
        case InfoType::ABILITY_INFO: {
            bundleInfoJson["abilityInfos"].push_back(infoJson);
            AbilityInfo abilityInfo = infoJson;
            break;
        }
        default:
            break;
    }

    innerBundleInfoJson["baseBundleInfo"] = bundleInfoJson;
    InnerBundleInfo fromJsonInfo;
    EXPECT_FALSE(fromJsonInfo.FromJson(innerBundleInfoJson));
}

void BmsBundleDataStorageDatabaseTest::SetUpTestCase()
{}

void BmsBundleDataStorageDatabaseTest::TearDownTestCase()
{}

void BmsBundleDataStorageDatabaseTest::SetUp()
{}

void BmsBundleDataStorageDatabaseTest::TearDown()
{}

/**
 * @tc.number: BundleInfoJsonSerializer_0100
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally
 *           2.successfully serialize and deserialize all right props in BundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, BundleInfoJsonSerializer_0100, Function | SmallTest | Level1)
{
    nlohmann::json sourceInfoJson = innerBundleInfoJson_.at(BASE_BUNDLE_INFO);
    // deserialize BundleInfo from json
    BundleInfo fromJsonInfo = sourceInfoJson;
    // serialize fromJsonInfo to json
    nlohmann::json toJsonObject = fromJsonInfo;
    EXPECT_TRUE(toJsonObject.dump() == sourceInfoJson.dump());
}

/**
 * @tc.number: BundleInfoJsonSerializer_0200
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally
 *           2.test can catch deserialize error for type error for name prop in BundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, BundleInfoJsonSerializer_0200, Function | SmallTest | Level1)
{
    nlohmann::json typeErrorProps;
    typeErrorProps["name"] = NOT_STRING_TYPE;
    typeErrorProps["label"] = NOT_STRING_TYPE;
    typeErrorProps["description"] = NOT_STRING_TYPE;
    typeErrorProps["vendor"] = NOT_STRING_TYPE;
    typeErrorProps["mainEntry"] = NOT_STRING_TYPE;
    typeErrorProps["versionName"] = NOT_STRING_TYPE;
    typeErrorProps["versionCode"] = NOT_NUMBER_TYPE;
    typeErrorProps["minSdkVersion"] = NOT_NUMBER_TYPE;

    for (nlohmann::json::iterator iter = typeErrorProps.begin(); iter != typeErrorProps.end(); iter++) {
        for (auto valueIter = iter.value().begin(); valueIter != iter.value().end(); valueIter++) {
            nlohmann::json infoJson = innerBundleInfoJson_.at(BASE_BUNDLE_INFO);
            infoJson[iter.key()] = valueIter.value();
        }
    }
}

/**
 * @tc.number: AbilityInfoJsonSerializer_0100
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally
 *           2.successfully serialize and deserialize all right props in AbilityInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, AbilityInfoJsonSerializer_0100, Function | SmallTest | Level1)
{
    nlohmann::json sourceInfoJson = innerBundleInfoJson_.at(BASE_ABILITY_INFO).at(abilityName);
    // deserialize AbilityInfo from json
    AbilityInfo fromJsonInfo = sourceInfoJson;
    // serialize fromJsonInfo to json
    nlohmann::json toJsonObject = fromJsonInfo;
    EXPECT_TRUE(toJsonObject.dump() == sourceInfoJson.dump());
}

/**
 * @tc.number: AbilityInfoJsonSerializer_0200
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally
 *           2.test can catch deserialize error for type error for name prop in AbilityInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, AbilityInfoJsonSerializer_0200, Function | SmallTest | Level1)
{
    nlohmann::json typeErrorProps;
    typeErrorProps["package"] = NOT_STRING_TYPE;
    typeErrorProps["name"] = NOT_STRING_TYPE;
    typeErrorProps["bundleName"] = NOT_STRING_TYPE;
    typeErrorProps["applicationName"] = NOT_STRING_TYPE;
    typeErrorProps["label"] = NOT_STRING_TYPE;
    typeErrorProps["description"] = NOT_STRING_TYPE;
    typeErrorProps["iconPath"] = NOT_STRING_TYPE;
    typeErrorProps["visible"] = NOT_BOOL_TYPE;
    typeErrorProps["kind"] = NOT_STRING_TYPE;
    typeErrorProps["type"] = NOT_NUMBER_TYPE;
    typeErrorProps["orientation"] = NOT_NUMBER_TYPE;
    typeErrorProps["launchMode"] = NOT_NUMBER_TYPE;
    typeErrorProps["codePath"] = NOT_STRING_TYPE;
    typeErrorProps["resourcePath"] = NOT_STRING_TYPE;
    typeErrorProps["libPath"] = NOT_STRING_TYPE;

    for (nlohmann::json::iterator iter = typeErrorProps.begin(); iter != typeErrorProps.end(); iter++) {
        for (auto valueIter = iter.value().begin(); valueIter != iter.value().end(); valueIter++) {
            APP_LOGD("deserialize check prop key = %{public}s, type = %{public}s",
                iter.key().c_str(),
                valueIter.key().c_str());
            nlohmann::json infoJson = innerBundleInfoJson_.at(BASE_ABILITY_INFO).at(abilityName);
            infoJson[iter.key()] = valueIter.value();
        }
    }
}

/**
 * @tc.number: ApplicationInfoJsonSerializer_0100
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally
 *           2.successfully serialize and deserialize all right props in ApplicationInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, ApplicationInfoJsonSerializer_0100, Function | SmallTest | Level1)
{
    nlohmann::json sourceInfoJson = innerBundleInfoJson_.at(BASE_APPLICATION_INFO);
    // deserialize ApplicationInfo from json
    ApplicationInfo fromJsonInfo = sourceInfoJson;
    // serialize fromJsonInfo to json
    nlohmann::json toJsonObject = fromJsonInfo;
    EXPECT_TRUE(toJsonObject.dump() == sourceInfoJson.dump());
}

/**
 * @tc.number: ApplicationInfoJsonSerializer_0200
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally
 *           2.test can catch deserialize error for type error for name prop in ApplicationInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, ApplicationInfoJsonSerializer_0200, Function | SmallTest | Level1)
{
    nlohmann::json typeErrorProps;
    typeErrorProps["name"] = NOT_STRING_TYPE;
    typeErrorProps["bundleName"] = NOT_STRING_TYPE;
    typeErrorProps["sandboxId"] = NOT_NUMBER_TYPE;
    typeErrorProps["signatureKey"] = NOT_STRING_TYPE;

    for (nlohmann::json::iterator iter = typeErrorProps.begin(); iter != typeErrorProps.end(); iter++) {
        for (auto valueIter = iter.value().begin(); valueIter != iter.value().end(); valueIter++) {
            APP_LOGD("deserialize check prop key = %{public}s, type = %{public}s",
                iter.key().c_str(),
                valueIter.key().c_str());
            nlohmann::json infoJson = innerBundleInfoJson_.at(BASE_APPLICATION_INFO);
            infoJson[iter.key()] = valueIter.value();
        }
    }
}

/**
 * @tc.number: ModuleInfoJsonSerializer_0100
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally
 *           2.successfully serialize and deserialize all right props in ModuleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, ModuleInfoJsonSerializer_0100, Function | SmallTest | Level1)
{
    nlohmann::json sourceInfoJson = moduleInfoJson_;
    // deserialize ModuleInfo from json
    ModuleInfo fromJsonInfo = sourceInfoJson;
    // serialize fromJsonInfo to json
    nlohmann::json toJsonObject = fromJsonInfo;

    EXPECT_TRUE(toJsonObject.dump() == sourceInfoJson.dump());
}

/**
 * @tc.number: SaveData_0100
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally and no saved any bundle data
 *           2.successfully save a new bundle installation information for the first time
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, SaveData_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    EXPECT_EQ(innerBundleInfo.FromJson(innerBundleInfoJson_), OHOS::ERR_OK);
}

/**
 * @tc.number: SaveData_0200
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally and no saved any bundle data
 *           2.save a new bundle installation information fail by wrong parameter
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, SaveData_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.ToJson(innerBundleInfoJson_);
    EXPECT_EQ(innerBundleInfo.FromJson(false), OHOS::ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: SaveData_0300
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally and no saved any bundle data
 *           2.successfully save a new bundle installation information for the first time
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, SaveData_0300, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject;
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = "bundleName";
    userInfo.uid = Constants::INVALID_UID;
    userInfo.accessTokenId = 0;
    userInfo.gids.push_back(0);
    userInfo.installTime = 0;
    userInfo.updateTime = 0;
    userInfo.bundleUserInfo.userId = 100;
    to_json(jsonObject, userInfo);
    EXPECT_EQ(jsonObject["bundleName"], "bundleName");
    EXPECT_EQ(jsonObject["uid"], Constants::INVALID_UID);
}

/**
 * @tc.number: InnerBundleInfo_0100
 * @tc.name: Test MatchLauncher
 * @tc.desc: 1.Test the MatchLauncher of InnerBundleInfoCpp
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0100, Function | SmallTest | Level1)
{
    OHOS::AAFwk::Want want;
    want.SetAction("");
    Skill skill;
    bool ret = skill.MatchLauncher(want);
    EXPECT_EQ(ret, false);

    std::vector<std::string> actions;
    actions.emplace_back("action1");
    skill.actions = actions;
    want.SetAction("action1");
    ret = skill.MatchLauncher(want);
    EXPECT_EQ(ret, true);

    want.AddEntity("entry");
    ret = skill.MatchLauncher(want);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfo_0200
 * @tc.name: Test Match
 * @tc.desc: Use Match to match different Uri And Type of InnerBundleInfoCpp
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0200, Function | SmallTest | Level1)
{
    OHOS::AAFwk::Want want;
    want.SetAction("action1");
    Skill skill;
    std::vector<std::string> actions;
    actions.emplace_back("action1");
    skill.actions = actions;

    std::vector<SkillUri> uris;
    SkillUri uri1;
    uri1.scheme = "uriString";
    uri1.type = "image/*";
    uris.emplace_back(uri1);
    skill.uris = uris;
    bool ret = skill.Match(want);
    EXPECT_EQ(ret, false);

    SkillUri uri2;
    uris.emplace_back(uri2);
    skill.uris = uris;
    ret = skill.Match(want);
    EXPECT_EQ(ret, true);

    std::string type = "text/xml";
    std::string uri = "uriString://";
    want.SetUri(uri);
    want.SetType(type);
    ret = skill.Match(want);
    EXPECT_EQ(ret, false);

    type = "*/*";
    want.SetType(type);
    ret = skill.Match(want);
    EXPECT_EQ(ret, true);

    SkillUri uri3;
    uri3.host = "host";
    uris.insert(uris.begin(), uri3);
    skill.uris = uris;
    ret = skill.Match(want);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InnerBundleInfo_0300
 * @tc.name: Test from_json
 * @tc.desc: 1.Test the from_json of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0300, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["accessTokenId"] = 1;
    jsonObject["appIndex"] = 1;
    jsonObject["userId"] = 101;
    SandboxAppPersistentInfo info;
    from_json(jsonObject, info);
    EXPECT_EQ(info.accessTokenId, 1);
    EXPECT_EQ(info.appIndex, 1);
    EXPECT_EQ(info.userId, 101);
}

/**
 * @tc.number: InnerBundleInfo_0400
 * @tc.name: Test BuildDefaultUserInfo
 * @tc.desc: 1.Use FromJson to call BuildDefaultUserInfo of InnerBundleInfoCpp
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0400, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "test";
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    nlohmann::json jsonObject;
    info.FromJson(jsonObject);
    EXPECT_EQ(applicationInfo.bundleName, "test");
}

/**
 * @tc.number: InnerBundleInfo_0500
 * @tc.name: Test FindHapModuleInfo
 * @tc.desc: 1.Test the FindHapModuleInfo of InnerBundleInfoCpp
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0500, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::vector<HqfInfo> hqfInfos;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "modulePackage";
    hqfInfos.emplace_back(hqfInfo);
    info.SetQuickFixHqfInfos(hqfInfos);
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "modulePackage";
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos["modulePackage"] = moduleInfo;
    info.AddInnerModuleInfo(innerModuleInfos);
    auto it = info.FindHapModuleInfo("modulePackage", 100);
    EXPECT_EQ(it->hqfInfo.moduleName, "modulePackage");
}

/**
 * @tc.number: Test_0500
 * @tc.name: Test Unmarshalling
 * @tc.desc: 1.Test the Unmarshalling of Parcel
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, Parcel_0100, Function | SmallTest | Level1)
{
    uint32_t b = 0;
    int32_t maxInt = (b - 1) / 2;
    OHOS::Parcel parcel;
    bool ret = parcel.WriteInt32(maxInt - 10);
    EXPECT_EQ(ret, true);
    for (int i = 0; i < 10; i++) {
        ret = parcel.WriteString(NORMAL_BUNDLE_NAME);
        EXPECT_EQ(ret, true);
    }

    RequestPermissionUsedScene *requestPermissionUsedScene = RequestPermissionUsedScene::Unmarshalling(parcel);
    EXPECT_EQ(requestPermissionUsedScene, nullptr);
}
/**
 * @tc.number: InnerBundleInfo_0600
 * @tc.name: Test FindAbilityInfos
 * @tc.desc: 1.Test the FindAbilityInfos of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0600, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string bundleName = "";
    int32_t userId = Constants::ALL_USERID;
    auto ret = info.FindAbilityInfos(bundleName, userId);
    EXPECT_EQ(ret, std::nullopt);

    AbilityInfo abilityInfo;
    bundleName = "com.ohos.test";
    abilityInfo.bundleName = bundleName;
    info.InsertAbilitiesInfo("key", abilityInfo);
    ret = info.FindAbilityInfos(bundleName, userId);
    EXPECT_EQ((*ret)[0].bundleName, "com.ohos.test");
}

/**
 * @tc.number: InnerBundleInfo_0700
 * @tc.name: Test RemoveModuleInfo
 * @tc.desc: 1.Test the RemoveModuleInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0700, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    ShortcutInfo shortcutInfo1;
    ShortcutInfo shortcutInfo2;
    CommonEventInfo commonEvent1;
    CommonEventInfo commonEvent2;
    ExtensionAbilityInfo extensionInfo;
    extensionInfo.name = "key";
    std::vector<Skill> skill;
    innerModuleInfo.extensionKeys.emplace_back("key1");
    innerModuleInfo.extensionSkillKeys.emplace_back("key2");
    info.InsertExtensionInfo("key1", extensionInfo);
    info.InsertExtensionSkillInfo("key2", skill);
    info.InsertInnerModuleInfo(".modulePackage.", innerModuleInfo);
    info.InsertShortcutInfos(".wrong.", shortcutInfo1);
    info.InsertShortcutInfos(".modulePackage.", shortcutInfo2);
    info.InsertCommonEvents(".wrong.", commonEvent1);
    info.InsertCommonEvents(".modulePackage.", commonEvent2);
    info.RemoveModuleInfo(".modulePackage.");
    auto ret1 = info.GetInnerExtensionInfos();
    auto ret2 = info.GetExtensionSkillInfos();
    EXPECT_EQ(ret1["key1"].name, "");
    EXPECT_EQ(ret2["key2"].empty(), true);
}

/**
 * @tc.number: InnerBundleInfo_0800
 * @tc.name: Test GetApplicationInfo
 * @tc.desc: 1.Test the GetApplicationInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0800, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = ".modulePackage.";
    innerModuleInfo.isModuleJson = true;
    std::vector<Metadata> data;
    Metadata data1;
    data1.name = "data1";
    data.emplace_back(data1);
    innerModuleInfo.metadata = data;
    info.InsertInnerModuleInfo(".modulePackage.", innerModuleInfo);
    ApplicationInfo appInfo1;
    appInfo1.bundleName = "com.ohos.test";
    info.SetBaseApplicationInfo(appInfo1);
    const int32_t failedId = -5;
    const int32_t flags = 0;
    ApplicationInfo appInfo2;
    info.GetApplicationInfo(flags, failedId, appInfo2);
    EXPECT_EQ(appInfo2.metadata[".modulePackage."].empty(), true);
}

/**
 * @tc.number: InnerBundleInfo_0900
 * @tc.name: Test GetModuleWithHashValue
 * @tc.desc: 1.Test the GetModuleWithHashValue of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0900, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = "infoName";
    const int32_t flags = 0;
    info.GetModuleWithHashValue(flags, "", hapModuleInfo);
    EXPECT_EQ(hapModuleInfo.name, "infoName");
}

/**
 * @tc.number: InnerBundleInfo_1000
 * @tc.name: Test GetInnerModuleInfoByModuleName
 * @tc.desc: 1.Test the GetInnerModuleInfoByModuleName of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1000, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    auto ret = info.GetInnerModuleInfoByModuleName("");
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: InnerBundleInfo_1100
 * @tc.name: Test GetModuleNames
 * @tc.desc: 1.Test the GetModuleNames of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    info.InsertInnerModuleInfo("key", innerModuleInfo);
    std::vector<std::string> moduleNames;
    info.GetModuleNames(moduleNames);
    EXPECT_EQ(moduleNames[0], "entry");
}

/**
 * @tc.number: InnerBundleInfo_1200
 * @tc.name: Test GetInnerBundleUserInfos
 * @tc.desc: 1.Test the GetInnerBundleUserInfos of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ApplicationInfo appInfo1;
    appInfo1.bundleName = "com.ohos.test";
    info.SetBaseApplicationInfo(appInfo1);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    innerBundleUserInfo.bundleUserInfo.enabled = false;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);
    const int32_t userId1 = -1;
    const int32_t userId2 = 100;
    info.ResetBundleState(userId1);
    auto ret = info.GetInnerBundleUserInfos();
    EXPECT_EQ(ret["com.ohos.test_100"].bundleUserInfo.enabled, false);
    info.ResetBundleState(userId2);
    ret = info.GetInnerBundleUserInfos();
    EXPECT_EQ(ret["com.ohos.test_100"].bundleUserInfo.enabled, true);
}

/**
 * @tc.number: InnerBundleInfo_1300
 * @tc.name: Test RemoveInnerBundleUserInfo
 * @tc.desc: 1.Test the RemoveInnerBundleUserInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1300, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ApplicationInfo appInfo1;
    appInfo1.bundleName = "com.ohos.test";
    info.SetBaseApplicationInfo(appInfo1);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerModuleInfo.isRemovable["100"] = true;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);
    info.InsertInnerModuleInfo("name_100", innerModuleInfo);
    const int32_t userId1 = -1;
    const int32_t userId2 = 100;
    info.RemoveInnerBundleUserInfo(userId1);
    auto ret = info.GetInnerModuleInfos();
    EXPECT_EQ(ret["name_100"].isRemovable["100"], true);
    info.RemoveInnerBundleUserInfo(userId2);
    ret = info.GetInnerModuleInfos();
    EXPECT_EQ(ret["name_100"].isRemovable["100"], false);
}

/**
 * @tc.number: InnerBundleInfo_1400
 * @tc.name: Test GetInnerBundleUserInfo
 * @tc.desc: 1.Test the GetInnerBundleUserInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1400, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = 100;
    int32_t userId = Constants::NOT_EXIST_USERID;
    auto ret = info.GetInnerBundleUserInfo(userId, userInfo);
    EXPECT_EQ(ret, true);
    userId = 100;
    ret = info.GetInnerBundleUserInfo(userId, userInfo);
    EXPECT_EQ(ret, false);
    userId = Constants::ALL_USERID;
    ret = info.GetInnerBundleUserInfo(userId, userInfo);
    EXPECT_EQ(ret, false);
    ApplicationInfo appInfo;
    info.SetBaseApplicationInfo(appInfo);
    info.AddInnerBundleUserInfo(userInfo);
    ret = info.GetInnerBundleUserInfo(userId, userInfo);
    EXPECT_EQ(ret, true);
    userId = 100;
    ret = info.GetInnerBundleUserInfo(userId, userInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InnerBundleInfo_1500
 * @tc.name: Test IsAbilityEnabled
 * @tc.desc: 1.Test the IsAbilityEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1500, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    int32_t userId = Constants::ALL_USERID;
    bool ret = info.HasInnerBundleUserInfo(userId);
    EXPECT_EQ(ret, false);
    const int64_t time = 1;
    uint32_t accessToken = 1;
    info.SetBundleInstallTime(time, userId);
    info.SetAccessTokenId(accessToken, userId);
    info.SetBundleUpdateTime(time, userId);
    userId = Constants::NOT_EXIST_USERID;
    AbilityInfo abilityInfo;
    ret = info.IsAbilityEnabled(abilityInfo, userId);
    EXPECT_EQ(ret, true);
    userId = Constants::ALL_USERID;
    ret = info.IsAbilityEnabled(abilityInfo, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfo_1600
 * @tc.name: Test FindAbilityInfos
 * @tc.desc: 1.Test the FindAbilityInfos of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1600, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string bundleName = "com.ohos.launcher";
    const int userId = 100;
    auto ret = info.FindAbilityInfos("", userId);
    EXPECT_EQ(ret, std::nullopt);

    ret = info.FindAbilityInfos(bundleName, userId);
    EXPECT_EQ(ret, std::nullopt);

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    info.InsertAbilitiesInfo("key", abilityInfo);
    ret = info.FindAbilityInfos(bundleName, userId);
    EXPECT_EQ((*ret)[0].bundleName, bundleName);
}

/**
 * @tc.number: InnerBundleInfo_1700
 * @tc.name: Test IsBundleRemovable
 * @tc.desc: 1.Test the IsBundleRemovable of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1700, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool isEnabled = true;
    int32_t userId = Constants::ALL_USERID;
    auto ret = info.SetAbilityEnabled("", "", "", isEnabled, userId);
    EXPECT_NE(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: InnerBundleInfo_1800
 * @tc.name: Test FindExtensionInfo
 * @tc.desc: 1.Test the FindExtensionInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1800, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string bundleName = "";
    std::string moduleName = "";
    std::string extensionName = "";
    auto ret = info.FindExtensionInfo(bundleName, moduleName, extensionName);
    EXPECT_EQ(ret, std::nullopt);

    ExtensionAbilityInfo extensionInfo;
    bundleName = "com.ohos.test";
    moduleName = "entry";
    extensionName = "extension";
    extensionInfo.bundleName = bundleName;
    extensionInfo.moduleName = moduleName;
    extensionInfo.name = "extension";
    info.InsertExtensionInfo("key", extensionInfo);
    ret = info.FindExtensionInfo(bundleName, moduleName, extensionName);
    EXPECT_EQ((*ret).bundleName, "com.ohos.test");
}

/**
 * @tc.number: InnerBundleInfo_1900
 * @tc.name: Test FindExtensionInfo
 * @tc.desc: 1.Test the FindExtensionInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_1900, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string bundleName = "";
    auto ret = info.FindExtensionInfos(bundleName);
    EXPECT_EQ(ret, std::nullopt);

    bundleName = "com.ohos.nullextension";
    ret = info.FindExtensionInfos(bundleName);
    EXPECT_EQ(ret, std::nullopt);

    ExtensionAbilityInfo extensionInfo;
    bundleName = "com.ohos.test";
    extensionInfo.bundleName = bundleName;
    info.InsertExtensionInfo("key", extensionInfo);
    ret = info.FindExtensionInfos(bundleName);
    EXPECT_EQ((*ret)[0].bundleName, "com.ohos.test");
}

/**
 * @tc.number: InnerBundleInfo_2000
 * @tc.name: Test IsBundleRemovable
 * @tc.desc: 1.Test the IsBundleRemovable of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2000, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetIsPreInstallApp(false);
    InnerModuleInfo innerModuleInfo;
    bool ret = info.IsBundleRemovable(Constants::START_USERID);
    EXPECT_EQ(ret, true);

    innerModuleInfo.moduleName = "entry";
    info.InsertInnerModuleInfo("entry", innerModuleInfo);
    ret = info.IsBundleRemovable(Constants::START_USERID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfo_2100
 * @tc.name: Test IsUserExistModule
 * @tc.desc: 1.Test the IsUserExistModule of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    info.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerModuleInfo.isRemovable.try_emplace("100", true);
    info.InsertInnerModuleInfo("entry", innerModuleInfo);
    bool ret = info.IsUserExistModule("entry", Constants::START_USERID);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InnerBundleInfo_2200
 * @tc.name: Test AddModuleRemovableInfo
 * @tc.desc: 1.Test the AddModuleRemovableInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool ret = info.SetModuleRemovable("entry", false, Constants::START_USERID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: FormInfo_0200
 * @tc.name: Test FormInfo
 * @tc.desc: 1.Test the IsValid of FormInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, FormInfo_0200, Function | SmallTest | Level1)
{
    FormInfo formInfo;
    formInfo.window.autoDesignWidth = false;
    formInfo.window.designWidth = -1;
    bool ret = formInfo.IsValid();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: DistributedModuleInfo_0100
 * @tc.name: Test FormInfo
 * @tc.desc: 1.Test Unmarshalling and Dump of DistributedModuleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, DistributedModuleInfo_0100, Function | SmallTest | Level1)
{
    DistributedModuleInfo info1;
    info1.moduleName = "entry";
    OHOS::Parcel parcel;
    info1.Marshalling(parcel);
    DistributedModuleInfo info2;
    info2.Unmarshalling(parcel);
    bool res = info2.ReadFromParcel(parcel);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: DistributedAbilityInfo_0100
 * @tc.name: Test FormInfo
 * @tc.desc: 1.Test Unmarshalling and Dump of DistributedAbilityInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, DistributedAbilityInfo_0100, Function | SmallTest | Level1)
{
    DistributedAbilityInfo info;
    info.abilityName = "MainAbility";
    OHOS::Parcel parcel;
    info.Marshalling(parcel);
    info.Unmarshalling(parcel);
    bool res = info.ReadFromParcel(parcel);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: PerfProfile_0100
 * @tc.name: Test FormInfo
 * @tc.desc: 1.Test Unmarshalling and Dump of DistributedAbilityInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, PerfProfile_0100, Function | SmallTest | Level1)
{
    DistributedAbilityInfo info;
    info.abilityName = "MainAbility";
    OHOS::Parcel parcel;
    info.Marshalling(parcel);
    info.Unmarshalling(parcel);
    bool res = info.ReadFromParcel(parcel);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: CommonEventInfo_0100
 * @tc.name: Test FormInfo
 * @tc.desc: 1.Test Unmarshalling of CommonEventInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, CommonEventInfo_0100, Function | SmallTest | Level1)
{
    CommonEventInfo info;
    info.uid = 0;
    OHOS::Parcel parcel;
    bool res = info.Marshalling(parcel);
    EXPECT_EQ(res, true);
}
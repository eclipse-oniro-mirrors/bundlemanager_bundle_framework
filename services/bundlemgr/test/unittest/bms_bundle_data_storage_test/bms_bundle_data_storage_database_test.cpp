/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#define private public

#include <fstream>
#include <gtest/gtest.h>

#include "ability_info.h"
#include "access_token.h"
#include "app_log_wrapper.h"
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
namespace OHOS {
namespace {
const std::string BUNDLE_NAME{"com.ohos.test"};
const std::string BUNDLE_NAME_WITH_USERID{"com.ohos.test_100"};
const std::string NORMAL_BUNDLE_NAME{"com.example.test"};
const std::string MODULE_NAME_TEST{"test"};
const std::string MODULE_PACKGE{"com.example.test.entry"};
const std::string MODULE_STATE_0{"test_0"};
const std::string MODULE_STATE_1{"test_1"};
const std::string MODULE_STATE_2{"test2"};
const std::string MODULE_NAME{"entry"};
const std::string TEST_PACK_AGE = "modulePackage";
const std::string TEST_NAME = "com.ohos.launcher";
const std::string TEST_ABILITY_NAME = "com.ohos.launcher.MainAbility";
const std::string TEST_BUNDLE_NAME = "bundleName";
const std::string TEST_UID = "uid";
const std::string TEST_KEY = "key";
const std::string TEST_KEY1 = "key1";
const std::string TEST_KEY2 = "key2";
const std::string USER = "100";
const std::string NAME = "name";
const std::string NAME_UID = "name_100";
const std::string ABILITY_NAME = "MainAbility";
const std::string SETTINGS = "settings";
const std::string WRONG_MODULEPACKAGE = ".modulePackage.";
const std::string WRONG = ".wrong.";
const std::string APP_INDEX = "appIndex";
const std::string USERID = "userId";
const std::string DEPENDENT_NAME = "DependentModule";
const std::string CONTINUE_TYPES = "Test";
const std::string HNPPACKAGE = "hnpPackage";
const std::string HNPPACKAGETYPE = "type";
const std::string URI = "dataability://test";
int32_t state = 0;
int32_t versionCode = 0;
int32_t userId = 1;
int32_t userId2 = 2;
int32_t appIndex = 1;
const int32_t FLAG = 0;
// This field is used to ensure OTA upgrade and cannot be added randomly.
const nlohmann::json INNER_BUNDLE_INFO_JSON_3_2 = R"(
{
    "allowedAcls":[],
    "appFeature":"hos_system_app",
    "appIndex":0,
    "appType":0,
    "baseAbilityInfos":{
        "com.example.myapplication.entry.MainAbility":{
            "applicationInfo":{
                "accessTokenId":0,
                "accessible":false,
                "allowCommonEvent":[

                ],
                "apiCompatibleVersion":0,
                "apiReleaseType":"",
                "apiTargetVersion":0,
                "appDetailAbilityLibraryPath":"",
                "appDistributionType":"none",
                "appPrivilegeLevel":"normal",
                "appProvisionType":"release",
                "appQuickFix":{
                    "bundleName":"",
                    "deployedAppqfInfo":{
                        "cpuAbi":"",
                        "hqfInfos":[

                        ],
                        "nativeLibraryPath":"",
                        "type":0,
                        "versionCode":0,
                        "versionName":""
                    },
                    "deployingAppqfInfo":{
                        "cpuAbi":"",
                        "hqfInfos":[

                        ],
                        "nativeLibraryPath":"",
                        "type":0,
                        "versionCode":0,
                        "versionName":""
                    },
                    "versionCode":0,
                    "versionName":""
                },
                "arkNativeFileAbi":"",
                "arkNativeFilePath":"",
                "associatedWakeUp":false,
                "bundleName":"",
                "cacheDir":"",
                "codePath":"",
                "cpuAbi":"",
                "crowdtestDeadline":-1,
                "dataBaseDir":"",
                "dataDir":"",
                "debug":false,
                "description":"",
                "descriptionId":0,
                "descriptionResource":{
                    "bundleName":"",
                    "id":0,
                    "moduleName":""
                },
                "deviceId":"",
                "distributedNotificationEnabled":true,
                "enabled":false,
                "entityType":"unspecified",
                "entryDir":"",
                "entryModuleName":"",
                "fingerprint":"",
                "flags":0,
                "formVisibleNotify":false,
                "hideDesktopIcon":false,
                "icon":"",
                "iconId":0,
                "iconPath":"",
                "iconResource":{
                    "bundleName":"",
                    "id":0,
                    "moduleName":""
                },
                "isCompressNativeLibs":true,
                "isFreeInstallApp":false,
                "isLauncherApp":false,
                "isSystemApp":false,
                "keepAlive":false,
                "label":"",
                "labelId":0,
                "labelResource":{
                    "bundleName":"",
                    "id":0,
                    "moduleName":""
                },
                "metaData":{

                },
                "metadata":{

                },
                "minCompatibleVersionCode":0,
                "moduleInfos":[

                ],
                "moduleSourceDirs":[

                ],
                "multiProjects":false,
                "name":"",
                "nativeLibraryPath":"",
                "needAppDetail":false,
                "permissions":[

                ],
                "process":"",
                "removable":true,
                "runningResourcesApply":false,
                "signatureKey":"",
                "singleton":false,
                "supportedModes":0,
                "targetBundleList":[

                ],
                "uid":-1,
                "userDataClearable":true,
                "vendor":"",
                "versionCode":0,
                "versionName":"",
                "multiAppMode": {
                    "multiAppModeType":2,
                    "maxCount":5
                }
            },
            "applicationName":"com.example.myapplication",
            "backgroundModes":0,
            "bundleName":"com.example.myapplication",
            "codePath":"",
            "compileMode":0,
            "configChanges":[

            ],
            "continuable":false,
            "defaultFormHeight":0,
            "defaultFormWidth":0,
            "description":"$string:MainAbility_desc",
            "descriptionId":16777218,
            "deviceCapabilities":[

            ],
            "deviceTypes":[
                "default",
                "tablet"
            ],
            "enabled":true,
            "excludeFromMissions":false,
            "extensionAbilityType":255,
            "formEnabled":false,
            "formEntity":0,
            "hapPath":"/data/app/el1/bundle/public/com.example.myapplication/entry.hap",
            "iconId":16777222,
            "iconPath":"$media:icon",
            "isLauncherAbility":false,
            "isModuleJson":true,
            "isNativeAbility":false,
            "isStageBasedModel":true,
            "kind":"",
            "label":"$string:MainAbility_label",
            "labelId":16777219,
            "launchMode":0,
            "maxWindowHeight":0,
            "maxWindowRatio":0,
            "maxWindowWidth":0,
            "metaData":{
                "customizeData":[

                ]
            },
            "metadata":[

            ],
            "minFormHeight":0,
            "minFormWidth":0,
            "minWindowHeight":0,
            "minWindowRatio":0,
            "minWindowWidth":0,
            "moduleName":"entry",
            "name":"MainAbility",
            "orientation":0,
            "package":"entry",
            "permissions":[

            ],
            "priority":0,
            "process":"",
            "readPermission":"",
            "removeMissionAfterTerminate":false,
            "resourcePath":"/data/app/el1/bundle/public/com.example.myapplication/entry/resources.index",
            "srcEntrance":"./ets/MainAbility/MainAbility.ts",
            "srcLanguage":"js",
            "srcPath":"",
            "startWindowBackground":"$color:white",
            "startWindowBackgroundId":16777221,
            "startWindowIcon":"$media:icon",
            "startWindowIconId":16777222,
            "supportPipMode":false,
            "supportWindowMode":[
                0,
                1,
                2
            ],
            "targetAbility":"",
            "theme":"",
            "type":1,
            "uid":-1,
            "uri":"",
            "visible":true,
            "writePermission":"",
            "supportExtNames": [],
            "supportMimeTypes": []
        }
    },
    "baseApplicationInfo":{
        "accessTokenId":0,
        "accessible":false,
        "allowCommonEvent":[

        ],
        "apiCompatibleVersion":9,
        "apiReleaseType":"Beta3",
        "apiTargetVersion":9,
        "appDetailAbilityLibraryPath":"",
        "appDistributionType":"os_integration",
        "appPrivilegeLevel":"system_core",
        "appProvisionType":"release",
        "appQuickFix":{
            "bundleName":"",
            "deployedAppqfInfo":{
                "cpuAbi":"",
                "hqfInfos":[

                ],
                "nativeLibraryPath":"",
                "type":0,
                "versionCode":0,
                "versionName":""
            },
            "deployingAppqfInfo":{
                "cpuAbi":"",
                "hqfInfos":[

                ],
                "nativeLibraryPath":"",
                "type":0,
                "versionCode":0,
                "versionName":""
            },
            "versionCode":0,
            "versionName":""
        },
        "arkNativeFileAbi":"",
        "arkNativeFilePath":"",
        "associatedWakeUp":false,
        "bundleName":"com.example.myapplication",
        "cacheDir":"",
        "codePath":"/data/app/el1/bundle/public/com.example.myapplication",
        "cpuAbi":"arm64-v8a",
        "crowdtestDeadline":-1,
        "dataBaseDir":"/data/app/el2/database/com.example.myapplication",
        "dataDir":"",
        "debug":true,
        "description":"",
        "descriptionId":0,
        "descriptionResource":{
            "bundleName":"com.example.myapplication",
            "id":0,
            "moduleName":"entry"
        },
        "deviceId":"PHONE-001",
        "distributedNotificationEnabled":true,
        "enabled":true,
        "entityType":"unspecified",
        "entryDir":"",
        "entryModuleName":"",
        "fingerprint":"8E93863FC32EE238060BF69A9B37E2608FFFB21F93C862DD511CBAC9F30024B5",
        "flags":0,
        "formVisibleNotify":false,
        "hideDesktopIcon":false,
        "icon":"",
        "iconId":16777217,
        "iconPath":"$media:app_icon",
        "iconResource":{
            "bundleName":"com.example.myapplication",
            "id":16777217,
            "moduleName":"entry"
        },
        "isCompressNativeLibs":true,
        "isFreeInstallApp":false,
        "isLauncherApp":false,
        "isSystemApp":true,
        "keepAlive":false,
        "label":"$string:app_name",
        "labelId":16777216,
        "labelResource":{
            "bundleName":"com.example.myapplication",
            "id":16777216,
            "moduleName":"entry"
        },
        "metaData":{},
        "metadata":{},
        "minCompatibleVersionCode":1000000,
        "moduleInfos":[],
        "moduleSourceDirs":[],
        "multiProjects":false,
        "name":"com.example.myapplication",
        "nativeLibraryPath":"",
        "needAppDetail":false,
        "permissions":[],
        "process":"com.example.myapplication",
        "removable":true,
        "runningResourcesApply":false,
        "signatureKey":"",
        "singleton":false,
        "supportedModes":0,
        "targetBundleList":[],
        "uid":-1,
        "userDataClearable":true,
        "vendor":"example",
        "versionCode":1000000,
        "versionName":"1.0.0",
        "resourcesApply":[],
        "multiAppMode": {
            "multiAppModeType":2,
            "maxCount":5
        },
        "configuration":""
    },
    "baseBundleInfo":{
        "abilityInfos":[],
        "appId":"com.example.myapplication",
        "appIndex":0,
        "applicationInfo":{
            "accessTokenId":0,
            "accessible":false,
            "allowCommonEvent":[

            ],
            "apiCompatibleVersion":0,
            "apiReleaseType":"",
            "apiTargetVersion":0,
            "appDetailAbilityLibraryPath":"",
            "appDistributionType":"none",
            "appPrivilegeLevel":"normal",
            "appProvisionType":"release",
            "appQuickFix":{
                "bundleName":"",
                "deployedAppqfInfo":{
                    "cpuAbi":"",
                    "hqfInfos":[

                    ],
                    "nativeLibraryPath":"",
                    "type":0,
                    "versionCode":0,
                    "versionName":""
                },
                "deployingAppqfInfo":{
                    "cpuAbi":"",
                    "hqfInfos":[

                    ],
                    "nativeLibraryPath":"",
                    "type":0,
                    "versionCode":0,
                    "versionName":""
                },
                "versionCode":0,
                "versionName":""
            },
            "arkNativeFileAbi":"",
            "arkNativeFilePath":"",
            "associatedWakeUp":false,
            "bundleName":"",
            "cacheDir":"",
            "codePath":"",
            "cpuAbi":"",
            "crowdtestDeadline":-1,
            "dataBaseDir":"",
            "dataDir":"",
            "debug":false,
            "description":"",
            "descriptionId":0,
            "descriptionResource":{
                "bundleName":"",
                "id":0,
                "moduleName":""
            },
            "deviceId":"",
            "distributedNotificationEnabled":true,
            "enabled":false,
            "entityType":"unspecified",
            "entryDir":"",
            "entryModuleName":"",
            "fingerprint":"",
            "flags":0,
            "formVisibleNotify":false,
            "hideDesktopIcon":false,
            "icon":"",
            "iconId":0,
            "iconPath":"",
            "iconResource":{
                "bundleName":"",
                "id":0,
                "moduleName":""
            },
            "isCompressNativeLibs":true,
            "isFreeInstallApp":false,
            "isLauncherApp":false,
            "isSystemApp":false,
            "keepAlive":false,
            "label":"",
            "labelId":0,
            "labelResource":{
                "bundleName":"",
                "id":0,
                "moduleName":""
            },
            "metaData":{},
            "metadata":{},
            "minCompatibleVersionCode":0,
            "moduleInfos":[],
            "moduleSourceDirs":[],
            "multiProjects":false,
            "name":"",
            "nativeLibraryPath":"",
            "needAppDetail":false,
            "permissions":[],
            "process":"",
            "removable":true,
            "runningResourcesApply":false,
            "signatureKey":"",
            "singleton":false,
            "supportedModes":0,
            "targetBundleList":[],
            "uid":-1,
            "userDataClearable":true,
            "vendor":"",
            "versionCode":0,
            "versionName":"",
            "resourcesApply":[],
            "multiAppMode": {
                "multiAppModeType":2,
                "maxCount":5
            },
            "configuration":""
        },
        "compatibleVersion":9,
        "cpuAbi":"",
        "defPermissions":[],
        "description":"",
        "entryInstallationFree":false,
        "entryModuleName":"entry",
        "extensionAbilityInfo":[],
        "gid":-1,
        "hapModuleInfos":[

        ],
        "hapModuleNames":[],
        "installTime":0,
        "isDifferentName":false,
        "isKeepAlive":false,
        "isNativeApp":false,
        "isPreInstallApp":false,
        "jointUserId":"",
        "label":"",
        "mainEntry":"entry",
        "maxSdkVersion":-1,
        "minCompatibleVersionCode":1000000,
        "minSdkVersion":-1,
        "moduleDirs":[],
        "moduleNames":[],
        "modulePublicDirs":[],
        "moduleResPaths":[],
        "name":"com.example.myapplication",
        "releaseType":"Beta3",
        "reqPermissionDetails":[],
        "reqPermissionStates":[],
        "reqPermissions":[],
        "seInfo":"",
        "signatureInfo":{
            "appId":"",
            "fingerprint":""
        },
        "singleton":false,
        "targetVersion":9,
        "uid":-1,
        "updateTime":0,
        "vendor":"example",
        "versionCode":1000000,
        "versionName":"1.0.0"
    },
    "baseDataDir":"",
    "baseExtensionInfos":{},
    "bundlePackInfo":{
        "packages":[
            {
                "deliveryWithInstall":true,
                "deviceType":[
                    "default",
                    "tablet"
                ],
                "moduleType":"entry",
                "name":"entry-default"
            }
        ],
        "summary":{
            "app":{
                "bundleName":"com.example.myapplication",
                "version":{
                    "code":1000000,
                    "minCompatibleVersionCode":0,
                    "name":"1.0.0"
                }
            },
            "modules":[
                {
                    "abilities":[
                        {
                            "forms":[],
                            "label":"$string:MainAbility_label",
                            "name":"MainAbility",
                            "visible":true
                        }
                    ],
                    "apiVersion":{
                        "compatible":9,
                        "releaseType":"Beta3",
                        "target":9
                    },
                    "deviceType":[
                        "default",
                        "tablet"
                    ],
                    "distro":{
                        "deliveryWithInstall":true,
                        "installationFree":false,
                        "moduleName":"entry",
                        "moduleType":"entry"
                    },
                    "extensionAbilities":[],
                    "mainAbility":"MainAbility"
                }
            ]
        }
    },
    "bundleStatus":1,
    "commonEvents":{},
    "disposedStatus":0,
    "extensionSkillInfos":{},
    "formInfos":{},
    "hqfInfos":[],
    "innerBundleUserInfos":{
        "com.example.myapplication_100":{
            "accessTokenId":537285595,
            "bundleName":"com.example.myapplication",
            "bundleUserInfo":{
                "disabledAbilities":[],
                "enabled":true,
                "userId":100
            },
            "gids":[
                20010065
            ],
            "installTime":1678677771,
            "uid":20010065,
            "updateTime":1678677771,
            "cloneInfos":{}
        }
    },
    "innerModuleInfos":{
        "entry":{
            "abilityKeys":[
                "com.example.myapplication.entry.MainAbility"
            ],
            "colorMode":-1,
            "compileMode":"jsbundle",
            "cpuAbi":"",
            "definePermissions":[],
            "dependencies":[],
            "description":"$string:entry_desc",
            "descriptionId":16777220,
            "deviceTypes":[
                "default",
                "tablet"
            ],
            "distro":{
                "deliveryWithInstall":true,
                "installationFree":false,
                "moduleName":"entry",
                "moduleType":"entry"
            },
            "entryAbilityKey":"com.example.myapplication.entry.MainAbility",
            "extensionKeys":[],
            "extensionSkillKeys":[],
            "hapPath":"/data/app/el1/bundle/public/com.example.myapplication/entry.hap",
            "hashValue":"",
            "icon":"$media:icon",
            "iconId":16777222,
            "installationFree":false,
            "isEntry":true,
            "isLibIsolated":false,
            "isModuleJson":true,
            "isRemovable":{},
            "isStageBasedModel":true,
            "label":"$string:MainAbility_label",
            "labelId":16777219,
            "mainAbility":"MainAbility",
            "metaData":{
                "customizeData":[]
            },
            "metadata":[],
            "moduleDataDir":"",
            "moduleName":"entry",
            "modulePackage":"entry",
            "modulePath":"/data/app/el1/bundle/public/com.example.myapplication/entry",
            "moduleResPath":"/data/app/el1/bundle/public/com.example.myapplication/entry/resources.index",
            "name":"entry",
            "nativeLibraryPath":"",
            "pages":"$profile:main_pages",
            "process":"com.example.myapplication",
            "reqCapabilities":[],
            "requestPermissions":[],
            "skillKeys":[
                "com.example.myapplication.entry.MainAbility"
            ],
            "srcEntrance":"./ets/Application/MyAbilityStage.ts",
            "srcPath":"",
            "uiSyntax":"hml",
            "upgradeFlag":0,
            "virtualMachine":"ark",
            "compressNativeLibs": true,
            "nativeLibraryFileNames": []
        }
    },
    "installMark":{
        "installMarkBundle":"com.example.myapplication",
        "installMarkPackage":"entry",
        "installMarkStatus":2
    },
    "isNewVersion":true,
    "isSandboxApp":false,
    "sandboxPersistentInfo":[
    ],
    "shortcutInfos":{
    },
    "skillInfos":{
        "com.example.myapplication.entry.MainAbility":[
            {
                "actions":[
                    "action.system.home"
                ],
                "entities":[
                    "entity.system.home"
                ],
                "uris":[

                ]
            }
        ]
    },
    "userId_":0,
    "uninstallState":true
})"_json;
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
    void CheckOverlayModuleState(
            const InnerBundleInfo &info, const std::string &moduleName, int32_t state) const;

protected:
    nlohmann::json innerBundleInfoJson_ = R"(
        {
            "allowedAcls": [],
            "appFeature": "hos_system_app",
            "appType": 0,
            "baseAbilityInfos": {
                "com.ohos.launcher.com.ohos.launcher.com.ohos.launcher.MainAbility": {
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
                    "recoverable":false,
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
                    "skills" : [],
                    "srcEntrance": "",
                    "srcLanguage": "ets",
                    "srcPath": "MainAbility",
                    "supportPipMode": false,
                    "targetAbility": "",
                    "theme": "",
                    "type": 1,
                    "unclearableMission": false,
                    "excludeFromDock": false,
                    "preferMultiWindowOrientation": "default",
                    "uri": "",
                    "visible": true,
                    "writePermission": "",
                    "supportExtNames": [],
                    "supportMimeTypes": [],
                    "isolationProcess": false,
                    "continueType": [],
                    "appIndex": 0,
                    "orientationId": 0
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
                    "recoverable": false,
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
                    "writePermission": "",
                    "orientationId": 0
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
                    "recoverable": false,
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
                    "writePermission": "",
                    "orientationId": 0
                }
            },
            "baseApplicationInfo": {
                "accessTokenId": 0,
                "accessTokenIdEx": 0,
                "accessible": false,
                "allowEnableNotification": false,
                "allowAppRunWhenDeviceFirstLocked": false,
                "apiCompatibleVersion": 8,
                "apiReleaseType": "Beta1",
                "apiTargetVersion": 8,
                "appPrivilegeLevel": "normal",
                "hnpPackages": {},
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
                "applicationReservedFlag": 0,
                "arkNativeFileAbi": "",
                "arkNativeFilePath": "",
                "asanEnabled": false,
                "bundleType": "app",
                "asanLogPath": "",
                "bundleName": "com.ohos.launcher",
                "cacheDir": "/data/app/el2/100/base/com.ohos.launcher/cache",
                "codePath": "/data/app/el1/bundle/public/com.ohos.launcher",
                "compileSdkType":"OpenHarmony",
                "compileSdkVersion":"",
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
                "appDetailAbilityLibraryPath": "",
                "bundleType": 0,
                "targetBundleName": "",
                "targetPriority": 0,
                "overlayState": 0,
                "resourcesApply":[],
                "GWPAsanEnabled": false,
                "tsanEnabled": false,
                "hwasanEnabled": false,
                "organization": "",
                "appEnvironments": [],
                "multiAppMode": {
                    "multiAppModeType":2,
                    "maxCount":5
                },
                "appIndex":0,
                "maxChildProcess": 0,
                "installSource": "unknown",
                "configuration":"",
                "cloudFileSyncEnabled": false
            },
            "baseBundleInfo": {
                "abilityInfos": [
                ],
                "appId": "com.ohos.launcher_BNtg4JBClbl92Rgc3jm/RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=",
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
                "overlayType": 3,
                "overlayBundleInfos": [
                ],
                "releaseType": "Beta1",
                "reqPermissionDetails": [
                ],
                "reqPermissionStates": [
                ],
                "reqPermissions": [
                ],
                "signatureInfo": {
                    "appId": "",
                    "fingerprint": "",
                    "appIdentifier": ""
                },
                "seInfo": "",
                "singleton": false,
                "targetVersion": 8,
                "uid": -1,
                "updateTime": 0,
                "appIndex": 0,
                "vendor": "ohos",
                "versionCode": 1000000,
                "versionName": "1.0.0",
                "oldAppIds":[],
                "routerArray": [],
                "isNewVersion": false
            },
            "baseExtensionInfos_": {
            },
            "bundleStatus": 1,
            "commonEvents": {
            },
            "extensionSkillInfos_": {
            },
            "innerSharedModuleInfos": {
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
                    "virtualMachine": "",
                    "compressNativeLibs": true,
                    "nativeLibraryFileNames": []
                },
                "com.ohos.launcher.recents": {
                    "abilityKeys": [
                        "com.ohos.launcher.com.ohos.launcher.recents.com.ohos.launcher.recents.MainAbility"
                    ],
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
                    "virtualMachine": "",
                    "compressNativeLibs": true,
                    "nativeLibraryFileNames": []
                },
                "com.ohos.launcher.settings": {
                    "abilityKeys": [
                        "com.ohos.launcher.com.ohos.launcher.settings.com.ohos.launcher.settings.MainAbility"
                    ],
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
                    "virtualMachine": "",
                    "compressNativeLibs": true,
                    "nativeLibraryFileNames": []
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
            "userId_": 100,
            "provisionMetadatas": {},
            "innerSharedBundleModuleInfos": {}
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

void BmsBundleDataStorageDatabaseTest::CheckOverlayModuleState(
    const InnerBundleInfo &info, const std::string &moduleName, int32_t state) const
{
    for (auto &innerUserInfo : info.GetInnerBundleUserInfos()) {
        auto &overlayStates = innerUserInfo.second.bundleUserInfo.overlayModulesState;
        std::any_of(overlayStates.begin(), overlayStates.end(), [&moduleName, &state](auto &item) {
            if (item.find(moduleName + Constants::FILE_UNDERLINE) == std::string::npos) {
                EXPECT_FALSE(true);
                return false;
            }
            EXPECT_EQ(item, MODULE_STATE_0);
            return true;
        });
    }
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
    nlohmann::json infoJson;
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
            infoJson = innerBundleInfoJson_.at(BASE_BUNDLE_INFO);
            infoJson[iter.key()] = valueIter.value();
        }
    }
    EXPECT_EQ(infoJson[NAME], TEST_NAME);
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
    nlohmann::json infoJson;
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
            infoJson = innerBundleInfoJson_.at(BASE_ABILITY_INFO).at(abilityName);
            infoJson[iter.key()] = valueIter.value();
        }
    }
    EXPECT_EQ(infoJson[NAME], TEST_ABILITY_NAME);
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
    nlohmann::json infoJson;
    typeErrorProps["name"] = NOT_STRING_TYPE;
    typeErrorProps["bundleName"] = NOT_STRING_TYPE;
    typeErrorProps["sandboxId"] = NOT_NUMBER_TYPE;
    typeErrorProps["signatureKey"] = NOT_STRING_TYPE;

    for (nlohmann::json::iterator iter = typeErrorProps.begin(); iter != typeErrorProps.end(); iter++) {
        for (auto valueIter = iter.value().begin(); valueIter != iter.value().end(); valueIter++) {
            APP_LOGD("deserialize check prop key = %{public}s, type = %{public}s",
                iter.key().c_str(),
                valueIter.key().c_str());
            infoJson = innerBundleInfoJson_.at(BASE_APPLICATION_INFO);
            infoJson[iter.key()] = valueIter.value();
        }
    }
    EXPECT_EQ(infoJson[NAME], TEST_NAME);
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
    userInfo.bundleName = TEST_BUNDLE_NAME;
    userInfo.uid = Constants::INVALID_UID;
    userInfo.accessTokenId = 0;
    userInfo.gids.push_back(0);
    userInfo.installTime = 0;
    userInfo.updateTime = 0;
    userInfo.bundleUserInfo.userId = 100;
    to_json(jsonObject, userInfo);
    EXPECT_EQ(jsonObject[TEST_BUNDLE_NAME], TEST_BUNDLE_NAME);
    EXPECT_EQ(jsonObject[TEST_UID], Constants::INVALID_UID);
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
    actions.emplace_back(NAME);
    skill.actions = actions;
    want.SetAction(NAME);
    ret = skill.MatchLauncher(want);
    EXPECT_EQ(ret, true);

    want.AddEntity(MODULE_NAME);
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
 * @tc.number: InnerBundleInfo_0400
 * @tc.name: Test BuildDefaultUserInfo
 * @tc.desc: 1.Use FromJson to call BuildDefaultUserInfo of InnerBundleInfoCpp
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_0400, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    nlohmann::json jsonObject;
    info.FromJson(jsonObject);
    EXPECT_EQ(applicationInfo.bundleName, NAME);
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
    hqfInfo.moduleName = TEST_PACK_AGE;
    hqfInfos.emplace_back(hqfInfo);
    info.SetQuickFixHqfInfos(hqfInfos);
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    info.AddInnerModuleInfo(innerModuleInfos);
    auto it = info.FindHapModuleInfo(TEST_PACK_AGE, 100);
    EXPECT_EQ(it->hqfInfo.moduleName, TEST_PACK_AGE);
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
    extensionInfo.name = TEST_KEY;
    std::vector<Skill> skill;
    innerModuleInfo.extensionKeys.emplace_back(TEST_KEY1);
    innerModuleInfo.extensionSkillKeys.emplace_back(TEST_KEY2);
    info.InsertExtensionInfo(TEST_KEY1, extensionInfo);
    info.InsertExtensionSkillInfo(TEST_KEY2, skill);
    info.InsertInnerModuleInfo(WRONG_MODULEPACKAGE, innerModuleInfo);
    info.InsertShortcutInfos(WRONG, shortcutInfo1);
    info.InsertShortcutInfos(WRONG_MODULEPACKAGE, shortcutInfo2);
    info.InsertCommonEvents(WRONG, commonEvent1);
    info.InsertCommonEvents(WRONG_MODULEPACKAGE, commonEvent2);
    info.RemoveModuleInfo(WRONG_MODULEPACKAGE);
    auto ret1 = info.GetInnerExtensionInfos();
    auto ret2 = info.GetExtensionSkillInfos();
    EXPECT_EQ(ret1[TEST_KEY1].name, "");
    EXPECT_EQ(ret2[TEST_KEY2].empty(), true);
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
    innerModuleInfo.moduleName = WRONG_MODULEPACKAGE;
    innerModuleInfo.isModuleJson = true;
    std::vector<Metadata> data;
    Metadata data1;
    data1.name = NAME;
    data.emplace_back(data1);
    innerModuleInfo.metadata = data;
    info.InsertInnerModuleInfo(WRONG_MODULEPACKAGE, innerModuleInfo);
    ApplicationInfo appInfo1;
    appInfo1.bundleName = BUNDLE_NAME;
    info.SetBaseApplicationInfo(appInfo1);
    const int32_t failedId = -5;
    const int32_t flags = 0;
    ApplicationInfo appInfo2;
    info.GetApplicationInfo(flags, failedId, appInfo2);
    EXPECT_EQ(appInfo2.metadata[WRONG_MODULEPACKAGE].empty(), true);
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
    hapModuleInfo.name = NAME;
    const int32_t flags = 0;
    info.GetModuleWithHashValue(flags, "", hapModuleInfo);
    EXPECT_EQ(hapModuleInfo.name, NAME);
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
    innerModuleInfo.moduleName = MODULE_NAME;
    info.InsertInnerModuleInfo(TEST_KEY, innerModuleInfo);
    std::vector<std::string> moduleNames;
    info.GetModuleNames(moduleNames);
    EXPECT_EQ(moduleNames[0], MODULE_NAME);
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
    appInfo1.bundleName = BUNDLE_NAME;
    info.SetBaseApplicationInfo(appInfo1);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    innerBundleUserInfo.bundleUserInfo.enabled = false;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);
    const int32_t userId1 = -1;
    const int32_t userId2 = 100;
    info.ResetBundleState(userId1);
    auto ret = info.GetInnerBundleUserInfos();
    EXPECT_EQ(ret[BUNDLE_NAME_WITH_USERID].bundleUserInfo.enabled, false);
    info.ResetBundleState(userId2);
    ret = info.GetInnerBundleUserInfos();
    EXPECT_EQ(ret[BUNDLE_NAME_WITH_USERID].bundleUserInfo.enabled, true);
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
    appInfo1.bundleName = BUNDLE_NAME;
    info.SetBaseApplicationInfo(appInfo1);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME;
    innerModuleInfo.isRemovable[USER] = true;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);
    info.InsertInnerModuleInfo(NAME_UID, innerModuleInfo);
    const int32_t userId1 = -1;
    const int32_t userId2 = 100;
    info.RemoveInnerBundleUserInfo(userId1);
    auto ret = info.GetInnerModuleInfos();
    EXPECT_EQ(ret[NAME_UID].isRemovable[USER], true);
    info.RemoveInnerBundleUserInfo(userId2);
    ret = info.GetInnerModuleInfos();
    EXPECT_EQ(ret[NAME_UID].isRemovable[USER], false);
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
    int32_t userId = ServiceConstants::NOT_EXIST_USERID;
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
    userId = ServiceConstants::NOT_EXIST_USERID;
    AbilityInfo abilityInfo;
    ret = info.IsAbilityEnabled(abilityInfo, userId);
    EXPECT_EQ(ret, true);
    userId = Constants::ALL_USERID;
    ret = info.IsAbilityEnabled(abilityInfo, userId);
    EXPECT_EQ(ret, false);
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
    auto ret = info.SetAbilityEnabled("", "", isEnabled, userId);
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
    std::string bundleName = BUNDLE_NAME;
    std::string moduleName = "";
    std::string extensionName = "";
    auto ret = info.FindExtensionInfo(moduleName, extensionName);
    EXPECT_EQ(ret, std::nullopt);

    ExtensionAbilityInfo extensionInfo;
    moduleName = MODULE_NAME;
    extensionName = bundleName;
    extensionInfo.bundleName = bundleName;
    extensionInfo.moduleName = moduleName;
    extensionInfo.name = extensionName;
    info.InsertExtensionInfo(TEST_KEY, extensionInfo);
    ret = info.FindExtensionInfo(moduleName, extensionName);
    EXPECT_EQ((*ret).bundleName, bundleName);
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
    innerModuleInfo.moduleName = MODULE_NAME;
    info.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    bool ret = info.IsBundleRemovable();
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
    innerModuleInfo.moduleName = MODULE_NAME;
    innerModuleInfo.isRemovable.try_emplace(USER, true);
    info.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    bool ret = info.IsUserExistModule(MODULE_NAME, Constants::START_USERID);
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
    bool ret = info.SetModuleRemovable(MODULE_NAME, false, Constants::START_USERID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfo_2300
 * @tc.name: Test FindExtensionInfos
 * @tc.desc: 1.Test the FindExtensionInfos of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2300, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string bundleName = BUNDLE_NAME;
    auto ret = info.FindExtensionInfos();
    EXPECT_EQ(ret, std::nullopt);

    ExtensionAbilityInfo extensionInfo;
    extensionInfo.bundleName = bundleName;
    info.InsertExtensionInfo(TEST_KEY, extensionInfo);
    ret = info.FindExtensionInfos();
    EXPECT_NE(ret, std::nullopt);
}

/**
 * @tc.number: InnerBundleInfo_2300
 * @tc.name: Test ProcessBundleWithHapModuleInfoFlag
 * @tc.desc: 1.Test the ProcessBundleWithHapModuleInfoFlag of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2400, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    info.ProcessBundleWithHapModuleInfoFlag(FLAG, bundleInfo, Constants::START_USERID);
    EXPECT_EQ(bundleInfo.hapModuleInfos.empty(), true);

    int32_t flag = 2;
    std::vector<HqfInfo> hqfInfos;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = TEST_PACK_AGE;
    hqfInfos.emplace_back(hqfInfo);
    info.SetQuickFixHqfInfos(hqfInfos);
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    info.AddInnerModuleInfo(innerModuleInfos);
    info.InsertInnerModuleInfo(TEST_PACK_AGE, moduleInfo);
    info.ProcessBundleWithHapModuleInfoFlag(flag, bundleInfo, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(bundleInfo.hapModuleInfos.empty(), true);
}

/**
 * @tc.number: InnerBundleInfo_2500
 * @tc.name: Test GetBundleWithAbilitiesV9
 * @tc.desc: 1.Test the GetBundleWithAbilitiesV9 of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2500, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    HapModuleInfo hapModuleInfo;
    info.GetBundleWithAbilitiesV9(FLAG, hapModuleInfo, Constants::START_USERID);
    EXPECT_EQ(hapModuleInfo.abilityInfos.empty(), true);

    AbilityInfo abilityInfo;
    abilityInfo.moduleName = hapModuleInfo.moduleName;
    abilityInfo.name = "";
    info.InsertAbilitiesInfo(TEST_KEY, abilityInfo);
    int32_t flag = 4;
    info.GetBundleWithAbilitiesV9(flag, hapModuleInfo, Constants::START_USERID);
    EXPECT_EQ(hapModuleInfo.abilityInfos.empty(), true);

    info.GetBundleWithAbilitiesV9(flag, hapModuleInfo, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(hapModuleInfo.abilityInfos.empty(), false);

    abilityInfo.moduleName = BUNDLE_NAME;
    abilityInfo.name = ServiceConstants::APP_DETAIL_ABILITY;
    hapModuleInfo.moduleName = MODULE_NAME;
    info.InsertAbilitiesInfo(TEST_KEY, abilityInfo);
    info.GetBundleWithAbilitiesV9(flag, hapModuleInfo, Constants::START_USERID);
    EXPECT_EQ(hapModuleInfo.abilityInfos.empty(), true);
}

/**
 * @tc.number: InnerBundleInfo_2600
 * @tc.name: Test GetBundleWithExtensionAbilitiesV9
 * @tc.desc: 1.Test the GetBundleWithExtensionAbilitiesV9 of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2600, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    HapModuleInfo hapModuleInfo;
    std::string moduleName = MODULE_NAME;
    info.GetBundleWithExtensionAbilitiesV9(FLAG, hapModuleInfo);
    EXPECT_EQ(hapModuleInfo.extensionInfos.empty(), true);

    ExtensionAbilityInfo extensionInfo;
    int32_t flag = 8;
    extensionInfo.moduleName = moduleName;
    extensionInfo.enabled = false;
    info.InsertExtensionInfo(TEST_KEY, extensionInfo);
    info.GetBundleWithExtensionAbilitiesV9(flag, hapModuleInfo);
    EXPECT_EQ(hapModuleInfo.extensionInfos.empty(), true);

    std::map<std::string, ExtensionAbilityInfo> extensionInfos;
    extensionInfo.enabled = true;
    hapModuleInfo.moduleName = extensionInfo.moduleName;
    extensionInfos["baseExtensionInfos_"] = extensionInfo;
    info.AddModuleExtensionInfos(extensionInfos);
    info.GetBundleWithExtensionAbilitiesV9(flag, hapModuleInfo);
    EXPECT_EQ(hapModuleInfo.extensionInfos.empty(), false);
}

/**
 * @tc.number: InnerBundleInfo_2700
 * @tc.name: Test GetRemovableModules
 * @tc.desc: 1.Test the GetRemovableModules of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2700, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::vector<std::string> moduleToDelete;
    bool ret = info.GetRemovableModules(moduleToDelete);
    EXPECT_EQ(ret, false);

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_PACK_AGE;
    moduleInfo.installationFree = false;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos[TEST_PACK_AGE] = moduleInfo;
    info.AddInnerModuleInfo(innerModuleInfos);
    ret = info.GetRemovableModules(moduleToDelete);
    EXPECT_EQ(ret, false);

    moduleInfo.installationFree = true;
    ret = info.GetRemovableModules(moduleToDelete);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfo_2800
 * @tc.name: Test IsBundleRemovable
 * @tc.desc: 1.Test the IsBundleRemovable of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2800, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    moduleInfo.installationFree = true;
    moduleInfo.isRemovable.try_emplace(MODULE_NAME, false);
    moduleInfo.isRemovable.try_emplace(MODULE_NAME_TEST, true);
    info.innerModuleInfos_.try_emplace(MODULE_NAME, moduleInfo);
    bool ret = info.IsBundleRemovable();
    EXPECT_EQ(ret, false);

    std::vector<std::string> moduleToDelete;
    ret = info.GetRemovableModules(moduleToDelete);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfo_2900
 * @tc.name: Test GetInnerModuleInfoHnpInfo
 * @tc.desc: 1.Test the GetInnerModuleInfoHnpInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_2900, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    auto ret = info.GetInnerModuleInfoHnpInfo("");
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: InnerBundleInfo_3000
 * @tc.name: Test GetInnerModuleInfoHnpPath
 * @tc.desc: 1.Test the GetInnerModuleInfoHnpPath of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3000, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string ret = info.GetInnerModuleInfoHnpPath("");
    EXPECT_EQ(ret, "");
}

/**
 * @tc.number: InnerBundleInfo_3100
 * @tc.name: Test GetAllDependentModuleNames
 * @tc.desc: 1.Test the GetAllDependentModuleNames of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3100, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    Dependency dependency;
    dependency.moduleName = DEPENDENT_NAME;
    moduleInfo.dependencies.push_back(dependency);
    bundleInfo.innerModuleInfos_[TEST_KEY] = moduleInfo;
    std::vector<std::string> dependentModuleNames;
    bool ret = bundleInfo.GetAllDependentModuleNames(MODULE_NAME, dependentModuleNames);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InnerBundleInfo_3200
 * @tc.name: Test FindAbilityInfo
 * @tc.desc: 1.Test the FindAbilityInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3200, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    auto ret = bundleInfo.FindAbilityInfo(CONTINUE_TYPES, userId);
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: InnerBundleInfo_3300
 * @tc.name: Test FindAbilityInfo
 * @tc.desc: 1.Test the FindAbilityInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3300, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(CONTINUE_TYPES);
    abilityInfo.continueType = continueTypes;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair(BUNDLE_NAME, abilityInfo));
    auto ret = bundleInfo.FindAbilityInfo(CONTINUE_TYPES, userId);
    EXPECT_NE(ret, std::nullopt);
}

/**
 * @tc.number: InnerBundleInfo_3400
 * @tc.name: Test GetAllSharedDependencies
 * @tc.desc: 1.Test the GetAllSharedDependencies of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3400, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    Dependency dependency;
    dependency.moduleName = DEPENDENT_NAME;
    moduleInfo.dependencies.push_back(dependency);
    bundleInfo.innerModuleInfos_[MODULE_NAME] = moduleInfo;
    std::vector<Dependency> dependencies;
    bool ret = bundleInfo.GetAllSharedDependencies(MODULE_NAME, dependencies);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InnerBundleInfo_3500
 * @tc.name: Test GetApplicationInfo
 * @tc.desc: 1.Test the GetApplicationInfo with baseApplicationInfo_ == nullptr
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3500, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = WRONG_MODULEPACKAGE;
    std::vector<Metadata> data;
    Metadata data1;
    data1.name = NAME;
    data.emplace_back(data1);
    innerModuleInfo.metadata = data;
    info.InsertInnerModuleInfo(WRONG_MODULEPACKAGE, innerModuleInfo);
    const int32_t failedId = -5;
    const int32_t flags = 0;
    ApplicationInfo appInfo2;
    info.GetApplicationInfo(flags, failedId, appInfo2);
    EXPECT_EQ(appInfo2.metadata[WRONG_MODULEPACKAGE].empty(), true);
}

/**
 * @tc.number: InnerBundleInfo_3600
 * @tc.name: Test GetInnerModuleInfoHnpInfo
 * @tc.desc: 1.Test the GetInnerModuleInfoHnpInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3600, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.innerModuleInfos_.clear();
    InnerModuleInfo innerModuleInfo;
    HnpPackage hnpPackage;
    std::vector<HnpPackage> hnpPackages;
    hnpPackage.package = HNPPACKAGE;
    hnpPackage.type = HNPPACKAGETYPE;
    hnpPackages.push_back(hnpPackage);
    innerModuleInfo.hnpPackages = hnpPackages;
    innerModuleInfo.moduleName = MODULE_NAME;
    info.innerModuleInfos_.insert(std::make_pair(MODULE_NAME, innerModuleInfo));
    auto ret = info.GetInnerModuleInfoHnpInfo(MODULE_NAME);
    EXPECT_NE(ret, std::nullopt);
}

/**
 * @tc.number: InnerBundleInfo_3700
 * @tc.name: Test GetInnerModuleInfoHnpPath
 * @tc.desc: 1.Test the GetInnerModuleInfoHnpPath of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3700, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.innerModuleInfos_.clear();
    InnerModuleInfo innerModuleInfo;
    HnpPackage hnpPackage;
    std::vector<HnpPackage> hnpPackages;
    hnpPackage.package = HNPPACKAGE;
    hnpPackage.type = HNPPACKAGETYPE;
    hnpPackages.push_back(hnpPackage);
    innerModuleInfo.hnpPackages = hnpPackages;
    innerModuleInfo.moduleName = MODULE_NAME;
    innerModuleInfo.moduleHnpsPath = MODULE_PACKGE;
    info.innerModuleInfos_.insert(std::make_pair(MODULE_NAME, innerModuleInfo));
    auto ret = info.GetInnerModuleInfoHnpPath(MODULE_NAME);
    EXPECT_NE(ret, "");
}

/**
 * @tc.number: InnerBundleInfo_3800
 * @tc.name: Test SetCloneAbilityEnabled
 * @tc.desc: 1.Test the SetCloneAbilityEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3800, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME;
    abilityInfo.moduleName = MODULE_NAME_TEST;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair(ABILITY_NAME, abilityInfo));
    auto ret = bundleInfo.SetCloneAbilityEnabled(MODULE_NAME_TEST, ABILITY_NAME, true, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    bundleInfo.baseAbilityInfos_.clear();
    AbilityInfo abilityInfo2;
    abilityInfo2.name = ABILITY_NAME;
    abilityInfo2.moduleName = BUNDLE_NAME;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair(ABILITY_NAME, abilityInfo2));
    ret = bundleInfo.SetCloneAbilityEnabled(MODULE_NAME_TEST, ABILITY_NAME, true, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    bundleInfo.baseAbilityInfos_.clear();
    AbilityInfo abilityInfo3;
    abilityInfo3.name = ABILITY_NAME;
    abilityInfo3.moduleName = MODULE_NAME_TEST;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair(ABILITY_NAME, abilityInfo3));
    ret = bundleInfo.SetCloneAbilityEnabled("", ABILITY_NAME, true, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: InnerBundleInfo_3900
 * @tc.name: Test SetCloneAbilityEnabled
 * @tc.desc: 1.Test the SetCloneAbilityEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_3900, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    bundleInfo.baseAbilityInfos_.clear();
    auto ret = bundleInfo.SetCloneAbilityEnabled(MODULE_NAME_TEST, ABILITY_NAME, true, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: InnerBundleInfo_4000
 * @tc.name: Test SetCloneAbilityEnabled
 * @tc.desc: 1.Test the SetCloneAbilityEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4000, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME;
    abilityInfo.moduleName = MODULE_NAME_TEST;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair(ABILITY_NAME, abilityInfo));
    auto ret = bundleInfo.SetCloneAbilityEnabled(MODULE_NAME_TEST, "", true, userId, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: InnerBundleInfo_4100
 * @tc.name: Test SetCloneAbilityEnabled
 * @tc.desc: 1.Test the SetCloneAbilityEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4100, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME;
    abilityInfo.moduleName = MODULE_NAME_TEST;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair("_1", abilityInfo));
    InnerBundleUserInfo innerBundleUserInfo;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));
    auto ret = bundleInfo.SetCloneAbilityEnabled(MODULE_NAME_TEST, ABILITY_NAME, true, userId, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX);
}

/**
 * @tc.number: InnerBundleInfo_4200
 * @tc.name: Test SetCloneAbilityEnabled
 * @tc.desc: 1.Test the SetCloneAbilityEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4200, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME;
    abilityInfo.moduleName = MODULE_NAME_TEST;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair("_1", abilityInfo));
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back(ABILITY_NAME);
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));
    auto ret = bundleInfo.SetCloneAbilityEnabled(MODULE_NAME_TEST, ABILITY_NAME, true, userId, appIndex);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerBundleInfo_4300
 * @tc.name: Test SetCloneAbilityEnabled
 * @tc.desc: 1.Test the SetCloneAbilityEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4300, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME;
    abilityInfo.moduleName = MODULE_NAME_TEST;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair("_1", abilityInfo));
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));
    auto ret = bundleInfo.SetCloneAbilityEnabled(MODULE_NAME_TEST, ABILITY_NAME, true, userId, appIndex);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerBundleInfo_4400
 * @tc.name: Test SetInnerModuleNeedDelete
 * @tc.desc: 1.Test the SetInnerModuleNeedDelete of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4400, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.innerModuleInfos_.clear();
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME;
    info.innerModuleInfos_.insert(std::make_pair(MODULE_NAME, innerModuleInfo));
    info.SetInnerModuleNeedDelete(MODULE_NAME, true);
    EXPECT_TRUE(info.innerModuleInfos_.at(MODULE_NAME).needDelete);
}

/**
 * @tc.number: InnerBundleInfo_4500
 * @tc.name: Test SetCloneApplicationEnabled
 * @tc.desc: 1.Test the SetCloneApplicationEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4500, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair(MODULE_NAME, innerBundleUserInfo));
    auto ret = bundleInfo.SetCloneApplicationEnabled(true, appIndex, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: InnerBundleInfo_4600
 * @tc.name: Test SetCloneApplicationEnabled
 * @tc.desc: 1.Test the SetCloneApplicationEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4600, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back(MODULE_NAME);
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair(MODULE_NAME, innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));
    auto ret = bundleInfo.SetCloneApplicationEnabled(true, appIndex, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX);
}

/**
 * @tc.number: InnerBundleInfo_4700
 * @tc.name: Test SetCloneApplicationEnabled
 * @tc.desc: 1.Test the SetCloneApplicationEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4700, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::map<std::string, InnerBundleCloneInfo> cloneInfos;
    InnerBundleCloneInfo innerBundleCloneInfo;
    std::vector<std::string> disabledAbilities;
    disabledAbilities.push_back("");
    innerBundleCloneInfo.disabledAbilities = disabledAbilities;
    cloneInfos.insert(std::make_pair("1", innerBundleCloneInfo));
    innerBundleUserInfo.cloneInfos = cloneInfos;
    bundleInfo.innerBundleUserInfos_.insert(std::make_pair("_1", innerBundleUserInfo));
    auto ret = bundleInfo.SetCloneApplicationEnabled(true, appIndex, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerBundleInfo_4800
 * @tc.name: Test GetQuickFixHqfInfos
 * @tc.desc: 1.Test the GetQuickFixHqfInfos of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4800, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = MODULE_NAME;
    bundleInfo.hqfInfos_.push_back(hqfInfo);
    std::vector<HqfInfo> hqfInfos;
    hqfInfos = bundleInfo.GetQuickFixHqfInfos();
    EXPECT_FALSE(hqfInfos.empty());
}

/**
 * @tc.number: InnerBundleInfo_4900
 * @tc.name: Test RemoveOverlayModuleInfo
 * @tc.desc: 1.Test the RemoveOverlayModuleInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_4900, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerModuleInfo innerModuleInfo;
    bundleInfo.innerModuleInfos_.insert(std::make_pair(MODULE_NAME, innerModuleInfo));
    bundleInfo.RemoveOverlayModuleInfo(MODULE_NAME, BUNDLE_NAME, MODULE_NAME);
    EXPECT_FALSE(bundleInfo.innerModuleInfos_.empty());
}

/**
 * @tc.number: InnerBundleInfo_5000
 * @tc.name: Test RemoveOverlayModuleInfo
 * @tc.desc: 1.Test the RemoveOverlayModuleInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5000, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerModuleInfo innerModuleInfo;
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = BUNDLE_NAME;
    overlayModuleInfo.moduleName = MODULE_NAME;
    overlayModuleInfos.push_back(overlayModuleInfo);
    innerModuleInfo.overlayModuleInfo = overlayModuleInfos;
    bundleInfo.innerModuleInfos_.insert(std::make_pair(MODULE_NAME, innerModuleInfo));
    bundleInfo.RemoveOverlayModuleInfo(MODULE_NAME, BUNDLE_NAME, MODULE_NAME);
    EXPECT_FALSE(bundleInfo.innerModuleInfos_.empty());
}

/**
 * @tc.number: InnerBundleInfo_5100
 * @tc.name: Test KeepOldOverlayConnection
 * @tc.desc: 1.Test the KeepOldOverlayConnection of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5100, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerBundleInfo bundleInfoNew;
    InnerModuleInfo innerModuleInfo;
    InnerModuleInfo innerModuleInfoNew;
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = BUNDLE_NAME;
    overlayModuleInfo.moduleName = MODULE_NAME;
    overlayModuleInfos.push_back(overlayModuleInfo);
    innerModuleInfo.overlayModuleInfo = overlayModuleInfos;
    innerModuleInfo.moduleName = MODULE_NAME;
    bundleInfo.innerModuleInfos_.insert(std::make_pair(MODULE_NAME, innerModuleInfo));
    bundleInfoNew.innerModuleInfos_.insert(std::make_pair(MODULE_NAME, innerModuleInfoNew));
    bundleInfo.KeepOldOverlayConnection(bundleInfoNew);
    EXPECT_FALSE(bundleInfoNew.innerModuleInfos_[MODULE_NAME].overlayModuleInfo.empty());
}

/**
 * @tc.number: InnerBundleInfo_5200
 * @tc.name: Test FindExtensionAbilityInfoByUri
 * @tc.desc: 1.Test the FindExtensionAbilityInfoByUri of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5200, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.uri = URI;
    ExtensionAbilityInfo baseExtensionInfo;
    bundleInfo.baseExtensionInfos_.insert(std::make_pair(MODULE_NAME, extensionAbilityInfo));
    bool ret = bundleInfo.FindExtensionAbilityInfoByUri(URI, baseExtensionInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InnerBundleInfo_5300
 * @tc.name: Test FindExtensionAbilityInfoByUri
 * @tc.desc: 1.Test the FindExtensionAbilityInfoByUri of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5300, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    bundleInfo.baseExtensionInfos_.clear();
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.uri = URI;
    ExtensionAbilityInfo baseExtensionInfo;
    bool ret = bundleInfo.FindExtensionAbilityInfoByUri(URI, baseExtensionInfo);
    EXPECT_FALSE(ret);
    bundleInfo.baseExtensionInfos_.insert(std::make_pair(MODULE_NAME, extensionAbilityInfo));
    ret = bundleInfo.FindExtensionAbilityInfoByUri("URI", baseExtensionInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InnerBundleInfo_5400
 * @tc.name: Test FindAbilityInfosByUri
 * @tc.desc: 1.Test the FindAbilityInfosByUri of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5400, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.uri = URI;
    std::vector<AbilityInfo> abilityInfos;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair(TEST_ABILITY_NAME, abilityInfo));
    bundleInfo.FindAbilityInfosByUri("test", abilityInfos, userId);
    EXPECT_FALSE(abilityInfos.empty());
}

/**
 * @tc.number: InnerBundleInfo_5500
 * @tc.name: Test FindAbilityInfosByUri
 * @tc.desc: 1.Test the FindAbilityInfosByUri of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5500, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.uri = URI;
    std::vector<AbilityInfo> abilityInfos;
    bundleInfo.baseAbilityInfos_.insert(std::make_pair(TEST_ABILITY_NAME, abilityInfo));
    bundleInfo.FindAbilityInfosByUri(URI, abilityInfos, userId);
    EXPECT_TRUE(abilityInfos.empty());
}

/**
 * @tc.number: InnerBundleInfo_5600
 * @tc.name: Test RemoveGroupInfos
 * @tc.desc: 1.Test the RemoveGroupInfos of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5600, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    std::vector<DataGroupInfo> dataGroupInfos;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.userId = userId;
    dataGroupInfos.push_back(dataGroupInfo);
    bundleInfo.dataGroupInfos_.insert(std::make_pair(TEST_NAME, dataGroupInfos));
    bundleInfo.RemoveGroupInfos(userId, "1");
    EXPECT_FALSE(bundleInfo.dataGroupInfos_.empty());
    bundleInfo.RemoveGroupInfos(userId2, TEST_NAME);
    EXPECT_FALSE(bundleInfo.dataGroupInfos_.empty());
    bundleInfo.RemoveGroupInfos(userId, TEST_NAME);
    EXPECT_FALSE(bundleInfo.dataGroupInfos_.empty());
}

/**
 * @tc.number: InnerBundleInfo_5700
 * @tc.name: Test UpdateDataGroupInfos
 * @tc.desc: 1.Test the UpdateDataGroupInfos of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5700, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    std::vector<DataGroupInfo> dataGroupInfos;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.userId = userId;
    dataGroupInfos.push_back(dataGroupInfo);
    bundleInfo.dataGroupInfos_.insert(std::make_pair(TEST_NAME, dataGroupInfos));
    std::vector<DataGroupInfo> dataGroupInfosNew;
    DataGroupInfo dataGroupInfoNew;
    std::unordered_map<std::string, std::vector<DataGroupInfo>> dataGroupInfoMapNew;
    dataGroupInfoNew.userId = userId;
    dataGroupInfosNew.push_back(dataGroupInfoNew);
    dataGroupInfoMapNew.insert(std::make_pair(TEST_NAME, dataGroupInfosNew));
    bundleInfo.UpdateDataGroupInfos(dataGroupInfoMapNew);
    EXPECT_FALSE(dataGroupInfoMapNew.empty());
}

/**
 * @tc.number: InnerBundleInfo_5800
 * @tc.name: Test UpdateDataGroupInfos
 * @tc.desc: 1.Test the UpdateDataGroupInfos with empty input
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5800, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    std::vector<DataGroupInfo> dataGroupInfos;
    DataGroupInfo dataGroupInfo;
    dataGroupInfo.userId = userId;
    dataGroupInfos.push_back(dataGroupInfo);
    bundleInfo.dataGroupInfos_.insert(std::make_pair(TEST_NAME, dataGroupInfos));
    std::vector<DataGroupInfo> dataGroupInfosNew;
    std::unordered_map<std::string, std::vector<DataGroupInfo>> dataGroupInfoMapNew;
    bundleInfo.UpdateDataGroupInfos(dataGroupInfoMapNew);
    EXPECT_FALSE(bundleInfo.dataGroupInfos_.empty());
}

/**
 * @tc.number: InnerBundleInfo_5900
 * @tc.name: Test IsAsanEnabled
 * @tc.desc: 1.Test the IsAsanEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_5900, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerModuleInfo innerModuleInfo;
    std::vector<InnerModuleInfo> innerModuleInfos;
    innerModuleInfo.asanEnabled = true;
    innerModuleInfos.push_back(innerModuleInfo);
    bundleInfo.innerSharedModuleInfos_.insert(std::make_pair(TEST_NAME, innerModuleInfos));
    bool ret = bundleInfo.IsAsanEnabled();
    EXPECT_TRUE(ret);
    innerModuleInfo.asanEnabled = false;
    innerModuleInfos.clear();
    innerModuleInfos.push_back(innerModuleInfo);
    bundleInfo.innerSharedModuleInfos_.clear();
    bundleInfo.innerSharedModuleInfos_.insert(std::make_pair(TEST_NAME, innerModuleInfos));
    ret = bundleInfo.IsAsanEnabled();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InnerBundleInfo_6000
 * @tc.name: Test IsGwpAsanEnabled
 * @tc.desc: 1.Test the IsGwpAsanEnabled of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_6000, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    InnerModuleInfo innerModuleInfo;
    std::vector<InnerModuleInfo> innerModuleInfos;
    innerModuleInfo.gwpAsanEnabled = true;
    innerModuleInfos.push_back(innerModuleInfo);
    bundleInfo.innerSharedModuleInfos_.insert(std::make_pair(TEST_NAME, innerModuleInfos));
    bool ret = bundleInfo.IsGwpAsanEnabled();
    EXPECT_TRUE(ret);
    innerModuleInfo.gwpAsanEnabled = false;
    innerModuleInfos.clear();
    innerModuleInfos.push_back(innerModuleInfo);
    bundleInfo.innerSharedModuleInfos_.clear();
    bundleInfo.innerSharedModuleInfos_.insert(std::make_pair(TEST_NAME, innerModuleInfos));
    ret = bundleInfo.IsGwpAsanEnabled();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InnerBundleInfo_6100
 * @tc.name: Test SetUninstallState
 * @tc.desc: 1.Test the SetUninstallState of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_6100, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    bundleInfo.SetUninstallState(false);
    EXPECT_FALSE(bundleInfo.uninstallState_);
}

/**
 * @tc.number: InnerBundleInfo_6200
 * @tc.name: Test GetAllExtensionDirsInSpecifiedModule
 * @tc.desc: 1.Test the GetAllExtensionDirsInSpecifiedModule of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_6200, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.moduleName = MODULE_NAME;
    extensionAbilityInfo.needCreateSandbox = true;
    bundleInfo.baseExtensionInfos_.insert(std::make_pair(MODULE_NAME, extensionAbilityInfo));
    auto ret = bundleInfo.GetAllExtensionDirsInSpecifiedModule(MODULE_NAME);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.number: InnerBundleInfo_6300
 * @tc.name: Test GetAllExtensionDirs
 * @tc.desc: 1.Test the GetAllExtensionDirs of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_6300, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.needCreateSandbox = true;
    bundleInfo.baseExtensionInfos_.insert(std::make_pair(MODULE_NAME, extensionAbilityInfo));
    auto ret = bundleInfo.GetAllExtensionDirs();
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.number: InnerBundleInfo_6400
 * @tc.name: Test UpdateExtensionDataGroupInfo
 * @tc.desc: 1.Test the UpdateExtensionDataGroupInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InnerBundleInfo_6400, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    std::vector<std::string> dataGroupIds;
    dataGroupIds.push_back(TEST_UID);
    bundleInfo.baseExtensionInfos_.insert(std::make_pair(TEST_NAME, extensionAbilityInfo));
    bundleInfo.UpdateExtensionDataGroupInfo("1", dataGroupIds);
    EXPECT_TRUE(bundleInfo.baseExtensionInfos_[TEST_NAME].validDataGroupIds.empty());
    bundleInfo.UpdateExtensionDataGroupInfo(TEST_NAME, dataGroupIds);
    EXPECT_FALSE(bundleInfo.baseExtensionInfos_[TEST_NAME].validDataGroupIds.empty());
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
    info1.moduleName = MODULE_NAME;
    OHOS::Parcel parcel;
    bool result = info1.Marshalling(parcel);
    ASSERT_TRUE(result);
    auto info2 = DistributedModuleInfo::Unmarshalling(parcel);
    ASSERT_NE(info2, nullptr);
    delete(info2);
}

/**
 * @tc.number: DistributedAbilityInfo_0100
 * @tc.name: Test FormInfo
 * @tc.desc: 1.Test Unmarshalling and Dump of DistributedAbilityInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, DistributedAbilityInfo_0100, Function | SmallTest | Level1)
{
    DistributedAbilityInfo info;
    info.abilityName = ABILITY_NAME;
    OHOS::Parcel parcel;
    auto res = info.Marshalling(parcel);
    ASSERT_TRUE(res);

    auto info2 = DistributedAbilityInfo::Unmarshalling(parcel);
    ASSERT_NE(info2, nullptr);
    delete(info2);
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
    ASSERT_TRUE(res);

    auto info2 = CommonEventInfo::Unmarshalling(parcel);
    ASSERT_NE(info2, nullptr);
    delete(info2);
}

/**
 * @tc.number: CheckNeedPreloadTest
 * @tc.name: Test CheckNeedPreload
 * @tc.desc: 1.Test CheckNeedPreload of ApplicationInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, CheckNeedPreloadTest, Function | SmallTest | Level1)
{
    ApplicationInfo applicationInfo;
    std::vector<ModuleInfo> moduleInfos;
    ModuleInfo info1;
    info1.moduleName = SETTINGS;
    moduleInfos.emplace_back(info1);
    applicationInfo.moduleInfos = moduleInfos;
    std::string moduleName = MODULE_NAME;
    bool ret = applicationInfo.CheckNeedPreload(moduleName);
    EXPECT_EQ(ret, false);
    ModuleInfo info2;
    info2.moduleName = MODULE_NAME;
    info2.preloads.emplace_back(MODULE_NAME);
    moduleInfos.emplace_back(info2);
    applicationInfo.moduleInfos = moduleInfos;
    ret = applicationInfo.CheckNeedPreload(moduleName);
    EXPECT_EQ(ret, false);

    moduleInfos.clear();
    info2.preloads.emplace_back(SETTINGS);
    moduleInfos.emplace_back(info2);
    applicationInfo.moduleInfos = moduleInfos;
    ret = applicationInfo.CheckNeedPreload(moduleName);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SetAccessTokenIdEx_0100
 * @tc.name: Test SetAccessTokenIdEx
 * @tc.desc: 1.Test the SetAccessTokenIdEx
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, SetAccessTokenIdEx_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = NORMAL_BUNDLE_NAME;
    info.SetBaseApplicationInfo(applicationInfo);

    OHOS::Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    accessTokenIdEx.tokenIDEx = 100;
    int32_t userId = Constants::DEFAULT_USERID;
    info.SetAccessTokenIdEx(accessTokenIdEx, userId);
    uint64_t tokenIdEx = info.GetAccessTokenIdEx(userId);
    EXPECT_EQ(tokenIdEx, 0);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    info.AddInnerBundleUserInfo(userInfo);
    info.SetAccessTokenIdEx(accessTokenIdEx, userId);
    tokenIdEx = info.GetAccessTokenIdEx(userId);
    EXPECT_EQ(tokenIdEx, accessTokenIdEx.tokenIDEx);
}

/**
 * @tc.number: GetMaxVerBaseSharedBundleInfoTest
 * @tc.name: Test GetMaxVerBaseSharedBundleInfo
 * @tc.desc: Test the GetMaxVerBaseSharedBundleInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, GetMaxVerBaseSharedBundleInfoTest, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BaseSharedBundleInfo sharedBundleInfo;
    bool ret = info.GetMaxVerBaseSharedBundleInfo(MODULE_NAME_TEST, sharedBundleInfo);
    EXPECT_EQ(ret, false);
    std::vector<InnerModuleInfo> moduleInfos;
    info.innerSharedModuleInfos_[MODULE_NAME_TEST] = moduleInfos;
    ret = info.GetMaxVerBaseSharedBundleInfo(MODULE_NAME_TEST, sharedBundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InsertInnerSharedModuleInfo
 * @tc.name: Test InsertInnerSharedModuleInfo
 * @tc.desc: Test the InsertInnerSharedModuleInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, InsertInnerSharedModuleInfo, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.versionCode = Constants::ALL_VERSIONCODE;
    info.InsertInnerSharedModuleInfo(MODULE_NAME_TEST, innerModuleInfo);
    EXPECT_EQ(info.GetInnerSharedModuleInfos().empty(), false);
    std::vector<InnerModuleInfo> moduleInfos;
    info.innerSharedModuleInfos_[MODULE_NAME_TEST] = moduleInfos;
    info.InsertInnerSharedModuleInfo(MODULE_NAME_TEST, innerModuleInfo);
    EXPECT_EQ(info.GetInnerSharedModuleInfos().empty(), false);
    moduleInfos.emplace_back(innerModuleInfo);
    info.innerSharedModuleInfos_[MODULE_NAME_TEST] = moduleInfos;
    info.InsertInnerSharedModuleInfo(MODULE_NAME_TEST, innerModuleInfo);
    EXPECT_EQ(info.GetInnerSharedModuleInfos().empty(), false);
    moduleInfos.clear();
    InnerModuleInfo newInfo;
    newInfo.versionCode = versionCode;
    moduleInfos.emplace_back(newInfo);
    info.InsertInnerSharedModuleInfo(MODULE_NAME_TEST, innerModuleInfo);
    EXPECT_EQ(info.GetInnerSharedModuleInfos().empty(), false);
}

/**
 * @tc.number: SharedModuleNativeLibraryPathTest
 * @tc.name: Test different nativeLibraryPath param
 * @tc.desc: Test the SetSharedModuleNativeLibraryPath of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, SharedModuleNativeLibraryPathTest, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.SetCurrentModulePackage(MODULE_PACKGE);
    info.SetSharedModuleNativeLibraryPath(MODULE_PACKGE);
    EXPECT_EQ(info.GetInnerSharedModuleInfos().empty(), true);

    std::vector<InnerModuleInfo> moduleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.versionCode = versionCode;
    moduleInfos.emplace_back(innerModuleInfo);
    info.InsertInnerModuleInfo(MODULE_PACKGE, innerModuleInfo);
    info.innerSharedModuleInfos_[MODULE_PACKGE] = moduleInfos;
    info.SetSharedModuleNativeLibraryPath(MODULE_PACKGE);
    EXPECT_EQ(info.GetInnerSharedModuleInfos().empty(), false);
}

/**
 * @tc.number: SetOverlayModuleState_0100
 * @tc.name: Test different moduleName and state param
 * @tc.desc: Test the SetOverlayModuleState of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, SetOverlayModuleState_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    info.SetOverlayModuleState(MODULE_NAME_TEST, state, Constants::START_USERID);
    CheckOverlayModuleState(info, MODULE_NAME_TEST, state);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = Constants::START_USERID;
    InnerBundleUserInfo newInfo;
    newInfo.bundleUserInfo.userId = Constants::DEFAULT_USERID;
    newInfo.bundleUserInfo.overlayModulesState.emplace_back(MODULE_STATE_0);
    innerBundleUserInfos[MODULE_NAME] = userInfo;
    innerBundleUserInfos[MODULE_NAME_TEST] = newInfo;
    info.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);
    info.innerBundleUserInfos_ = innerBundleUserInfos;
    info.SetOverlayModuleState(MODULE_NAME_TEST, state, Constants::DEFAULT_USERID);
    CheckOverlayModuleState(info, MODULE_NAME_TEST, state);
}

/**
 * @tc.number: SetOverlayModuleState_0200
 * @tc.name: Test different moduleName and state param
 * @tc.desc: Test the SetOverlayModuleState of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, SetOverlayModuleState_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.SetOverlayModuleState(MODULE_NAME_TEST, state);
    CheckOverlayModuleState(info, MODULE_NAME_TEST, state);

    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo newInfo;
    newInfo.bundleUserInfo.overlayModulesState.emplace_back(MODULE_STATE_0);
    info.SetOverlayType(OVERLAY_EXTERNAL_BUNDLE);
    innerBundleUserInfos[MODULE_NAME_TEST] = newInfo;
    info.innerBundleUserInfos_ = innerBundleUserInfos;
    info.SetOverlayModuleState(MODULE_NAME_TEST, state);
    CheckOverlayModuleState(info, MODULE_NAME_TEST, state);

    info.overlayType_ = OverlayType::NON_OVERLAY_TYPE;
    info.SetOverlayModuleState(MODULE_NAME_TEST, state);
    CheckOverlayModuleState(info, MODULE_NAME_TEST, state);
}

/**
 * @tc.number: GetOverlayModuleStateTest
 * @tc.name: Test use different param with GetOverlayModuleState
 * @tc.desc: Test the GetOverlayModuleState of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, GetOverlayModuleStateTest, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    int userId = ServiceConstants::NOT_EXIST_USERID;
    bool ret = info.GetOverlayModuleState("", userId, state);
    EXPECT_EQ(ret, false);

    userId = Constants::START_USERID;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseApplicationInfo(applicationInfo);
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo oldInfo;
    innerBundleUserInfos[MODULE_NAME] = oldInfo;
    info.innerBundleUserInfos_ = innerBundleUserInfos;
    ret = info.GetOverlayModuleState(MODULE_NAME_TEST, userId, state);
    EXPECT_EQ(ret, false);

    InnerBundleUserInfo newInfo;
    innerBundleUserInfos[BUNDLE_NAME_WITH_USERID] = newInfo;
    info.innerBundleUserInfos_ = innerBundleUserInfos;
    ret = info.GetOverlayModuleState(MODULE_NAME_TEST, userId, state);
    EXPECT_EQ(ret, false);

    newInfo.bundleUserInfo.overlayModulesState.emplace_back(MODULE_STATE_1);
    innerBundleUserInfos[BUNDLE_NAME_WITH_USERID] = newInfo;
    info.innerBundleUserInfos_ = innerBundleUserInfos;
    ret = info.GetOverlayModuleState(MODULE_NAME_TEST, userId, state);
    EXPECT_EQ(ret, true);

    newInfo.bundleUserInfo.overlayModulesState.emplace_back(MODULE_STATE_0);
    newInfo.bundleUserInfo.overlayModulesState.emplace_back(MODULE_STATE_2);
    innerBundleUserInfos[BUNDLE_NAME_WITH_USERID] = newInfo;
    info.innerBundleUserInfos_ = innerBundleUserInfos;
    ret = info.GetOverlayModuleState(MODULE_NAME_TEST, userId, state);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ClearOverlayModuleStatesTest
 * @tc.name: Test use different param with ClearOverlayModuleStates
 * @tc.desc: Test the ClearOverlayModuleStates of InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, ClearOverlayModuleStatesTest, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo newInfo;
    newInfo.bundleUserInfo.overlayModulesState.emplace_back(MODULE_STATE_0);
    innerBundleUserInfos[MODULE_NAME_TEST] = newInfo;
    info.innerBundleUserInfos_ = innerBundleUserInfos;
    bool ret =
        info.innerBundleUserInfos_[MODULE_NAME_TEST].bundleUserInfo.overlayModulesState.empty();
    EXPECT_EQ(ret, false);
    info.ClearOverlayModuleStates(MODULE_NAME_TEST);
    ret = info.innerBundleUserInfos_[MODULE_NAME_TEST].bundleUserInfo.overlayModulesState.empty();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: OTA_InnerBundleInfoJsonSerializer_0001
 * @tc.name: save bundle installation information to persist storage
 * @tc.desc: 1.system running normally
 *           2.successfully deserialize InnerBundleInfo
 */
HWTEST_F(BmsBundleDataStorageDatabaseTest, OTA_InnerBundleInfoJsonSerializer_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    // deserialize BundleInfo from json, test OTA
    auto ret = innerBundleInfo.FromJson(INNER_BUNDLE_INFO_JSON_3_2);
    EXPECT_EQ(ret, 0);
}
} // OHOS
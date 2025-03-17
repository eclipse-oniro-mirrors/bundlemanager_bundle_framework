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

#include <sstream>
#include <string>
#include <gtest/gtest.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_extractor.h"
#include "bundle_parser.h"
#include "bundle_profile.h"
#include "bundle_service_constants.h"
#include "common_profile.h"
#include "default_permission_profile.h"
#include "json_constants.h"
#include "module_profile.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::Constants;
using namespace OHOS::AppExecFwk::ServiceConstants;
using namespace OHOS::AppExecFwk::ProfileReader;
namespace OHOS {
namespace {
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/parse_bundle/";
const std::string BUNDLE_NAME1 = "com.ohos.test1";
const std::string BUNDLE_PERMISSION_NAME1 = "ohos.permission.test1";
const std::string BUNDLE_PERMISSION_NAME2 = "ohos.permission.test2";
const std::string MODULE_NAME = "moduleName";
const std::string NEW_APP = "new";
const std::string UNKOWN_PATH = "unknown_path";
const std::string EMPTY_NAME = "";
const std::string MODULE = "module";
const std::string NAME = "name";
const std::string TYPE = "type";
const std::string NO_EXIST_NAME = "noExist";
const std::string BUNDLETYPE = "bundleType";
const std::string BUNDLE_TYPE_APP = "app";
const std::string PROFILE_KEY_LABEL_ID = "labelId";
const std::string PROFILE_KEY_LABEL = "label";
const std::string BUNDLE_MODULE_PROFILE_KEY_DISTRO = "distro";
const std::string BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE = "moduleType";
const std::string MODULE_TYPE_SHARED = "shared";
const std::string BUNDLE_MODULE_PROFILE_KEY_DEVICE_TYPE = "deviceType";
const std::string BUNDLE_APP_PROFILE_KEY_CODE = "code";
const std::string BUNDLE_APP_PROFILE_KEY_VERSION = "version";
const std::string BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE = "installationFree";
const size_t ONE = 1;
const size_t TWO = 2;
const std::string OVER_MAX_PATH_SIZE(4097, 'x');
const nlohmann::json CONFIG_JSON = R"(
    {
        "app": {
            "bundleName": "com.example.hiworld.himusic",
            "vendor": "example",
            "version": {
                "code": 2,
                "name": "2.0"
            },
            "apiVersion": {
                "compatible": 3,
                "target": 3,
                "releaseType": "Beta1"
            }
        },
        "deviceConfig": {
            "default": {
                "keepAlive":true
            }
        },
        "module": {
            "package": "com.example.hiworld.himusic.entry",
            "name": ".MainApplication",
            "supportedModes": [
                "drive"
            ],
            "distro": {
                "moduleType": "entry",
                "deliveryWithInstall": true,
                "moduleName": "hap-car"
            },
            "deviceType": [
                "car"
            ],
            "shortcuts": [
                {
                    "shortcutId": "id",
                    "label": "$string:shortcut",
                    "icon": "$media:icon",
                    "intents": [
                      {
                        "targetBundle": "com.demo.hiworld.himusic",
                        "targetClass": "com.demo.hiworld.himusic.entry.MainAbility"
                      }
                    ]
                }
            ],
            "abilities": [
                {
                    "name": ".MainAbility",
                    "description": "himusic main ability",
                    "icon": "$media:ic_launcher",
                    "label": "HiMusic",
                    "launchType": "standard",
                    "orientation": "unspecified",
                    "visible": true,
                    "forms": [
                        {
                        "name": "Form_JS",
                        "description": "It's JS Form",
                        "type": "JS",
                        "colorMode": "auto",
                        "isDefault": false,
                        "jsComponentName": "card4x4",
                        "updateEnabled": true,
                        "scheduledUpdateTime": "21:05",
                        "updateDuration": 1,
                        "defaultDimension": "2*1",
                        "supportDimensions": [
                            "2*1"
                        ],
                        "landscapeLayouts": [
                            "$layout:ability_form"
                        ],
                        "portraitLayouts": [
                            "$layout:ability_form"
                        ],
                        "src": "pages/card/index",
                        "window": {
                            "designWidth": 720,
                            "autoDesignWidth": true
                        },
                        "formVisibleNotify": true,
                        "deepLink": "ability://com.example.myapplication.fa/.MainAbility",
                        "formConfigAbility": "ability://com.example.myapplication.fa/.MainAbility",
                            "metaData": {
                                "customizeData": [
                                    {
                                        "name": "originWidgetName",
                                        "value": "com.weather.testWidget"
                                    }
                                ]
                            }
                        }
                    ],
                    "skills": [
                        {
                            "actions": [
                                "action.system.home"
                            ],
                            "entities": [
                                "entity.system.home"
                            ]
                        }
                    ],
                    "type": "page",
                    "formEnabled": true
                },
                {
                    "name": ".PlayService",
                    "description": "himusic play ability",
                    "icon": "$media:ic_launcher",
                    "label": "HiMusic",
                    "launchType": "standard",
                    "orientation": "unspecified",
                    "visible": false,
                    "skills": [
                        {
                            "actions": [
                                "action.play.music",
                                "action.stop.music"
                            ],
                            "entities": [
                                "entity.audio"
                            ]
                        }
                    ],
                    "type": "service",
                    "backgroundModes": [
                        "audioPlayback"
                    ]
                },
                {
                    "name": ".UserADataAbility",
                    "type": "data",
                    "uri": "dataability://com.example.hiworld.himusic.UserADataAbility",
                    "visible": true
                }
            ],
            "reqPermissions": [
                {
                    "name": "ohos.permission.DISTRIBUTED_DATASYNC",
                    "reason": "",
                    "usedScene": {
                        "ability": [
                            "com.example.hiworld.himusic.entry.MainAbility",
                            "com.example.hiworld.himusic.entry.PlayService"
                        ],
                        "when": "inuse"
                    }
                }
            ]
        }
    }
)"_json;

const nlohmann::json CONFIG_JSON_2 = R"(
{
    "app":{
        "apiVersion":{
            "compatible":8,
            "releaseType":"Release",
            "target":8
        },
        "bundleName":"com.example.myapplication",
        "vendor":"example",
        "version":{
            "code":1000000,
            "name":"1.0.0"
        }
    },
    "deviceConfig":{
        "default":{
            "debug":true
        }
    },
    "module":{
        "abilities":[
            {
                "description":"$string:MainAbility_desc",
                "descriptionId":16777216,
                "formsEnabled":false,
                "icon":"$media:icon",
                "iconId":16777220,
                "label":"$string:MainAbility_label",
                "labelId":16777217,
                "launchType":"standard",
                "name":".MainAbility",
                "orientation":"unspecified",
                "srcLanguage":"ets",
                "srcPath":"MainAbility",
                "type":"page",
                "visible":true
            }
        ],
        "deviceType":[
            "phone"
        ],
        "distro":{
            "deliveryWithInstall":true,
            "installationFree":false,
            "moduleName":"entry",
            "moduleType":"entry",
            "virtualMachine":"ark0.0.0.2"
        },
        "js":[
            {
                "mode":{
                    "syntax":"ets",
                    "type":"pageAbility"
                },
                "name":".MainAbility",
                "pages":[
                    "pages/index"
                ],
                "window":{
                    "autoDesignWidth":false,
                    "designWidth":720
                }
            }
        ],
        "mainAbility":".MainAbility",
        "name":".entry",
        "package":"com.example.myapplication"
    }
}
)"_json;

const nlohmann::json CONFIG_JSON_3 = R"(
{
    "app":{
        "apiVersion":{
            "compatible":8,
            "releaseType":"Release",
            "target":8
        },
        "bundleName":"com.example.myapplication",
        "vendor":"example",
        "version":{
            "code":1000000,
            "name":"1.0.0"
        }
    },
    "deviceConfig":{
        "default":{
            "debug":true
        }
    },
    "module":{
        "abilities":[
            {
                "skills": [
                    {
                        "entities": [
                            "entity.system.home"
                        ],
                        "actions": [
                            "action.system.home"
                        ]
                    }
                ],
                "description":"$string:MainAbility_desc",
                "descriptionId":16777216,
                "formsEnabled":false,
                "icon":"$media:icon",
                "iconId":16777220,
                "label":"$string:MainAbility_label",
                "labelId":16777217,
                "launchType":"standard",
                "name":".MainAbility",
                "orientation":"unspecified",
                "srcLanguage":"ets",
                "srcPath":"MainAbility",
                "type":"page",
                "visible":true
            }
        ],
        "deviceType":[
            "phone"
        ],
        "distro":{
            "deliveryWithInstall":true,
            "installationFree":false,
            "moduleName":"entry",
            "moduleType":"entry",
            "virtualMachine":"ark0.0.0.2"
        },
        "js":[
            {
                "mode":{
                    "syntax":"ets",
                    "type":"pageAbility"
                },
                "name":".MainAbility",
                "pages":[
                    "pages/index"
                ],
                "window":{
                    "autoDesignWidth":false,
                    "designWidth":720
                }
            }
        ],
        "mainAbility":".MainAbility",
        "name":".entry",
        "package":"com.example.myapplication"
    }
}
)"_json;

const nlohmann::json MODULE_JSON = R"(
    {
        "app": {
            "apiReleaseType": "Beta3",
            "bundleName": "com.example.backuptest",
            "debug": true,
            "icon": "$media:app_icon",
            "iconId": 16777220,
            "label": "$string:app_name",
            "labelId": 16777216,
            "minAPIVersion": 9,
            "targetAPIVersion": 9,
            "vendor": "example",
            "versionCode": 1000000,
            "versionName": "1.0.0",
            "bundleType": "atomicService",
            "default": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            },
            "car": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            },
            "liteWearable": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            },
            "phone": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            },
            "router": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            },
            "smartVision": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            },
            "tablet": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            },
            "tv": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            },
            "wearable": {
                "accessible": false,
                "keepAlive": false,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false
            }
        },
        "deviceConfig": {
            "default": {
                "keepAlive":true,
                "minAPIVersion": 9,
                "removable": false,
                "singleton": false,
                "userDataClearable": false,
                "accessible": false
            }
        },
        "module": {
            "abilities": [
                {
                    "description": "$string:MainAbility_desc",
                    "descriptionId": 16777217,
                    "icon": "$media:icon",
                    "iconId": 16777221,
                    "label": "$string:MainAbility_label",
                    "labelId": 16777218,
                    "name": "MainAbility",
                    "launchType": "unknowlaunchType",
                    "orientation": "unknoworientation",
                    "skills": [
                        {
                            "actions": [
                                "action.system.home"
                            ],
                            "entities": [
                                "entity.system.home",
                                "flag.home.intent.from.system"
                            ]
                        }
                    ],
                    "srcEntrance": "./ets/MainAbility/MainAbility.ts",
                    "visible": true
                },
                {
                    "description": "$string:MainAbility_desc",
                    "descriptionId": 16777217,
                    "icon": "$media:icon",
                    "iconId": 16777221,
                    "label": "$string:MainAbility_label",
                    "labelId": 16777218,
                    "name": "MainAbility",
                    "launchType": "unknowlaunchType",
                    "orientation": "unknoworientation",
                    "skills": [
                        {
                            "actions": [
                                "action.thirdparty.home"
                            ],
                            "entities": [
                                "entity.thirdparty.home"
                            ]
                        }
                    ],
                    "srcEntrance": "./ets/MainAbility/MainAbility.ts",
                    "visible": true
                },
                {
                    "description": "$string:MainAbility_desc",
                    "descriptionId": 16777217,
                    "icon": "$media:icon",
                    "iconId": 16777221,
                    "label": "$string:MainAbility_label",
                    "labelId": 16777218,
                    "name": "MainAbility",
                    "launchType": "unknowlaunchType",
                    "orientation": "unknoworientation",
                    "skills": [
                        {
                            "actions": [
                                "action.system.home"
                            ],
                            "entities": [
                                "entity.thirdparty.home"
                            ]
                        }
                    ],
                    "srcEntrance": "./ets/MainAbility/MainAbility.ts",
                    "visible": true
                },
                {
                    "description": "$string:MainAbility_desc",
                    "descriptionId": 16777217,
                    "icon": "$media:icon",
                    "iconId": 16777221,
                    "label": "$string:MainAbility_label",
                    "labelId": 16777218,
                    "name": "MainAbility",
                    "launchType": "unknowlaunchType",
                    "orientation": "unknoworientation",
                    "skills": [
                        {
                            "actions": [
                                "action.thirdparty.home"
                            ],
                            "entities": [
                                "entity.system.home"
                            ]
                        }
                    ],
                    "srcEntrance": "./ets/MainAbility/MainAbility.ts",
                    "visible": true
                }
            ],
            "deliveryWithInstall": true,
            "description": "$string:entry_desc",
            "descriptionId": 16777219,
            "deviceTypes": [
                "unknowtype"
            ],
            "extensionAbilities": [
                {
                    "name": "extensionAbility_A",
                    "skills": [
                        {
                            "actions": [
                                "action.system.home"
                            ],
                            "entities": [
                                "entity.system.home"
                            ]
                        }
                    ],
                    "srcEntrance": "",
                    "type": "backup"
                }
            ],
            "installationFree": true,
            "mainElement": "MainAbility",
            "name": "entry",
            "pages": "$profile:main_pages",
            "srcEntrance": "./ets/Application/AbilityStage.ts",
            "type": "unknowtype",
            "virtualMachine": "ark0.0.0.3",
            "atomicService":{
                "preloads":[]
            }
        }
    }
)"_json;

const nlohmann::json MODULE_JSON_2 = R"(
{
        "app": {
            "bundleName": "com.example.backuptest",
            "debug": true,
            "icon": "$media:app_icon",
            "iconId": 16777220,
            "label": "$string:app_name",
            "labelId": 16777216,
            "minAPIVersion": 9,
            "targetAPIVersion": 9,
            "vendor": "example",
            "versionCode": 1000000,
            "versionName": "1.0.0"
        },
        "module": {
            "deliveryWithInstall": true,
            "description": "$string:entry_desc",
            "descriptionId": 16777219,
            "deviceTypes": [
                "default"
            ],
            "abilities": [
                {
                    "description": "$string:MainAbility_desc",
                    "descriptionId": 16777217,
                    "icon": "$media:icon",
                    "iconId": 16777221,
                    "label": "$string:MainAbility_label",
                    "labelId": 16777218,
                    "name": "MainAbility",
                    "launchType": "unknowlaunchType",
                    "orientation": "unknoworientation",
                    "srcEntrance": "./ets/MainAbility/MainAbility.ts",
                    "visible": true
                }
            ],
            "name": "entry",
            "installationFree": false,
            "mainElement": "MainAbility",
            "pages": "$profile:main_pages",
            "srcEntrance": "./ets/Application/AbilityStage.ts",
            "type": "entry",
            "virtualMachine": "ark0.0.0.3"
        }
    }
)"_json;

const nlohmann::json MODULE_JSON_3 = R"(
{
    "app": {
            "bundleName": "com.example.backuptest",
            "debug": true,
            "icon": "$media:app_icon",
            "iconId": 16777220,
            "label": "$string:app_name",
            "labelId": 16777216,
            "minAPIVersion": 9,
            "targetAPIVersion": 9,
            "vendor": "example",
            "versionCode": 1000000,
            "versionName": "1.0.0"
        },
        "module": {
            "deliveryWithInstall": true,
            "description": "$string:entry_desc",
            "descriptionId": 16777219,
            "deviceTypes": [
                "default"
            ],
            "abilities": [
                {
                    "description": "$string:MainAbility_desc",
                    "descriptionId": 16777217,
                    "icon": "$media:icon",
                    "iconId": 16777221,
                    "label": "$string:MainAbility_label",
                    "labelId": 16777218,
                    "name": "MainAbility",
                    "launchType": "unknowlaunchType",
                    "orientation": "unknoworientation",
                    "srcEntrance": "./ets/MainAbility/MainAbility.ts",
                    "visible": true,
                    "skills": [
                        {
                            "actions": [
                                "action.system.home"
                            ],
                            "entities": [
                                "entity.system.home"
                            ]
                        }
                    ]
                }
            ],
            "name": "entry",
            "installationFree": false,
            "mainElement": "MainAbility",
            "pages": "$profile:main_pages",
            "srcEntrance": "./ets/Application/AbilityStage.ts",
            "type": "entry",
            "virtualMachine": "ark0.0.0.3"
        }
    }
)"_json;

const nlohmann::json MODULE_JSON_4 = R"(
    {
    }
)"_json;

const nlohmann::json MODULE_JSON_5 = R"(
{
    "app": {
        "iconId": 33554433,
        "debug": true,
        "minAPIVersion": 16,
        "icon": "$media:app_icon",
        "label": "$string:app_name",
        "bundleType": "app",
        "versionName": "2.0.0",
        "versionCode": 2000000,
        "multiAppMode": {
            "multiAppModeType": "appClone",
            "maxCount": 5
        },
        "appEnvironments": [],
        "compileSdkType": "OpenHarmony",
        "labelId": 33554432,
        "compileSdkVersion": "5.1.0.46",
        "targetAPIVersion": 16,
        "vendor": "example",
        "bundleName": "com.example.myapplication",
        "apiReleaseType": "Beta1"
    },
    "module": {
        "virtualMachine": "ark13.0.1.0",
        "mainElement": "EntryAbility",
        "installationFree": false,
        "deliveryWithInstall": true,
        "description": "$string:module_desc",
        "extensionAbilities": [
            {
                "exported": false,
                "metadata": [
                    {
                        "resourceId": 33554448,
                        "resource": "$profile:backup_config",
                        "name": "ohos.extension.backup"
                    }
                ],
                "srcEntry": "./ets/entrybackupability/EntryBackupAbility.ets",
                "name": "EntryBackupAbility",
                "type": "backup"
            }
        ],
        "compileMode": "esmodule",
        "type": "entry",
        "dependencies": [],
        "abilities": [
            {
                "exported": true,
                "iconId": 33554442,
                "startWindowIconId": 33554443,
                "icon": "$media:layered_image",
                "startWindowIcon": "$media:startIcon",
                "startWindowBackgroundId": 33554439,
                "description": "$string:EntryAbility_desc",
                "startWindow": "$profile:start_window",
                "label": "$string:EntryAbility_label",
                "skills": [
                    {
                        "entities": [
                            "entity.system.home"
                        ],
                        "actions": [
                            "action.system.home"
                        ]
                    }
                ],
                "srcEntry": "./ets/entryability/EntryAbility.ets",
                "descriptionId": 33554434,
                "labelId": 33554435,
                "startWindowBackground": "$color:start_window_background",
                "startWindowId": 33554450,
                "name": "EntryAbility"
            }
        ],
        "deviceTypes": [
            "default",
            "tablet"
        ],
        "pages": "$profile:main_pages",
        "descriptionId": 33554436,
        "name": "entry",
        "packageName": "entry"
        }
    }
)"_json;
}  // namespace

class BmsBundleParserTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    void GetProfileTypeErrorProps(nlohmann::json &typeErrorProps) const;
    void CheckNoPropProfileParseApp(const std::string &propKey, const ErrCode expectCode) const;
    void CheckNoPropProfileParseDeviceConfig(const std::string &propKey, const ErrCode expectCode) const;
    void CheckNoPropProfileParseModule(const std::string &propKey, const ErrCode expectCode) const;
    void CheckProfilePermission(const nlohmann::json &checkedProfileJson) const;
    void CheckProfileForms(const nlohmann::json &checkedProfileJson) const;
    void CheckProfileShortcut(const nlohmann::json &checkedProfileJson, const ErrCode expectCode) const;
    void CheckProfileModule(const nlohmann::json &checkedProfileJson, const ErrCode code) const;
    ErrCode CheckProfileDefaultPermission(const nlohmann::json &checkedProfileJson,
        std::set<DefaultPermission> &defaultPermissions) const;
protected:
    std::ostringstream pathStream_;
};

void BmsBundleParserTest::SetUpTestCase()
{}

void BmsBundleParserTest::TearDownTestCase()
{}

void BmsBundleParserTest::SetUp()
{}

void BmsBundleParserTest::TearDown()
{
    pathStream_.clear();
}

void BmsBundleParserTest::GetProfileTypeErrorProps(nlohmann::json &typeErrorProps) const
{
    typeErrorProps[PROFILE_KEY_NAME] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[PROFILE_KEY_LABEL] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[PROFILE_KEY_DESCRIPTION] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[PROFILE_KEY_TYPE] = JsonConstants::NOT_STRING_TYPE;
    // bundle profile tag
    typeErrorProps[BUNDLE_PROFILE_KEY_APP] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_PROFILE_KEY_DEVICE_CONFIG] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_PROFILE_KEY_MODULE] = JsonConstants::NOT_OBJECT_TYPE;
    // sub BUNDLE_PROFILE_KEY_APP
    typeErrorProps[BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_APP_PROFILE_KEY_VENDOR] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_APP_PROFILE_KEY_VERSION] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_APP_PROFILE_KEY_API_VERSION] = JsonConstants::NOT_OBJECT_TYPE;
    // BUNDLE_APP_PROFILE_KEY_VERSION
    typeErrorProps[BUNDLE_APP_PROFILE_KEY_CODE] = JsonConstants::NOT_NUMBER_TYPE;
    // BUNDLE_APP_PROFILE_KEY_API_VERSION
    typeErrorProps[BUNDLE_APP_PROFILE_KEY_COMPATIBLE] = JsonConstants::NOT_NUMBER_TYPE;
    typeErrorProps[BUNDLE_APP_PROFILE_KEY_TARGET] = JsonConstants::NOT_NUMBER_TYPE;
    typeErrorProps[BUNDLE_APP_PROFILE_KEY_RELEASE_TYPE] = JsonConstants::NOT_STRING_TYPE;
    // sub BUNDLE_PROFILE_KEY_DEVICE_CONFIG
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEFAULT] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_PHONE] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TABLET] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TV] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_CAR] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_WEARABLE] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_LITE_WEARABLE] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SMART_VISION] = JsonConstants::NOT_OBJECT_TYPE;
    // BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEFAULT
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_PROCESS] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DIRECT_LAUNCH] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SUPPORT_BACKUP] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_COMPRESS_NATIVE_LIBS] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_NETWORK] = JsonConstants::NOT_OBJECT_TYPE;
    // BUNDLE_DEVICE_CONFIG_PROFILE_KEY_NETWORK
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_USES_CLEAR_TEXT] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SECURITY_CONFIG] = JsonConstants::NOT_OBJECT_TYPE;
    // BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SECURITY_CONFIG
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAIN_SETTINGS] = JsonConstants::NOT_OBJECT_TYPE;
    // BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAIN_SETTINGS
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_CLEAR_TEXT_PERMITTED] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAINS] = JsonConstants::NOT_ARRAY_TYPE;
    // BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAINS
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SUB_DOMAINS] = JsonConstants::NOT_ARRAY_TYPE;
    // sub BUNDLE_PROFILE_KEY_MODULE
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_PACKAGE] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_SUPPORTED_MODES] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_DEVICE_TYPE] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_DISTRO] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_ABILITIES] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_JS] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_COLOR_MODE] = JsonConstants::NOT_STRING_TYPE;
    // BUNDLE_MODULE_PROFILE_KEY_DISTRO
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_DELIVERY_WITH_INSTALL] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE] = JsonConstants::NOT_STRING_TYPE;
    // BUNDLE_MODULE_PROFILE_KEY_ABILITIES
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_ICON] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_URI] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_LAUNCH_TYPE] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_VISIBLE] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_PERMISSIONS] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_SKILLS] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_DEVICE_CAP_ABILITY] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_ORIENTATION] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_BACKGROUND_MODES] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_READ_PERMISSION] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_WRITE_PERMISSION] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_DIRECT_LAUNCH] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_CONFIG_CHANGES] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_MISSION] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_TARGET_ABILITY] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_MULTIUSER_SHARED] = JsonConstants::NOT_BOOL_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_SUPPORT_PIP_MODE] = JsonConstants::NOT_BOOL_TYPE;
    // BUNDLE_MODULE_PROFILE_KEY_SKILLS
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_ACTIONS] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_ENTITIES] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_URIS] = JsonConstants::NOT_ARRAY_TYPE;
    // BUNDLE_MODULE_PROFILE_KEY_URIS
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_SCHEME] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_HOST] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_PORT] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_PATH] = JsonConstants::NOT_STRING_TYPE;
    // BUNDLE_MODULE_PROFILE_KEY_JS
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_PAGES] = JsonConstants::NOT_ARRAY_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_WINDOW] = JsonConstants::NOT_OBJECT_TYPE;
    // BUNDLE_MODULE_PROFILE_KEY_WINDOW
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_DESIGN_WIDTH] = JsonConstants::NOT_NUMBER_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_AUTO_DESIGN_WIDTH] = JsonConstants::NOT_BOOL_TYPE;
    // BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_ID] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_WANTS] = JsonConstants::NOT_STRING_TYPE;
    // BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_WANTS
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_TARGET_CLASS] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_TARGET_BUNDLE] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_COMPATIBLE] = JsonConstants::NOT_NUMBER_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TARGET] = JsonConstants::NOT_NUMBER_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_REQ_VERSION] = JsonConstants::NOT_OBJECT_TYPE;
    typeErrorProps[BUNDLE_DEVICE_CONFIG_PROFILE_KEY_FLAG] = JsonConstants::NOT_STRING_TYPE;
    typeErrorProps[BUNDLE_MODULE_PROFILE_KEY_MODE] = JsonConstants::NOT_STRING_TYPE;
}

void BmsBundleParserTest::CheckNoPropProfileParseApp(const std::string &propKey, const ErrCode expectCode) const
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json errorProfileJson = CONFIG_JSON;
    errorProfileJson[BUNDLE_PROFILE_KEY_APP].erase(propKey);
    profileFileBuffer << errorProfileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, expectCode);
}

void BmsBundleParserTest::CheckNoPropProfileParseDeviceConfig(
    const std::string &propKey, const ErrCode expectCode) const
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json errorProfileJson = CONFIG_JSON;
    errorProfileJson[BUNDLE_PROFILE_KEY_DEVICE_CONFIG].erase(propKey);
    profileFileBuffer << errorProfileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, expectCode);
}

void BmsBundleParserTest::CheckNoPropProfileParseModule(const std::string &propKey, const ErrCode expectCode) const
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json errorProfileJson = CONFIG_JSON;
    errorProfileJson[BUNDLE_PROFILE_KEY_MODULE].erase(propKey);
    profileFileBuffer << errorProfileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, expectCode);
}

void BmsBundleParserTest::CheckProfilePermission(const nlohmann::json &checkedProfileJson) const
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    profileFileBuffer << checkedProfileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

void BmsBundleParserTest::CheckProfileForms(const nlohmann::json &checkedProfileJson) const
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    profileFileBuffer << checkedProfileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP) << profileFileBuffer.str();
}

void BmsBundleParserTest::CheckProfileShortcut(const nlohmann::json &checkedProfileJson, const ErrCode expectCode) const
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    profileFileBuffer << checkedProfileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, expectCode) << profileFileBuffer.str();
}

void BmsBundleParserTest::CheckProfileModule(const nlohmann::json &checkedProfileJson, const ErrCode code) const
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->isPreInstallApp = true;
    std::ostringstream profileFileBuffer;

    profileFileBuffer << checkedProfileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, code) << profileFileBuffer.str();
}

ErrCode BmsBundleParserTest::CheckProfileDefaultPermission(const nlohmann::json &checkedProfileJson,
    std::set<DefaultPermission> &defaultPermissions) const
{
    DefaultPermissionProfile profile;
    std::ostringstream profileFileBuffer;
    profileFileBuffer << checkedProfileJson.dump();
    nlohmann::json jsonObject =  nlohmann::json::parse(profileFileBuffer.str(), nullptr, false);
    if (jsonObject.is_discarded()) {
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }

    return profile.TransformTo(jsonObject, defaultPermissions);
}

/**
 * @tc.number: TestParse_0200
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parse bundle failed when file is not exist by the input pathName
 */
HWTEST_F(BmsBundleParserTest, TestParse_0200, Function | SmallTest | Level0)
{
    BundleParser bundleParser;
    InnerBundleInfo innerBundleInfo;
    pathStream_ << RESOURCE_ROOT_PATH << UNKOWN_PATH << INSTALL_FILE_SUFFIX;
    ErrCode result = bundleParser.Parse(pathStream_.str(), innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: TestParse_0600
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parse bundle failed when prop(APP_notMustPropKeys) is not exist in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_0600, Function | SmallTest | Level0)
{
    std::vector<std::string> notMustPropKeys = {
        PROFILE_KEY_DESCRIPTION,
        PROFILE_KEY_LABEL,
        // sub BUNDLE_APP_PROFILE_KEY_API_VERSION
        BUNDLE_APP_PROFILE_KEY_VENDOR,
        BUNDLE_APP_PROFILE_KEY_TARGET,
        BUNDLE_APP_PROFILE_KEY_RELEASE_TYPE,
    };

    for (const auto &propKey : notMustPropKeys) {
        APP_LOGD("test not must prop %{public}s not exist", propKey.c_str());
        CheckNoPropProfileParseApp(propKey, ERR_OK);
    }
}

/**
 * @tc.number: TestParse_0700
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parse bundle failed when prop(deviceConfig_notMustPropKeys) is not exist in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_0700, Function | SmallTest | Level0)
{
    std::vector<std::string> notMustPropKeys = {
        PROFILE_KEY_DESCRIPTION,
        PROFILE_KEY_LABEL,
        // sub BUNDLE_PROFILE_KEY_DEVICE_CONFIG
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_PHONE,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TABLET,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TV,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_CAR,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_WEARABLE,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_LITE_WEARABLE,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SMART_VISION,
        // sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DEFAULT
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_PROCESS,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DIRECT_LAUNCH,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SUPPORT_BACKUP,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_COMPRESS_NATIVE_LIBS,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_NETWORK,
        // sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_NETWORK
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_USES_CLEAR_TEXT,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SECURITY_CONFIG,
        // sub BUNDLE_DEVICE_CONFIG_PROFILE_KEY_SECURITY_CONFIG
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_DOMAIN_SETTINGS,
    };

    for (const auto &propKey : notMustPropKeys) {
        APP_LOGD("test not must prop %{public}s not exist", propKey.c_str());
        CheckNoPropProfileParseDeviceConfig(propKey, ERR_OK);
    }
}

/**
 * @tc.number: TestParse_0800
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parse bundle failed when prop(module_notMustPropKeys) is not exist in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_0800, Function | SmallTest | Level0)
{
    std::vector<std::string> notMustPropKeys = {
        PROFILE_KEY_DESCRIPTION,
        PROFILE_KEY_LABEL,
        // sub BUNDLE_PROFILE_KEY_MODULE
        BUNDLE_MODULE_PROFILE_KEY_SUPPORTED_MODES,
        BUNDLE_MODULE_PROFILE_KEY_ABILITIES,
        BUNDLE_MODULE_PROFILE_KEY_JS,
        BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS,
        BUNDLE_MODULE_PROFILE_KEY_DEFINE_PERMISSIONS,
        BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS,
        BUNDLE_MODULE_PROFILE_KEY_COLOR_MODE,
        // sub BUNDLE_MODULE_PROFILE_KEY_ABILITIES
        BUNDLE_MODULE_PROFILE_KEY_PROCESS,
        BUNDLE_MODULE_PROFILE_KEY_ICON,
        BUNDLE_MODULE_PROFILE_KEY_URI,
        BUNDLE_MODULE_PROFILE_KEY_LAUNCH_TYPE,
        BUNDLE_MODULE_PROFILE_KEY_VISIBLE,
        BUNDLE_MODULE_PROFILE_KEY_PERMISSIONS,
        BUNDLE_MODULE_PROFILE_KEY_SKILLS,
        BUNDLE_MODULE_PROFILE_KEY_DEVICE_CAP_ABILITY,
        BUNDLE_MODULE_PROFILE_KEY_ORIENTATION,
        BUNDLE_MODULE_PROFILE_KEY_BACKGROUND_MODES,
        BUNDLE_MODULE_PROFILE_KEY_READ_PERMISSION,
        BUNDLE_MODULE_PROFILE_KEY_WRITE_PERMISSION,
        BUNDLE_MODULE_PROFILE_KEY_DIRECT_LAUNCH,
        BUNDLE_MODULE_PROFILE_KEY_CONFIG_CHANGES,
        BUNDLE_MODULE_PROFILE_KEY_MISSION,
        BUNDLE_MODULE_PROFILE_KEY_TARGET_ABILITY,
        BUNDLE_MODULE_PROFILE_KEY_MULTIUSER_SHARED,
        BUNDLE_MODULE_PROFILE_KEY_SUPPORT_PIP_MODE,
        // sub BUNDLE_MODULE_PROFILE_KEY_JS
        BUNDLE_MODULE_PROFILE_KEY_WINDOW,
        // sub BUNDLE_MODULE_PROFILE_KEY_WINDOW
        BUNDLE_MODULE_PROFILE_KEY_DESIGN_WIDTH,
        BUNDLE_MODULE_PROFILE_KEY_AUTO_DESIGN_WIDTH,
        // sub BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS
        BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_WANTS,
        // sub BUNDLE_MODULE_PROFILE_KEY_SHORTCUT_WANTS
        BUNDLE_MODULE_PROFILE_KEY_TARGET_CLASS,
        BUNDLE_MODULE_PROFILE_KEY_TARGET_BUNDLE,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_COMPATIBLE,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_TARGET,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_REQ_VERSION,
        BUNDLE_DEVICE_CONFIG_PROFILE_KEY_FLAG,
        BUNDLE_MODULE_PROFILE_KEY_MODE,
        BUNDLE_MODULE_PROFILE_KEY_PATH,
    };

    for (const auto &propKey : notMustPropKeys) {
        APP_LOGD("test not must prop %{public}s not exist", propKey.c_str());
        CheckNoPropProfileParseModule(propKey, ERR_OK);
    }
}

/**
 * @tc.number: TestParse_0900
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parse bundle failed when prop(configJson.app.bundleName) is not exist in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_0900, Function | SmallTest | Level0)
{
    std::vector<std::string> mustPropKeys = {
        BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME,
    };

    for (const auto &propKey : mustPropKeys) {
        APP_LOGD("test must prop %{public}s not exist", propKey.c_str());
        CheckNoPropProfileParseApp(propKey, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
    }
}

/**
 * @tc.number: TestParse_1000
 * @tc.name: parse bundle deviceType by config.json
 * @tc.desc: 1. system running normally
 *           2. test parse bundle failed when prop(configJson.module.deviceType) is not exist in the
 *              config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_1000, Function | SmallTest | Level0)
{
    std::vector<std::string> mustPropKeys = {
        BUNDLE_MODULE_PROFILE_KEY_DEVICE_TYPE,
    };

    for (const auto &propKey : mustPropKeys) {
        APP_LOGD("test must prop %{public}s not exist", propKey.c_str());
        CheckNoPropProfileParseModule(propKey, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
    }
}

/**
 * @tc.number: TestParse_1100
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parse bundle failed when prop(configJson.module.package,distro.moduleName) is not exist in the
 *           config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_1100, Function | SmallTest | Level0)
{
    std::vector<std::string> mustPropKeys = {
        BUNDLE_MODULE_PROFILE_KEY_PACKAGE,
        BUNDLE_MODULE_PROFILE_KEY_DISTRO,
    };

    for (const auto &propKey : mustPropKeys) {
        APP_LOGD("test must prop %{public}s not exist", propKey.c_str());
        CheckNoPropProfileParseModule(propKey, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);
    }
}

/**
 * @tc.number: TestParse_1200
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parse bundle failed when prop(module.abilities.name) is not exist in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_1200, Function | SmallTest | Level0)
{
    std::vector<std::string> mustPropKeys = {
        PROFILE_KEY_NAME,
    };

    for (const auto &propKey : mustPropKeys) {
        APP_LOGD("test must prop %{public}s not exist", propKey.c_str());
        CheckNoPropProfileParseModule(propKey, ERR_OK);
    }
}

/**
 * @tc.number: TestParse_1600
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when an ability packet with an incorrect type in the file path
 */
HWTEST_F(BmsBundleParserTest, TestParse_1600, Function | SmallTest | Level0)
{
    BundleParser bundleParser;
    InnerBundleInfo innerBundleInfo;
    pathStream_ << RESOURCE_ROOT_PATH << "demo.error_type";
    ErrCode result = bundleParser.Parse(pathStream_.str(), innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_UNEXPECTED);

    pathStream_.str("");
    pathStream_ << RESOURCE_ROOT_PATH << "demo.";
    result = bundleParser.Parse(pathStream_.str(), innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_UNEXPECTED);

    pathStream_.str("");
    pathStream_ << RESOURCE_ROOT_PATH << "bundle_suffix_test.BUNDLE";
    result = bundleParser.Parse(pathStream_.str(), innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: TestParse_1700
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when an bundle packet with a deep file path depth
 */
HWTEST_F(BmsBundleParserTest, TestParse_1700, Function | SmallTest | Level1)
{
    BundleParser bundleParser;
    InnerBundleInfo innerBundleInfo;
    pathStream_ << RESOURCE_ROOT_PATH;
    int maxDeep = 100;
    for (int i = 0; i < maxDeep; i++) {
        pathStream_ << "test/";
    }
    pathStream_ << NEW_APP << INSTALL_FILE_SUFFIX;
    ErrCode result = bundleParser.Parse(pathStream_.str(), innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_UNEXPECTED) << pathStream_.str();
}

/**
 * @tc.number: TestParse_1800
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when an bundle packet with a long path
 */
HWTEST_F(BmsBundleParserTest, TestParse_1800, Function | SmallTest | Level1)
{
    BundleParser bundleParser;
    InnerBundleInfo innerBundleInfo;
    pathStream_ << RESOURCE_ROOT_PATH;
    int maxLength = 256;
    for (int i = 0; i < maxLength; i++) {
        pathStream_ << "test/";
    }
    pathStream_ << NEW_APP << INSTALL_FILE_SUFFIX;
    ErrCode result = bundleParser.Parse(pathStream_.str(), innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: TestParse_1900
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when an bundle packet with special character in the file path
 */
HWTEST_F(BmsBundleParserTest, TestParse_1900, Function | SmallTest | Level1)
{
    BundleParser bundleParser;
    InnerBundleInfo innerBundleInfo;
    pathStream_ << RESOURCE_ROOT_PATH;
    std::string specialChars = "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-";
    pathStream_ << specialChars << "new" << INSTALL_FILE_SUFFIX;
    ErrCode result = bundleParser.Parse(pathStream_.str(), innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: TestParse_2000
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when def-permission prop has error in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_2000, Function | SmallTest | Level1)
{
    nlohmann::json errorDefPermJson = CONFIG_JSON;
    errorDefPermJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_DEFINE_PERMISSIONS] = R"(
        [{
            "name": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
            "reason": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
            "when": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-"
        }]
    )"_json;
    CheckProfilePermission(errorDefPermJson);
}

/**
 * @tc.number: TestParse_2100
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when req-permission prop has error in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_2100, Function | SmallTest | Level1)
{
    nlohmann::json errorReqPermJson = CONFIG_JSON;
    errorReqPermJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS] = R"(
        [{
            "reason": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
            "when": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-"
        }]
    )"_json;
    CheckProfilePermission(errorReqPermJson);
}

/**
 * @tc.number: TestParse_2200
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when def-permission prop has empty in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_2200, Function | SmallTest | Level1)
{
    nlohmann::json errorDefPermJson = CONFIG_JSON;
    errorDefPermJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_DEFINE_PERMISSIONS] = R"(
        [{

        }]
    )"_json;
    CheckProfilePermission(errorDefPermJson);
}

/**
 * @tc.number: TestParse_2300
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when req-permission prop has empty in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_2300, Function | SmallTest | Level1)
{
    nlohmann::json errorReqPermJson = CONFIG_JSON;
    errorReqPermJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_REQ_PERMISSIONS] = R"(
        [{

        }]
    )"_json;
    CheckProfilePermission(errorReqPermJson);
}

/**
 * @tc.number: TestParse_2400
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when forms prop has error in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_2400, Function | SmallTest | Level1)
{
    nlohmann::json errorFormsJson = CONFIG_JSON;
    errorFormsJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_ABILITIES]= R"(
    [{
        "skills": [
          {
            "entities": [
              "entity.system.home",
              "flag.home.intent.from.system"
            ],
            "actions": [
              "action.system.home"
            ]
          }
        ],
        "forms": [
            {
                "description": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "type": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "colorMode": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "isDefault": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "updateEnabled": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "scheduledUpdateTime": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "updateDuration": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "defaultDimension": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "supportDimensions": [
                    "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                    "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-"
                ],
                "jsComponentName": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "deepLink": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "metaData": {
                    "customizeData": [
                        {
                            "name": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                            "value": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-"
                        }
                    ]
                }
            }
        ],
        "name": "com.example.napi_test_suite.MainAbility",
        "icon": "$media:icon",
        "description": "$string:mainability_description",
        "label": "MyApplication11",
        "type": "page",
        "launchType": "standard"
    }]

    )"_json;
    CheckProfileForms(errorFormsJson);
}

/**
 * @tc.number: TestParse_2500
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when forms prop has empty in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_2500, Function | SmallTest | Level1)
{
    nlohmann::json errorFormsJson = CONFIG_JSON;
    errorFormsJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_ABILITIES] = R"(
        [{
        "skills": [
          {
            "entities": [
              "entity.system.home",
              "flag.home.intent.from.system"
            ],
            "actions": [
              "action.system.home"
            ]
          }
        ],
        "forms": [{
                 }],
        "name": "com.example.napi_test_suite.MainAbility",
        "icon": "$media:icon",
        "description": "$string:mainability_description",
        "label": "MyApplication11",
        "type": "page",
        "launchType": "standard"
        }]
    )"_json;
    CheckProfileForms(errorFormsJson);
}

/**
 * @tc.number: TestParse_2600
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when shortcuts prop has empty in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_2600, Function | SmallTest | Level1)
{
    nlohmann::json errorShortcutJson = CONFIG_JSON;
    errorShortcutJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS] = R"(
        [{

        }]
    )"_json;
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestParse_2700
 * @tc.name: parse bundle package by config.json
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when shortcuts prop has error in the config.json
 */
HWTEST_F(BmsBundleParserTest, TestParse_2700, Function | SmallTest | Level1)
{
    nlohmann::json errorShortcutJson = CONFIG_JSON;
    errorShortcutJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_SHORTCUTS] = R"(
        [{
            "label": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
            "icon": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
            "intents": [
              {
                "targetBundle": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-",
                "targetClass": "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-"
              }
            ]
        }]
    )"_json;
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.name: TestParse_2800
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when forms prop has empty in the config.json
 * @tc.type: FUNC
 * @tc.require: issueI5MZ3F
 */
HWTEST_F(BmsBundleParserTest, TestParse_2800, Function | SmallTest | Level1)
{
    nlohmann::json formsJson = CONFIG_JSON;

    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    profileFileBuffer << formsJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
    innerBundleInfo.GetFormsInfoByApp(formInfos);
    int newSupportDimension = 5;
    EXPECT_EQ(formInfos[0].supportDimensions[0], newSupportDimension);
}

/**
 * @tc.name: TestParse_2900
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when forms prop has empty in the config.json
 * @tc.type: FUNC
 * @tc.require: issueI5MZ3F
 */
HWTEST_F(BmsBundleParserTest, TestParse_2900, Function | SmallTest | Level1)
{
    nlohmann::json errorShortcutJson = CONFIG_JSON;
    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "xxx";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = OVER_MAX_PATH_SIZE;
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "bundleName&";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "bundleName/";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "bundleName?";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "bundleName]";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "bundleName`";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "bundleName|";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);
}

/**
 * @tc.name: TestParse_3000
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when forms prop has empty in the config.json
 * @tc.type: FUNC
 * @tc.require: issueI5MZ3F
 */
HWTEST_F(BmsBundleParserTest, TestParse_3000, Function | SmallTest | Level1)
{
    nlohmann::json errorShortcutJson = CONFIG_JSON;
    errorShortcutJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_PACKAGE] = "";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_DISTRO][
        BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME] = "com../hiworld../";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_DISTRO][
        BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME] = "";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    errorShortcutJson[BUNDLE_PROFILE_KEY_MODULE][BUNDLE_MODULE_PROFILE_KEY_DEVICE_TYPE] = "";
    CheckProfileShortcut(errorShortcutJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.name: TestParse_3100
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3100, Function | SmallTest | Level1)
{
    nlohmann::json moduleJson = MODULE_JSON;
    CheckProfileModule(moduleJson, ERR_OK);

    moduleJson[BUNDLE_PROFILE_KEY_MODULE][PROFILE_KEY_NAME] = "";
    CheckProfileModule(moduleJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    moduleJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "";
    CheckProfileModule(moduleJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    moduleJson[BUNDLE_PROFILE_KEY_MODULE][PROFILE_KEY_NAME] = "../entry";
    moduleJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "com.ex";
    CheckProfileModule(moduleJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    moduleJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] =
        "doe8m8mMt2DicXm3fZ7Nz0xaVaw4R2in5Gm1gJVvzRKmh3SM7Jf5gmkaDGFzRsriDtLRioSvg07wokZtmUDE4XKplv6pIMqF5aVIdaff";
    CheckProfileModule(moduleJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    moduleJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "1com.example.backuptest";
    moduleJson[BUNDLE_PROFILE_KEY_MODULE][PROFILE_KEY_NAME] = "entry";
    CheckProfileModule(moduleJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);

    moduleJson[BUNDLE_PROFILE_KEY_APP][BUNDLE_APP_PROFILE_KEY_BUNDLE_NAME] = "com.example/.backuptest";
    CheckProfileModule(moduleJson, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);
}

/**
 * @tc.name: TestParse_3200
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3200, Function | SmallTest | Level1)
{
    nlohmann::json formsJson = R"({
        "app": {
            "bundleName": "com.example.backuptest",
            "debug": true,
            "icon": "$media:app_icon",
            "iconId": 16777220,
            "label": "$string:app_name",
            "labelId": 16777216,
            "minAPIVersion": 9,
            "targetAPIVersion": 9,
            "vendor": "example",
            "versionCode": 1000000,
            "versionName": "1.0.0"
        },
        "module": {
            "name": "entry",
            "installationFree": false,
            "mainElement": "MainAbility",
            "pages": "$profile:main_pages",
            "srcEntrance": "./ets/Application/AbilityStage.ts",
            "type": "entry",
            "virtualMachine": "ark0.0.0.3"
        }
    }
    )"_json;
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    profileFileBuffer << formsJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_3300
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3300, Function | SmallTest | Level1)
{
    nlohmann::json formsJson = R"({
        "app": {
            "bundleName": "com.example.backuptest",
            "debug": true,
            "icon": "$media:app_icon",
            "iconId": 16777220,
            "label": "$string:app_name",
            "labelId": 16777216,
            "minAPIVersion": 9,
            "targetAPIVersion": 9,
            "vendor": "example",
            "versionCode": 1000000,
            "versionName": "1.0.0"
        },
        "module": {
            "deliveryWithInstall": true,
            "description": "$string:entry_desc",
            "descriptionId": 16777219,
            "deviceTypes": [
                "default"
            ],
            "abilities": [
                {
                    "description": "$string:MainAbility_desc",
                    "descriptionId": 16777217,
                    "icon": "$media:icon",
                    "iconId": 16777221,
                    "label": "$string:MainAbility_label",
                    "labelId": 16777218,
                    "name": "MainAbility",
                    "launchType": "unknowlaunchType",
                    "orientation": "unknoworientation",
                    "skills": [
                        {
                            "actions": [
                                "action.thirdparty.home"
                            ],
                            "entities": [
                                "entity.system.home",
                                "flag.home.intent.from.system"
                            ]
                        }
                    ],
                    "srcEntrance": "./ets/MainAbility/MainAbility.ts",
                    "visible": true
                }
            ],
            "name": "entry",
            "installationFree": false,
            "mainElement": "MainAbility",
            "pages": "$profile:main_pages",
            "srcEntrance": "./ets/Application/AbilityStage.ts",
            "type": "entry",
            "virtualMachine": "ark0.0.0.3"
        }
    }
    )"_json;
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    profileFileBuffer << formsJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.number: TestExtractByName_0100
 * @tc.name: extract file stream by file name from package
 * @tc.desc: 1. system running normally
 *           2. test extract file from is not exist bundle or ability package
 */
HWTEST_F(BmsBundleParserTest, TestExtractByName_0100, Function | SmallTest | Level0)
{
    pathStream_ << RESOURCE_ROOT_PATH << UNKOWN_PATH << INSTALL_FILE_SUFFIX;
    std::string fileInBundle = "";
    std::ostringstream fileBuffer;

    BundleExtractor bundleExtractor(pathStream_.str());
    bool result = bundleExtractor.ExtractByName(fileInBundle, fileBuffer);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: TestExtractByName_0200
 * @tc.name: extract file stream by file name from package
 * @tc.desc: 1. system running normally
 *           2. test extract is not exist file from bundle or ability package
 */
HWTEST_F(BmsBundleParserTest, TestExtractByName_0200, Function | SmallTest | Level0)
{
    pathStream_ << RESOURCE_ROOT_PATH << NEW_APP << INSTALL_FILE_SUFFIX;
    std::string fileInBundle = "unknown";
    std::ostringstream fileBuffer;

    BundleExtractor bundleExtractor(pathStream_.str());
    bool result = bundleExtractor.ExtractByName(fileInBundle, fileBuffer);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: TestExtractByName_0300
 * @tc.name: extract file stream by file name from package
 * @tc.desc: 1. system running normally
 *           2. test failed to extract files from a package with a deep file path depth
 */
HWTEST_F(BmsBundleParserTest, TestExtractByName_0300, Function | SmallTest | Level1)
{
    pathStream_ << RESOURCE_ROOT_PATH;
    int maxDeep = 100;
    for (int i = 0; i < maxDeep; i++) {
        pathStream_ << "test/";
    }
    pathStream_ << BUNDLE_TYPE_APP << INSTALL_FILE_SUFFIX;

    std::string fileInBundle = "config.json";
    std::ostringstream fileBuffer;

    BundleExtractor bundleExtractor(pathStream_.str());
    bool result = bundleExtractor.ExtractByName(fileInBundle, fileBuffer);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: TestExtractByName_0400
 * @tc.name: extract file stream by file name from package
 * @tc.desc: 1. system running normally
 *           2. test failed to extract files from a file with a long path
 */
HWTEST_F(BmsBundleParserTest, TestExtractByName_0400, Function | SmallTest | Level1)
{
    pathStream_ << RESOURCE_ROOT_PATH;
    int maxLength = 256;
    for (int i = 0; i < maxLength; i++) {
        pathStream_ << "test";
    }
    pathStream_ << "new" << INSTALL_FILE_SUFFIX;

    std::string fileInBundle = "config.json";
    std::ostringstream fileBuffer;

    BundleExtractor bundleExtractor(pathStream_.str());
    bool result = bundleExtractor.ExtractByName(fileInBundle, fileBuffer);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: TestExtractByName_0500
 * @tc.name: extract file stream by file name from package
 * @tc.desc: 1. system running normally
 *           2. test failed to extract files from a package with special character in the file path
 */
HWTEST_F(BmsBundleParserTest, TestExtractByName_0500, Function | SmallTest | Level1)
{
    pathStream_ << RESOURCE_ROOT_PATH;
    std::string specialChars = "~!@#$%^&*(){}[]:;'?<>,.|`/./+_-";
    pathStream_ << specialChars << "new" << INSTALL_FILE_SUFFIX;

    std::string fileInBundle = "config.json";
    std::ostringstream fileBuffer;

    BundleExtractor bundleExtractor(pathStream_.str());
    bool result = bundleExtractor.ExtractByName(fileInBundle, fileBuffer);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: TestDefaultPermissionProfile_0100
 * @tc.name: test default permission profile
 * @tc.desc: 1. system running normally
 *           2. test success
 */
HWTEST_F(BmsBundleParserTest, TestDefaultPermissionProfile_0100, Function | SmallTest | Level1)
{
    std::set<DefaultPermission> defaultPermissions;
    nlohmann::json profileJson = R"(
        [
            {
                "bundleName": "com.ohos.test"
            }
        ]
        )"_json;
    ErrCode result = CheckProfileDefaultPermission(profileJson, defaultPermissions);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(defaultPermissions.size(), ONE);
}

/**
 * @tc.number: TestDefaultPermissionProfile_0200
 * @tc.name: test default permission profile
 * @tc.desc: 1. system running normally
 *           2. test success
 */
HWTEST_F(BmsBundleParserTest, TestDefaultPermissionProfile_0200, Function | SmallTest | Level1)
{
    std::set<DefaultPermission> defaultPermissions;
    nlohmann::json profileJson = R"(
        [
            {
                "bundleName": "com.ohos.test1",
                "permissions":[
                    {
                        "name": "ohos.permission.test1",
                        "userCancellable":true
                    },
                    {
                        "name": "ohos.permission.test2",
                        "userCancellable":false
                    }
                ]
            }
        ]
        )"_json;
    ErrCode result = CheckProfileDefaultPermission(profileJson, defaultPermissions);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(defaultPermissions.size(), ONE);
    if (defaultPermissions.size() == ONE) {
        auto defaultPermission = *defaultPermissions.begin();
        EXPECT_EQ(defaultPermission.bundleName, BUNDLE_NAME1);
        EXPECT_EQ(defaultPermission.grantPermission[0].name, BUNDLE_PERMISSION_NAME1);
        EXPECT_TRUE(defaultPermission.grantPermission[0].userCancellable);
        EXPECT_EQ(defaultPermission.grantPermission[1].name, BUNDLE_PERMISSION_NAME2);
        EXPECT_FALSE(defaultPermission.grantPermission[1].userCancellable);
    }
}

/**
 * @tc.number: TestDefaultPermissionProfile_0300
 * @tc.name: test default permission profile
 * @tc.desc: 1. system running normally
 *           2. test success
 */
HWTEST_F(BmsBundleParserTest, TestDefaultPermissionProfile_0300, Function | SmallTest | Level1)
{
    std::set<DefaultPermission> defaultPermissions;
    nlohmann::json profileJson = R"(
        [
            {
                "bundleName": "com.ohos.test1",
                "permissions":[
                    {
                        "name": "ohos.permission.test1",
                        "userCancellable":true
                    },
                    {
                        "name": "ohos.permission.test2",
                        "userCancellable":false
                    }
                ]
            },
            {
                "bundleName": "com.ohos.test2",
                "permissions":[
                    {
                        "name": "ohos.permission.test1",
                        "userCancellable":true
                    },
                    {
                        "name": "ohos.permission.test2",
                        "userCancellable":false
                    }
                ]
            }
        ]
        )"_json;
    ErrCode result = CheckProfileDefaultPermission(profileJson, defaultPermissions);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(defaultPermissions.size(), TWO);
    if (defaultPermissions.size() == TWO) {
        DefaultPermission firstDefaultPermission;
        firstDefaultPermission.bundleName = BUNDLE_NAME1;
        auto firstDefaultPermissionIter = defaultPermissions.find(firstDefaultPermission);
        EXPECT_TRUE(firstDefaultPermissionIter != defaultPermissions.end());
        firstDefaultPermission = *firstDefaultPermissionIter;
        EXPECT_EQ(firstDefaultPermission.grantPermission[0].name, BUNDLE_PERMISSION_NAME1);
        EXPECT_TRUE(firstDefaultPermission.grantPermission[0].userCancellable);
        EXPECT_EQ(firstDefaultPermission.grantPermission[1].name, BUNDLE_PERMISSION_NAME2);
        EXPECT_FALSE(firstDefaultPermission.grantPermission[1].userCancellable);
        DefaultPermission secondDefaultPermission;
        secondDefaultPermission.bundleName = "com.ohos.test2";
        EXPECT_TRUE(defaultPermissions.find(secondDefaultPermission) != defaultPermissions.end());
    }
}

/**
 * @tc.number: TestDefaultPermissionProfile_0400
 * @tc.name: test default permission profile
 * @tc.desc: 1. system running normally
 *           2. test failed
 */
HWTEST_F(BmsBundleParserTest, TestDefaultPermissionProfile_0400, Function | SmallTest | Level1)
{
    std::set<DefaultPermission> defaultPermissions;
    nlohmann::json errorProfileJson = R"(
        [
            {
                "bundleName": "com.ohos.test",
                "permissions": [
                    {
                        "name": "ohos.permission.test1"
                    }
                ]
            }
        ]
        )"_json;
    ErrCode result = CheckProfileDefaultPermission(errorProfileJson, defaultPermissions);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.number: TestDefaultPermissionProfile_0500
 * @tc.name: test default permission profile
 * @tc.desc: 1. system running normally
 *           2. test failed
 */
HWTEST_F(BmsBundleParserTest, TestDefaultPermissionProfile_0500, Function | SmallTest | Level1)
{
    std::set<DefaultPermission> defaultPermissions;
    nlohmann::json errorProfileJson = R"(
        [
            {
            }
        ]
        )"_json;
    ErrCode result = CheckProfileDefaultPermission(errorProfileJson, defaultPermissions);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP);
}

/**
 * @tc.name: TestParse_3400
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3400, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_3500
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3500, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_3600
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3600, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[MODULE][TYPE] = PROFILE_KEY_LABEL_ID;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_3700
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3700, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[MODULE][TYPE] = PROFILE_KEY_LABEL_ID;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_3800
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3800, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_3;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_3900
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_3900, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_3;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4000
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4000, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_3;
    profileJson[MODULE][TYPE] = PROFILE_KEY_LABEL_ID;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4100
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4100, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_3;
    profileJson[MODULE][TYPE] = PROFILE_KEY_LABEL_ID;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4200
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4200, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[BUNDLE_TYPE_APP][PROFILE_KEY_LABEL_ID] = 0;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4300
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4300, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[BUNDLE_TYPE_APP][PROFILE_KEY_LABEL_ID] = 0;
    profileJson[BUNDLE_TYPE_APP][PROFILE_KEY_LABEL] = EMPTY_NAME;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4400
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4400, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[BUNDLE_TYPE_APP][PROFILE_KEY_LABEL] = EMPTY_NAME;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4500
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4500, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_2;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4600
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4600, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_2;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4700
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4700, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;
    nlohmann::json profileJson = CONFIG_JSON_2;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_DISTRO][
        BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE] = MODULE_TYPE_SHARED;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4800
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4800, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_2;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_DISTRO][
        BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE] = MODULE_TYPE_SHARED;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_4900
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_4900, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5000
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_5000, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5100
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_5100, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_DISTRO][
        BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE] = MODULE_TYPE_SHARED;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5200
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_5200, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_DISTRO][
        BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE] = MODULE_TYPE_SHARED;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5300
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_5300, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileJson[MODULE][NAME] = ServiceConstants::RELATIVE_PATH;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5400
 * @tc.desc: 1. system running normally
 *           2. test parsing succeed when deviceType is empty in the config.json
 * @tc.type: FUNC
 * @tc.require: issueI5MZ3F
 */
HWTEST_F(BmsBundleParserTest, TestParse_5400, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_DEVICE_TYPE].clear();
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5500
 * @tc.desc: 1. system running normally
 *           2. test parsing failed when version code is -1 in the config.json
 * @tc.type: FUNC
 * @tc.require: issueI5MZ3F
 */
HWTEST_F(BmsBundleParserTest, TestParse_5500, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileJson[BUNDLE_TYPE_APP][BUNDLE_APP_PROFILE_KEY_VERSION][BUNDLE_APP_PROFILE_KEY_CODE] = -1;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_NE(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5600
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_5600, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[BUNDLE_TYPE_APP][PROFILE_KEY_LABEL] = EMPTY_NAME;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5700
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_5700, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[MODULE][NAME] = EMPTY_NAME;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_NE(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5800
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_5800, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[MODULE][NAME] = OVER_MAX_PATH_SIZE;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_NE(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_5900
 * @tc.desc: 1. system running normally
 *           2. test ParserAtomicConfig failed invalid installationFree in module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_5900, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[BUNDLE_TYPE_APP][BUNDLETYPE] = BUNDLE_TYPE_APP;

    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6000
 * @tc.desc: 1. system running normally
 *           2. test ParserAtomicConfig split not exist
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6000, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;
    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[BUNDLE_TYPE_APP][BUNDLETYPE] = EMPTY_NAME;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE] = true;

    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6100
 * @tc.desc: 1. system running normally
 *           2. test ParserAtomicConfig
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6100, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE] = true;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6200
 * @tc.desc: 1. system running normally
 *           2. test ParserAtomicConfig
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6200, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE] = true;
    profileJson[MODULE][TYPE] = NO_EXIST_NAME;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6300
 * @tc.desc: 1. system running normally
 *           2. test ParserAtomicConfig
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6300, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6400
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6400, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_2;
    profileJson[MODULE][NAME] = NAME + ServiceConstants::MODULE_NAME_SEPARATOR;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_NE(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6500
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6500, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_4;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_NE(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6600
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6600, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;
    nlohmann::json profileJson = MODULE_JSON;

    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6700
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6700, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_DISTRO][MODULE_NAME] = ServiceConstants::RELATIVE_PATH;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6800
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the config.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6800, Function | SmallTest | Level1)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<FormInfo> formInfos;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = CONFIG_JSON_3;
    profileJson[MODULE][BUNDLE_MODULE_PROFILE_KEY_DISTRO][MODULE_NAME] = ServiceConstants::MODULE_NAME_SEPARATOR;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR) << profileFileBuffer.str();
}

/**
 * @tc.name: TestParse_6900
 * @tc.desc: 1. system running normally
 *           2. test parsing info in the module.json
 * @tc.type: FUNC
 */
HWTEST_F(BmsBundleParserTest, TestParse_6900, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;
    nlohmann::json profileJson = MODULE_JSON_5;

    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor(EMPTY_NAME);
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK) << profileFileBuffer.str();
}

/**
 * @tc.number: BundleParser_0100
 * @tc.name: Test ReadFileIntoJson
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0100, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string filePath;
    nlohmann::json jsonBuf;
    bool ret = bundleParser.ReadFileIntoJson(filePath, jsonBuf);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleParser_0200
 * @tc.name: Test ReadFileIntoJson
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0200, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string filePath = "config/sharefs/com.ohos.settings/appid";
    nlohmann::json jsonBuf;
    bool ret = bundleParser.ReadFileIntoJson(filePath, jsonBuf);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleParser_0300
 * @tc.name: Test ParsePackInfo
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0300, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string pathName = "com.ohos.settings";
    BundlePackInfo bundlePackInfo;
    ErrCode ret = bundleParser.ParsePackInfo(pathName, bundlePackInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: BundleParser_0400
 * @tc.name: Test ParseSysCap
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0400, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string pathName = "com.ohos.settings";
    std::vector<std::string> sysCaps;
    ErrCode ret = bundleParser.ParseSysCap(pathName, sysCaps);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: BundleParser_0500
 * @tc.name: Test ParsePreInstallConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0500, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile;
    std::set<PreScanInfo> scanInfos;
    ErrCode ret = bundleParser.ParsePreInstallConfig(configFile, scanInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_0600
 * @tc.name: Test ParsePreInstallConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0600, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile = "config.cfg";
    std::set<PreScanInfo> scanInfos;
    ErrCode ret = bundleParser.ParsePreInstallConfig(configFile, scanInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_0700
 * @tc.name: Test ParsePreUnInstallConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0700, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile;
    std::set<std::string> uninstallList;
    ErrCode ret = bundleParser.ParsePreUnInstallConfig(configFile, uninstallList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_0800
 * @tc.name: Test ParsePreUnInstallConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0800, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile = "config.cfg";
    std::set<std::string> uninstallList;
    ErrCode ret = bundleParser.ParsePreUnInstallConfig(configFile, uninstallList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_0900
 * @tc.name: Test ParsePreInstallAbilityConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_0900, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile;
    std::set<PreBundleConfigInfo> preBundleConfigInfos;
    ErrCode ret = bundleParser.ParsePreInstallAbilityConfig(configFile, preBundleConfigInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_1000
 * @tc.name: Test ParsePreInstallAbilityConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1000, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile = "config.cfg";
    std::set<PreBundleConfigInfo> preBundleConfigInfos;
    ErrCode ret = bundleParser.ParsePreInstallAbilityConfig(configFile, preBundleConfigInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_1100
 * @tc.name: Test ParseDefaultPermission
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1100, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string permissionFile;
    std::set<DefaultPermission> defaultPermissions;
    ErrCode ret = bundleParser.ParseDefaultPermission(permissionFile, defaultPermissions);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_1200
 * @tc.name: Test ParseDefaultPermission
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1200, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string permissionFile = "permission.file";
    std::set<DefaultPermission> defaultPermissions;
    ErrCode ret = bundleParser.ParseDefaultPermission(permissionFile, defaultPermissions);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_1300
 * @tc.name: Test ParseExtTypeConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1300, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile;
    std::set<std::string> extensionTypeList;
    ErrCode ret = bundleParser.ParseExtTypeConfig(configFile, extensionTypeList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_1400
 * @tc.name: Test ParseExtTypeConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1400, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile = "config.cfg";
    std::set<std::string> extensionTypeList;
    ErrCode ret = bundleParser.ParseExtTypeConfig(configFile, extensionTypeList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_1500
 * @tc.name: Test ParseRouterArray
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1500, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string jsonString;
    std::vector<RouterItem> routerArray;
    ErrCode ret = bundleParser.ParseRouterArray(jsonString, routerArray);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_NO_PROFILE);
}

/**
 * @tc.number: BundleParser_1600
 * @tc.name: Test ParseRouterArray
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1600, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string jsonString = "{\"Name\" : \"zhangsan\"}";
    std::vector<RouterItem> routerArray;
    ErrCode ret = bundleParser.ParseRouterArray(jsonString, routerArray);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: BundleParser_1700
 * @tc.name: Test ParseNoDisablingList
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1700, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configPath;
    std::vector<std::string> noDisablingList;
    ErrCode ret = bundleParser.ParseNoDisablingList(configPath, noDisablingList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);
}

/**
 * @tc.number: BundleParser_1800
 * @tc.name: Test ParseNoDisablingList
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1800, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configPath = "config.cfg";
    std::vector<std::string> noDisablingList;
    ErrCode ret = bundleParser.ParseNoDisablingList(configPath, noDisablingList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);
}

/**
 * @tc.number: BundleParser_1900
 * @tc.name: Test CheckRouterData
 * @tc.desc: Test the CheckRouterData of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_1900, Function | MediumTest | Level1)
{
    BundleParser bundleParser;
    nlohmann::json data;
    auto ret = bundleParser.CheckRouterData(data);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleParser_2000
 * @tc.name: Test ParseNoDisablingList
 * @tc.desc: Test the ParseNoDisablingList of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_2000, Function | MediumTest | Level1)
{
    BundleParser bundleParser;
    std::string configPath;
    std::vector<std::string> noDisablingList;
    ErrCode ret = bundleParser.ParseNoDisablingList(configPath, noDisablingList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);
}

/**
 * @tc.number: BundleParser_2100
 * @tc.name: Test CheckRouterData
 * @tc.desc: Test the CheckRouterData of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_2100, Function | MediumTest | Level1)
{
    BundleParser bundleParser;
    nlohmann::json data;
    data["data"] = "data";
    auto ret = bundleParser.CheckRouterData(data);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleParser_2200
 * @tc.name: Test ParsePreAppListConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_2200, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile;
    std::set<PreScanInfo> scanInfos;
    ErrCode ret = bundleParser.ParsePreAppListConfig(configFile, scanInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_2300
 * @tc.name: Test ParsePreAppListConfig
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_2300, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string configFile = "config.cfg";
    std::set<PreScanInfo> scanInfos;
    ErrCode ret = bundleParser.ParsePreAppListConfig(configFile, scanInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_FILE_FAILED);
}

/**
 * @tc.number: BundleParser_2400
 * @tc.name: Test ParseAclExtendedMap
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_2400, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string jsonString;
    std::map<std::string, std::string> aclExtendedMap = bundleParser.ParseAclExtendedMap(jsonString);
    EXPECT_EQ(aclExtendedMap.empty(), true);

    jsonString = R"({"name": "zhangsan")";
    aclExtendedMap = bundleParser.ParseAclExtendedMap(jsonString);
    EXPECT_EQ(aclExtendedMap.empty(), true);
}

/**
 * @tc.number: BundleParser_2500
 * @tc.name: Test ParseAclExtendedMap
 * @tc.desc: test the interface of BundleParser
 */
 HWTEST_F(BmsBundleParserTest, BundleParser_2500, Function | MediumTest | Level1)
 {
    BundleParser bundleParser;

    std::string jsonString = R"(["one", "two"])";
    std::map<std::string, std::string> aclExtendedMap = bundleParser.ParseAclExtendedMap(jsonString);
    EXPECT_EQ(aclExtendedMap.empty(), true);

    jsonString = "a";
    aclExtendedMap = bundleParser.ParseAclExtendedMap(jsonString);
    EXPECT_EQ(aclExtendedMap.empty(), true);
 }

/**
 * @tc.number: BundleParser_2600
 * @tc.name: Test ParseAclExtendedMap
 * @tc.desc: test the interface of BundleParser
 */
HWTEST_F(BmsBundleParserTest, BundleParser_2600, Function | MediumTest | Level1)
{
    BundleParser bundleParser;

    std::string jsonString = R"({"name": "zhangsan", "age": 18})";
    std::map<std::string, std::string> aclExtendedMap = bundleParser.ParseAclExtendedMap(jsonString);
    EXPECT_EQ(aclExtendedMap.size(), 2);

    for (auto it = aclExtendedMap.begin(); it != aclExtendedMap.end(); ++it) {
        if (it->first == "name") {
            EXPECT_EQ(it->second, "zhangsan");
        } else if (it->first == "age") {
            EXPECT_EQ(it->second, "18");
        }
    }
}
} // OHOS
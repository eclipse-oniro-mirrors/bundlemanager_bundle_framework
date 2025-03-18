/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { BundleInfo } from './BundleInfo';
import { AsyncCallback, BusinessError } from '@ohos.base';
import { ApplicationInfo } from './ApplicationInfo';

namespace bundleManager {

  loadLibrary("anibundlemanager.z");

  enum BundleFlag {
    GET_BUNDLE_INFO_DEFAULT = 0x00000000,
    GET_BUNDLE_INFO_WITH_APPLICATION = 0x00000001,
    GET_BUNDLE_INFO_WITH_HAP_MODULE = 0x00000002,
    GET_BUNDLE_INFO_WITH_ABILITY = 0x00000004,
    GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY = 0x00000008,
    GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION = 0x00000010,
    GET_BUNDLE_INFO_WITH_METADATA = 0x00000020,
    GET_BUNDLE_INFO_WITH_DISABLE = 0x00000040,
    GET_BUNDLE_INFO_WITH_SIGNATURE_INFO = 0x00000080,
    GET_BUNDLE_INFO_WITH_MENU = 0x00000100,
    GET_BUNDLE_INFO_WITH_ROUTER_MAP = 0x00000200,
    GET_BUNDLE_INFO_WITH_SKILL = 0x00000800,
    GET_BUNDLE_INFO_ONLY_WITH_LAUNCHER_ABILITY = 0x00001000,
    GET_BUNDLE_INFO_OF_ANY_USER = 0x00002000,
    GET_BUNDLE_INFO_EXCLUDE_CLONE = 0x00004000,
  }

  enum ApplicationFlag {
    GET_APPLICATION_INFO_DEFAULT = 0x00000000,
    GET_APPLICATION_INFO_WITH_PERMISSION = 0x00000001,
    GET_APPLICATION_INFO_WITH_METADATA = 0x00000002,
    GET_APPLICATION_INFO_WITH_DISABLE = 0x00000004
  }

  enum AbilityFlag {
    GET_ABILITY_INFO_DEFAULT = 0x00000000,
    GET_ABILITY_INFO_WITH_PERMISSION = 0x00000001,
    GET_ABILITY_INFO_WITH_APPLICATION = 0x00000002,
    GET_ABILITY_INFO_WITH_METADATA = 0x00000004,
    GET_ABILITY_INFO_WITH_DISABLE = 0x00000008,
    GET_ABILITY_INFO_ONLY_SYSTEM_APP = 0x00000010,
    GET_ABILITY_INFO_WITH_APP_LINKING = 0x00000040,
    GET_ABILITY_INFO_WITH_SKILL = 0x00000080,
  }

  enum ExtensionAbilityFlag {
    GET_EXTENSION_ABILITY_INFO_DEFAULT = 0x00000000,
    GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION = 0x00000001,
    GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION = 0x00000002,
    GET_EXTENSION_ABILITY_INFO_WITH_METADATA = 0x00000004,
    GET_EXTENSION_ABILITY_INFO_WITH_SKILL = 0x00000010,
  }

  export enum ExtensionAbilityType {
    FORM = 0,
    WORK_SCHEDULER = 1,
    INPUT_METHOD = 2,
    SERVICE = 3,
    ACCESSIBILITY = 4,
    DATA_SHARE = 5,
    FILE_SHARE = 6,
    STATIC_SUBSCRIBER = 7,
    WALLPAPER = 8,
    BACKUP = 9,
    WINDOW = 10,
    ENTERPRISE_ADMIN = 11,
    THUMBNAIL = 13,
    PREVIEW = 14,
    PRINT = 15,
    SHARE = 16,
    PUSH = 17,
    DRIVER = 18,
    ACTION = 19,
    ADS_SERVICE = 20,
    EMBEDDED_UI = 21,
    INSIGHT_INTENT_UI = 22,
    UNSPECIFIED = 255
  }

  export enum PermissionGrantState {
    PERMISSION_DENIED = -1,
    PERMISSION_GRANTED = 0
  }

  export enum SupportWindowMode {
    FULL_SCREEN = 0,
    SPLIT = 1,
    FLOATING = 2
  }

  export enum LaunchType {
    SINGLETON = 0,
    MULTITON = 1,
    SPECIFIED = 2
  }

  export enum AbilityType {
    PAGE = 1,
    SERVICE = 2,
    DATA = 3
  }

  export enum DisplayOrientation {
    UNSPECIFIED,
    LANDSCAPE,
    PORTRAIT,
    FOLLOW_RECENT,
    LANDSCAPE_INVERTED,
    PORTRAIT_INVERTED,
    AUTO_ROTATION,
    AUTO_ROTATION_LANDSCAPE,
    AUTO_ROTATION_PORTRAIT,
    AUTO_ROTATION_RESTRICTED,
    AUTO_ROTATION_LANDSCAPE_RESTRICTED,
    AUTO_ROTATION_PORTRAIT_RESTRICTED,
    LOCKED,
    AUTO_ROTATION_UNSPECIFIED,
    FOLLOW_DESKTOP
  }

  export enum ModuleType {
    ENTRY = 1,
    FEATURE = 2,
    SHARED = 3
  }

  export enum BundleType {
    APP = 0,
    ATOMIC_SERVICE = 1
  }

  export enum CompatiblePolicy {
    BACKWARD_COMPATIBILITY = 1
  }

  export enum ProfileType {
    INTENT_PROFILE = 1
  }

  export enum AppDistributionType {
    APP_GALLERY = 1,
    ENTERPRISE = 2,
    ENTERPRISE_NORMAL = 3,
    ENTERPRISE_MDM = 4,
    OS_INTEGRATION = 5,
    CROWDTESTING = 6,
    NONE = 7
  }

  export enum MultiAppModeType {
    UNSPECIFIED = 0,
    MULTI_INSTANCE = 1,
    APP_CLONE = 2,
  }

  export enum ApplicationInfoFlag {
    FLAG_INSTALLED = 0x00000001,
  }

  export native function isApplicationEnabledSync(bundleName: string): boolean;

  export native function getBundleInfoForSelfSync(bundleFlags: int): BundleInfo;

  export native function getBundleInfoSync(bundleName: string, bundleFlags: int, userId: int) : BundleInfo;

  export native function getApplicationInfoSync(bundleName: string, applicationFlags: int, userId: int): ApplicationInfo;

  export function getBundleInfoForSelf(bundleFlags: int, callback: AsyncCallback<BundleInfo, void>):void {
    let p1 = taskpool.execute(bundleManager.getBundleInfoForSelfSync, bundleFlags);
    p1.then((e: NullishType) => {
        let resultBundleInfo = e as BundleInfo;
        let r: BusinessError = { code: 0, name: "error", message: "error", data: undefined };
        callback(r, resultBundleInfo);
    }, (err: Object): void => {
    });
  }

  export function getBundleInfoForSelf(bundleFlags: int):Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: Object) => void) => {
        let p1 = taskpool.execute(bundleManager.getBundleInfoForSelfSync, bundleFlags);
        p1.then((e: NullishType) => {
            let resultBundleInfo = e as BundleInfo;
            resolve(resultBundleInfo);
        }, (err: Object): void => {
        });
    }
    );
    return p;
  }

  export function getBundleInfoSync(bundleName: string, bundleFlags: int): BundleInfo {
    return bundleManager.getBundleInfoSync(bundleName, bundleFlags, -500);
  }

  export function getBundleInfo(bundleName: string, bundleFlags: int, userId?: int): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: Object) => void) => {
        let userIdInfo: int = userId ?? -500;
        let execFun = (bundleName: string, bundleFlags: int, userId: int): BundleInfo => {
          return bundleManager.getBundleInfoSync(bundleName, bundleFlags, userId);
        };
        let p1 = taskpool.execute(execFun, bundleName, bundleFlags, userIdInfo);
        p1.then((e: NullishType) => {
            let resultBundleInfo = e as BundleInfo;
            resolve(resultBundleInfo);
        }, (err: Object): void => {
        });
    }
    );
    return p;
  }

  export function getBundleInfo(bundleName: string, bundleFlags: int, callback: AsyncCallback<BundleInfo, void>): void {
    let execFun = (bundleName: string, bundleFlags: int): BundleInfo => {
      return bundleManager.getBundleInfoSync(bundleName, bundleFlags);
    };
    let p1 = taskpool.execute(execFun, bundleName, bundleFlags);
    p1.then((e: NullishType) => {
        let resultBundleInfo = e as BundleInfo;
        let r: BusinessError = { code: 0, name: "error", message: "error", data: undefined };
        callback(r, resultBundleInfo);
    }, (err: Object): void => {
    });
  }

  export function getBundleInfo(bundleName: string, bundleFlags: int, userId: int, callback: AsyncCallback<BundleInfo, void>): void {
    let execFun = (bundleName: string, bundleFlags: int, userId: int): BundleInfo => {
      return bundleManager.getBundleInfoSync(bundleName, bundleFlags, userId);
    };
    let p1 = taskpool.execute(execFun, bundleName, bundleFlags, userId);
    p1.then((e: NullishType) => {
        let resultBundleInfo = e as BundleInfo;
        let r: BusinessError = { code: 0, name: "error", message: "error", data: undefined };
        callback(r, resultBundleInfo);
    }, (err: Object): void => {
    });
  }

  export function getApplicationInfoSync(bundleName: string, applicationFlags: int): ApplicationInfo {
    return bundleManager.getApplicationInfoSync(bundleName, applicationFlags, -500);
  }
}

export default bundleManager;

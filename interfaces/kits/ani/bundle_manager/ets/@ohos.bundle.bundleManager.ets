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

import { BundleInfo, AppCloneIdentity, SignatureInfo } from 'bundleManager.BundleInfo';
import { AsyncCallback, BusinessError } from '@ohos.base';
import { PreinstalledApplicationInfo, ApplicationInfo } from 'bundleManager.ApplicationInfo';
import { AbilityInfo } from 'bundleManager.AbilityInfo';
import { ExtensionAbilityInfo } from 'bundleManager.ExtensionAbilityInfo';
import { PermissionDef } from 'bundleManager.PermissionDef';
import { AppProvisionInfo } from 'bundleManager.AppProvisionInfo'
import Want from '@ohos.app.ability.Want';

namespace bundleManager {

  loadLibrary("ani_bundle_manager.z");

  const EMPTY_USER_ID: number = -500;

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
    FENCE = 24,
    ASSET_ACCELERATION = 26,
    FORM_EDIT = 27,
    DISTRIBUTED = 28,
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
    FLAG_OTHER_INSTALLED = 0x00000010,
    FLAG_PREINSTALLED_APP = 0x00000020,
    FLAG_PREINSTALLED_APP_UPDATE = 0x00000040,
  }

  export native function getBundleInfoForSelfNative(bundleFlags: number, isSync: boolean): BundleInfo;

  export native function getBundleInfoNative(bundleName: string, bundleFlags: number, userId: number, isSync: boolean) : BundleInfo;

  export native function getApplicationInfoNative(bundleName: string, applicationFlags: number, userId: number, isSync: boolean): ApplicationInfo;

  export native function getAllBundleInfoNative(bundleFlags: number, userId: number): Array<BundleInfo>;

  export native function getAllApplicationInfoNative(appFlags: number, userId: number): Array<ApplicationInfo>;

  export native function isApplicationEnabledNative(bundleName: string, appIndex: number, isSync: boolean): boolean;

  export native function queryAbilityInfoSyncNative(want: Want, abilityFlags: number, userId: number, isSync: boolean): Array<AbilityInfo>;

  export native function getAppCloneIdentityNative(uid: number): AppCloneIdentity;

  export native function getAbilityLabelNative(bundleName: string, moduleName: string, abilityName: string, isSync: boolean): string;

  export native function getLaunchWantForBundleNative(bundleName: string, userId: number, isSync: boolean): Want;

  export native function getAppCloneBundleInfoNative(bundleName: string, appIndex: number,
    bundleFlags: number, userId: number): BundleInfo;

  export native function getSpecifiedDistributionType(bundleName: string): string;

  export native function getBundleNameByUidNative(uid: number, isSync: boolean): string;

  export native function isAbilityEnabledNative(info: AbilityInfo, appIndex: number, isSync: boolean): boolean;

  export native function setAbilityEnabledNative(info: AbilityInfo, isEnabled: boolean, appIndex: number, isSync: boolean): void;

  export native function setApplicationEnabledNative(bundleName: string, isEnabled: boolean, appIndex: number, isSync: boolean): void;

  export native function getDynamicIconNative(bundleName: string): string;

  export native function queryAbilityInfoWithWantsNative(wants: Array<Want>, abilityFlags: number,
    userId: number): Array<AbilityInfo>;

  export native function queryExtensionAbilityInfoNative(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityTypeName: string, extensionAbilityFlags: number,
    userId: number, isExtensionTypeName: boolean, isSync: boolean): Array<ExtensionAbilityInfo>;

  export native function queryExAbilityInfoSyncWithoutWantNative(extensionAbilityType: string, extensionAbilityFlags: number,
    userId: number): Array<ExtensionAbilityInfo>;

  export native function enableDynamicIconNative(bundleName: string, moduleName: string): void;

  function getBundleInfoForSelfSync(bundleFlags: number): BundleInfo {
    return bundleManager.getBundleInfoForSelfNative(bundleFlags, true);
  }

  function getAbilityLabelSync(bundleName: string, moduleName: string, abilityName: string): string {
    return bundleManager.getAbilityLabelNative(bundleName, moduleName, abilityName, true);
  }

  function getBundleNameByUidSync(uid: number): string {
    return bundleManager.getBundleNameByUidNative(uid, true);
  }

  export native function getBundleArchiveInfoNative(hapFilePath: string, bundleFlags: number, isSync: boolean): BundleInfo;

  export native function getLaunchWant(): Want;

  export native function getProfileByAbilityNative(moduleName: string,
    abilityName: string, metadataName: string, isExtensionProfile: boolean, isSync: boolean): Array<string>;
  
  export native function getPermissionDefNative(permissionName: string, isSync: boolean): PermissionDef;

  export native function cleanBundleCacheFilesNative(bundleName: string, appIndex: number): void;

  export native function getAllBundleCacheSizeNative(): number;

  export native function cleanAllBundleCacheNative(): void;

  export native function getAppProvisionInfoNative(bundleName: string, userId: number, isSync: boolean): AppProvisionInfo;

  export native function canOpenLink(link: string): boolean;

  export native function getAllPreinstalledApplicationInfoNative(): Array<PreinstalledApplicationInfo>;

  export native function getAllBundleInfoByDeveloperId(developerId: string): Array<BundleInfo>;

  export native function switchUninstallState(bundleName: string, state: boolean): void;

  export native function getSignatureInfo(uid: number): SignatureInfo;

  export native function getAllAppCloneBundleInfoNative(bundleName: string,
    bundleFlags: number, userId: number): Array<BundleInfo>;
  
  function isApplicationEnabledSync(bundleName: string): boolean {
    return bundleManager.isApplicationEnabledNative(bundleName, 0, true);
  }

  function queryAbilityInfoSync(want: Want, abilityFlags: number, userId?: number): Array<AbilityInfo> {
    let userIdInfo: number = userId ?? EMPTY_USER_ID;
    return bundleManager.queryAbilityInfoSyncNative(want, abilityFlags, userIdInfo, true);
  }

  function getLaunchWantForBundleSync(bundleName: string, userId?: number): Want {
    let userIdInfo: number = userId ?? EMPTY_USER_ID;
    return bundleManager.getLaunchWantForBundleNative(bundleName, userIdInfo, true);
  }

  function isAbilityEnabledSync(info: AbilityInfo): boolean {
    return bundleManager.isAbilityEnabledNative(info, 0, true);
  }

  function setAbilityEnabledSync(info: AbilityInfo, isEnabled: boolean): void {
    return bundleManager.setAbilityEnabledNative(info, isEnabled, 0, true);
  }

  function setApplicationEnabledSync(bundleName: string, isEnabled: boolean): void {
    return bundleManager.setApplicationEnabledNative(bundleName, isEnabled, 0, true);
  }

  function queryExtensionAbilityInfoSync(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: number, userId?: number): Array<ExtensionAbilityInfo> {
    let userIdInfo: number = userId ?? EMPTY_USER_ID;
    return bundleManager.queryExtensionAbilityInfoNative(
      want, extensionAbilityType, "", extensionAbilityFlags, userIdInfo, false, true);
  }

  function queryExtensionAbilityInfoSync(want: Want, extensionAbilityType: string, extensionAbilityFlags: number,
    userId?: number): Array<ExtensionAbilityInfo> {
    let userIdInfo: number = userId ?? EMPTY_USER_ID;
    return bundleManager.queryExtensionAbilityInfoNative(
      want, ExtensionAbilityType.UNSPECIFIED, extensionAbilityType, extensionAbilityFlags, userIdInfo, true, true);
  }

  function queryExtensionAbilityInfoSync(extensionAbilityType: string, extensionAbilityFlags: number,
    userId?: number): Array<ExtensionAbilityInfo> {
    let userIdInfo: number = userId ?? EMPTY_USER_ID;
    return bundleManager.queryExAbilityInfoSyncWithoutWantNative(extensionAbilityType, extensionAbilityFlags, userIdInfo);
  }

  function getBundleArchiveInfoSync(hapFilePath: string, bundleFlags: number): BundleInfo {
    return bundleManager.getBundleArchiveInfoNative(hapFilePath, bundleFlags, true);
  }

  function getProfileByAbilitySync(moduleName: string, abilityName: string, metadataName?: string): Array<string> {
    let metadataNameInfo: string = metadataName ?? "";
    return bundleManager.getProfileByAbilityNative(moduleName, abilityName, metadataNameInfo, false, true);
  }

  function getProfileByExtensionAbilitySync(moduleName: string,
    extensionAbilityName: string, metadataName?: string): Array<string> {
    let metadataNameInfo: string = metadataName ?? "";
    return bundleManager.getProfileByAbilityNative(moduleName, extensionAbilityName, metadataNameInfo, true, true);
  }

  function getPermissionDefSync(permissionName: string): PermissionDef {
    return bundleManager.getPermissionDefNative(permissionName, true);
  }
  
  function getAppProvisionInfoSync(bundleName: string, userId?: number): AppProvisionInfo {
    let userIdInfo: number = userId ?? EMPTY_USER_ID;
    return bundleManager.getAppProvisionInfoNative(bundleName, userIdInfo, true);
  }

  function getBundleInfoForSelf(bundleFlags: number, callback: AsyncCallback<BundleInfo, void>):void {
    let execFun = (): BundleInfo => {
      return bundleManager.getBundleInfoForSelfNative(bundleFlags, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      callback(null, resultBundleInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundleInfoForSelf(bundleFlags: number):Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): BundleInfo => {
        return bundleManager.getBundleInfoForSelfNative(bundleFlags, false);
      };
      let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let resultBundleInfo: BundleInfo = e as BundleInfo;
          resolve(resultBundleInfo);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
    }
    );
    return p;
  }

  function getBundleInfoSync(bundleName: string, bundleFlags: number, userId: number): BundleInfo {
    return bundleManager.getBundleInfoNative(bundleName, bundleFlags, userId, true);
  }

  function getBundleInfoSync(bundleName: string, bundleFlags: number): BundleInfo {
    return bundleManager.getBundleInfoNative(bundleName, bundleFlags, EMPTY_USER_ID, true);
  }

  function getBundleInfo(bundleName: string, bundleFlags: number, userId?: number): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): BundleInfo => {
        return bundleManager.getBundleInfoNative(bundleName, bundleFlags, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultBundleInfo: BundleInfo = e as BundleInfo;
        resolve(resultBundleInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getBundleInfo(bundleName: string, bundleFlags: number, callback: AsyncCallback<BundleInfo>): void {
    let execFun = (): BundleInfo => {
      return bundleManager.getBundleInfoNative(bundleName, bundleFlags, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      callback(null, resultBundleInfo);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundleInfo(bundleName: string, bundleFlags: number, userId: number, callback: AsyncCallback<BundleInfo>): void {
    let execFun = (): BundleInfo => {
      return bundleManager.getBundleInfoNative(bundleName, bundleFlags, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      callback(null, resultBundleInfo);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getApplicationInfoSync(bundleName: string, applicationFlags: number): ApplicationInfo {
    return bundleManager.getApplicationInfoNative(bundleName, applicationFlags, EMPTY_USER_ID, true);
  }

  function getApplicationInfoSync(bundleName: string, applicationFlags: number, userId: number): ApplicationInfo {
    return bundleManager.getApplicationInfoNative(bundleName, applicationFlags, userId, true);
  }

  function getAllBundleInfo(bundleFlags: number, userId?: number): Promise<Array<BundleInfo>> {
    let p = new Promise<Array<BundleInfo>>((resolve: (bundleInfos: Array<BundleInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): Array<BundleInfo> => {
        return bundleManager.getAllBundleInfoNative(bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
        resolve(resultBundleInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllBundleInfo(bundleFlags: number, callback: AsyncCallback<Array<BundleInfo>>): void {
    let execFun = (): Array<BundleInfo> => {
      return bundleManager.getAllBundleInfoNative(bundleFlags, EMPTY_USER_ID);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
      callback(null, resultBundleInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllBundleInfo(bundleFlags: number, userId: number, callback: AsyncCallback<Array<BundleInfo>>): void {
    let execFun = (): Array<BundleInfo> => {
      return bundleManager.getAllBundleInfoNative(bundleFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
      callback(null, resultBundleInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllApplicationInfo(appFlags: number, userId?: number): Promise<Array<ApplicationInfo>> {
    let p = new Promise<Array<ApplicationInfo>>((resolve: (applicationInfos: Array<ApplicationInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): Array<ApplicationInfo> => {
        return bundleManager.getAllApplicationInfoNative(appFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
        resolve(resultApplicationInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllApplicationInfo(appFlags: number, callback: AsyncCallback<Array<ApplicationInfo>>): void {
    let execFun = (): Array<ApplicationInfo> => {
      return bundleManager.getAllApplicationInfoNative(appFlags, EMPTY_USER_ID);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
      callback(null, resultApplicationInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllApplicationInfo(appFlags: number, userId: number,
    callback: AsyncCallback<Array<ApplicationInfo>>): void {
    let execFun = (): Array<ApplicationInfo> => {
      return bundleManager.getAllApplicationInfoNative(appFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
      callback(null, resultApplicationInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function isApplicationEnabled(bundleName: string, appIndex: number): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return bundleManager.isApplicationEnabledNative(bundleName, appIndex, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let isEnabled: boolean = e as boolean;
        resolve(isEnabled);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function isApplicationEnabled(bundleName: string): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return bundleManager.isApplicationEnabledNative(bundleName, 0, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let isEnabled: boolean = e as boolean;
        resolve(isEnabled);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function isApplicationEnabled(bundleName: string, callback: AsyncCallback<boolean>): void {
    let execFun = (): boolean => {
      return bundleManager.isApplicationEnabledNative(bundleName, 0, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let isEnabled: boolean = e as boolean;
      callback(null, isEnabled);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function queryAbilityInfo(want: Want, abilityFlags: number, userId?: number): Promise<Array<AbilityInfo>> {
    let p = new Promise<Array<AbilityInfo>>((resolve: (abilityInfos: Array<AbilityInfo>)
      => void, reject: (error: BusinessError) => void) => {
        let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): Array<AbilityInfo> => {
        return bundleManager.queryAbilityInfoSyncNative(want, abilityFlags, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
        resolve(resultAbilityInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function queryAbilityInfo(want: Want, abilityFlags: number, callback: AsyncCallback<Array<AbilityInfo>>): void {
    let execFun = (): Array<AbilityInfo> => {
      return bundleManager.queryAbilityInfoSyncNative(want, abilityFlags, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
      callback(null, resultAbilityInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function queryAbilityInfo(want: Want,
    abilityFlags: number, userId: number, callback: AsyncCallback<Array<AbilityInfo>>): void {
    let execFun = (): Array<AbilityInfo> => {
      return bundleManager.queryAbilityInfoSyncNative(want, abilityFlags, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
      callback(null, resultAbilityInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getApplicationInfo(bundleName: string, appFlags: number, userId?: number): Promise<ApplicationInfo> {
    let p = new Promise<ApplicationInfo>((
      resolve: (applicationInfo: ApplicationInfo) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): ApplicationInfo => {
        return bundleManager.getApplicationInfoNative(bundleName, appFlags, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
        resolve(resultApplicationInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getApplicationInfo(bundleName: string, appFlags: number, callback: AsyncCallback<ApplicationInfo>): void {
    let execFun = (): ApplicationInfo => {
      return bundleManager.getApplicationInfoNative(bundleName, appFlags, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
      callback(null, resultApplicationInfo);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getApplicationInfo(bundleName: string,
    appFlags: number, userId: number, callback: AsyncCallback<ApplicationInfo>): void {
    let execFun = (): ApplicationInfo => {
      return bundleManager.getApplicationInfoNative(bundleName, appFlags, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
      callback(null, resultApplicationInfo);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAppCloneIdentity(uid: number): Promise<AppCloneIdentity> {
    let p = new Promise<AppCloneIdentity>((
      resolve: (appCloneIdentity: AppCloneIdentity) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): AppCloneIdentity => {
        return bundleManager.getAppCloneIdentityNative(uid);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultAppCloneIdentity: AppCloneIdentity = e as AppCloneIdentity;
        resolve(resultAppCloneIdentity);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAbilityLabel(bundleName: string, moduleName: string, abilityName: string): Promise<string> {
    let p = new Promise<string>((
      resolve: (label: string) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): string => {
        return bundleManager.getAbilityLabelNative(bundleName, moduleName, abilityName, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let label: string = e as string;
        resolve(label);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAbilityLabel(
    bundleName: string, moduleName: string, abilityName: string, callback: AsyncCallback<string>): void {
    let execFun = (): string => {
      return bundleManager.getAbilityLabelNative(bundleName, moduleName, abilityName, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let label: string = e as string;
      callback(null, label);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getLaunchWantForBundle(bundleName: string, userId?: number): Promise<Want> {
    let p = new Promise<Want>((
      resolve: (want: Want) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): Want => {
        return bundleManager.getLaunchWantForBundleNative(bundleName, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let want: Want = e as Want;
        resolve(want);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getLaunchWantForBundle(bundleName: string, userId: number, callback: AsyncCallback<Want>): void {
    let execFun = (): Want => {
      return bundleManager.getLaunchWantForBundleNative(bundleName, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let want: Want = e as Want;
      callback(null, want);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getLaunchWantForBundle(bundleName: string, callback: AsyncCallback<Want>): void {
    let execFun = (): Want => {
      return bundleManager.getLaunchWantForBundleNative(bundleName, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let want: Want = e as Want;
      callback(null, want);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAppCloneBundleInfo(bundleName: string, appIndex: number,
    bundleFlags: number, userId?: number): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void,
      reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): BundleInfo => {
        return bundleManager.getAppCloneBundleInfoNative(bundleName, appIndex, bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultBundleInfo: BundleInfo = e as BundleInfo;
        resolve(resultBundleInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getBundleNameByUid(uid: number, callback: AsyncCallback<string>): void {
    let execFun = (): string => {
      return bundleManager.getBundleNameByUidNative(uid, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let result: string = e as string;
      callback(null, result);
    }).catch((err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundleNameByUid(uid: number): Promise<string> {
    let p = new Promise<string>((resolve: (result: string) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): string => {
        return bundleManager.getBundleNameByUidNative(uid, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let result: string = e as string;
        resolve(result);
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function queryExtensionAbilityInfo(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: number, callback: AsyncCallback<Array<ExtensionAbilityInfo>>): void {
    let execFun = (): Array<ExtensionAbilityInfo> => {
      return bundleManager.queryExtensionAbilityInfoNative(
        want, extensionAbilityType, "", extensionAbilityFlags, EMPTY_USER_ID, false, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
      callback(null, extensionAbilityInfos);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function queryExtensionAbilityInfo(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: number, userId: number, callback: AsyncCallback<Array<ExtensionAbilityInfo>>): void {
    let execFun = (): Array<ExtensionAbilityInfo> => {
      return bundleManager.queryExtensionAbilityInfoNative(
        want, extensionAbilityType, "", extensionAbilityFlags, userId, false, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
      callback(null, extensionAbilityInfos);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function queryExtensionAbilityInfo(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: number, userId?: number): Promise<Array<ExtensionAbilityInfo>> {
    let p = new Promise<Array<ExtensionAbilityInfo>>((
      resolve: (extensionAbilityInfos: Array<ExtensionAbilityInfo>) => void,
      reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): Array<ExtensionAbilityInfo> => {
        return bundleManager.queryExtensionAbilityInfoNative(
          want, extensionAbilityType, "", extensionAbilityFlags, userIdInfo, false, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
        resolve(extensionAbilityInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function isAbilityEnabled(info: AbilityInfo, appIndex: number): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return bundleManager.isAbilityEnabledNative(info, appIndex, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let isEnabled: boolean = e as boolean;
        resolve(isEnabled);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function isAbilityEnabled(info: AbilityInfo): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return bundleManager.isAbilityEnabledNative(info, 0, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let isEnabled: boolean = e as boolean;
        resolve(isEnabled);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function isAbilityEnabled(info: AbilityInfo, callback: AsyncCallback<boolean>): void {
    let execFun = (): boolean => {
      return bundleManager.isAbilityEnabledNative(info, 0, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let isEnabled: boolean = e as boolean;
      callback(null, isEnabled);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setAbilityEnabled(info: AbilityInfo, appIndex: number, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.setAbilityEnabledNative(info, isEnabled, appIndex, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setAbilityEnabled(info: AbilityInfo, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.setAbilityEnabledNative(info, isEnabled, 0, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setAbilityEnabled(info: AbilityInfo, isEnabled: boolean, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return bundleManager.setAbilityEnabledNative(info, isEnabled, 0, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setApplicationEnabled(bundleName: string, appIndex: number, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.setApplicationEnabledNative(bundleName, isEnabled, appIndex, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setApplicationEnabled(bundleName: string, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.setApplicationEnabledNative(bundleName, isEnabled, 0, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setApplicationEnabled(bundleName: string, isEnabled: boolean, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return bundleManager.setApplicationEnabledNative(bundleName, isEnabled, 0, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getDynamicIcon(bundleName: string): Promise<string> {
    let p = new Promise<string>((
      resolve: (icon: string) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): string => {
        return bundleManager.getDynamicIconNative(bundleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let icon: string = e as string;
        resolve(icon);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function queryAbilityInfo(wants: Array<Want>, abilityFlags: number, userId?: number): Promise<Array<AbilityInfo>> {
    let p = new Promise<Array<AbilityInfo>>((resolve: (abilityInfos: Array<AbilityInfo>)
      => void, reject: (error: BusinessError) => void) => {
        let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): Array<AbilityInfo> => {
        return bundleManager.queryAbilityInfoWithWantsNative(wants, abilityFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
        resolve(resultAbilityInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function enableDynamicIcon(bundleName: string, moduleName: string): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.enableDynamicIconNative(bundleName, moduleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getBundleArchiveInfo(hapFilePath: string, bundleFlags: number, callback: AsyncCallback<BundleInfo>): void {
    let execFun = (): BundleInfo => {
      return bundleManager.getBundleArchiveInfoNative(hapFilePath, bundleFlags, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      callback(null, resultBundleInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundleArchiveInfo(hapFilePath: string, bundleFlags: number): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void,
      reject: (error: Error) => void) => {
      let execFun = (): BundleInfo => {
        return bundleManager.getBundleArchiveInfoNative(hapFilePath, bundleFlags, false);
      };
      let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let resultBundleInfo: BundleInfo = e as BundleInfo;
          resolve(resultBundleInfo);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
    }
    );
    return p;
  }

  function getProfileByAbility(moduleName: string, abilityName: string, metadataName?: string): Promise<Array<string>> {
    let p = new Promise<Array<string>>((resolve: (profile: Array<string>)
      => void, reject: (error: Error) => void) => {
      let metadataNameInfo: string = metadataName ?? "";
      let execFun = (): Array<string> => {
        return bundleManager.getProfileByAbilityNative(moduleName, abilityName, metadataNameInfo, false, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let profile: Array<string> = e as Array<string>;
        resolve(profile);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getProfileByAbility(moduleName: string,
    abilityName: string, metadataName: string, callback: AsyncCallback<Array<string>>) {
    let execFun = (): Array<string> => {
      return bundleManager.getProfileByAbilityNative(moduleName, abilityName, metadataName, false, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let profile: Array<string> = e as Array<string>;
      callback(null, profile);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getProfileByExtensionAbility(moduleName: string,
    extensionAbilityName: string, metadataName?: string): Promise<Array<string>> {
    let p = new Promise<Array<string>>((resolve: (profile: Array<string>)
      => void, reject: (error: Error) => void) => {
      let metadataNameInfo: string = metadataName ?? "";
      let execFun = (): Array<string> => {
        return bundleManager.getProfileByAbilityNative(moduleName, extensionAbilityName, metadataNameInfo, true, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let profile: Array<string> = e as Array<string>;
        resolve(profile);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getProfileByExtensionAbility(moduleName: string,
    extensionAbilityName: string, metadataName: string, callback: AsyncCallback<Array<string>>): void {
    let execFun = (): Array<string> => {
      return bundleManager.getProfileByAbilityNative(moduleName, extensionAbilityName, metadataName, true, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let profile: Array<string> = e as Array<string>;
      callback(null, profile);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getPermissionDef(permissionName: string): Promise<PermissionDef> {
    let p = new Promise<PermissionDef>((resolve: (profile: PermissionDef)
      => void, reject: (error: Error) => void) => {
      let execFun = (): PermissionDef => {
        return bundleManager.getPermissionDefNative(permissionName, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let permissionDef: PermissionDef = e as PermissionDef;
        resolve(permissionDef);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getPermissionDef(permissionName: string, callback: AsyncCallback<PermissionDef>): void {
    let execFun = (): PermissionDef => {
      return bundleManager.getPermissionDefNative(permissionName, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let permissionDef: PermissionDef = e as PermissionDef;
      callback(null, permissionDef);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function cleanBundleCacheFiles(bundleName: string, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return bundleManager.cleanBundleCacheFilesNative(bundleName, 0);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function cleanBundleCacheFiles(bundleName: string): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        return bundleManager.cleanBundleCacheFilesNative(bundleName, 0);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function cleanBundleCacheFiles(bundleName: string, appIndex: number): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        return bundleManager.cleanBundleCacheFilesNative(bundleName, appIndex);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllBundleCacheSize(): Promise<number> {
    let p = new Promise<number>((resolve: (size: number) => void, reject: (error: Error) => void) => {
      let execFun = (): number => {
        return bundleManager.getAllBundleCacheSizeNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let size: number = e as number;
        resolve(size);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function cleanAllBundleCache(): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        return bundleManager.cleanAllBundleCacheNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }
  
  function getAppProvisionInfo(bundleName: string, userId?: number): Promise<AppProvisionInfo> {
    let p = new Promise<AppProvisionInfo>((resolve: (appProvisionInfo: AppProvisionInfo)
      => void, reject: (error: Error) => void) => {
      let userIdInfo: number = userId ?? EMPTY_USER_ID;
      let execFun = (): AppProvisionInfo => {
        return bundleManager.getAppProvisionInfoNative(bundleName, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let appProvisionInfo: AppProvisionInfo = e as AppProvisionInfo;
        resolve(appProvisionInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAppProvisionInfo(bundleName: string, userId: number, callback: AsyncCallback<AppProvisionInfo>): void {
    let execFun = (): AppProvisionInfo => {
      return bundleManager.getAppProvisionInfoNative(bundleName, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let appProvisionInfo: AppProvisionInfo = e as AppProvisionInfo;
      callback(null, appProvisionInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAppProvisionInfo(bundleName: string, callback: AsyncCallback<AppProvisionInfo>): void {
    let execFun = (): AppProvisionInfo => {
      return bundleManager.getAppProvisionInfoNative(bundleName, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let appProvisionInfo: AppProvisionInfo = e as AppProvisionInfo;
      callback(null, appProvisionInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllPreinstalledApplicationInfo(): Promise<Array<PreinstalledApplicationInfo>> {
    let p = new Promise<Array<PreinstalledApplicationInfo>>((resolve:
      (applicationInfo: Array<PreinstalledApplicationInfo>) => void, reject: (error: Error) => void) => {
      let execFun = (): Array<PreinstalledApplicationInfo> => {
        return bundleManager.getAllPreinstalledApplicationInfoNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let applicationInfo: Array<PreinstalledApplicationInfo> = e as Array<PreinstalledApplicationInfo>;
        resolve(applicationInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllAppCloneBundleInfo(bundleName: string, bundleFlags:
    number, userId?: number): Promise<Array<BundleInfo>> {
    let p = new Promise<Array<BundleInfo>>((resolve: (bundleInfos: Array<BundleInfo>)
      => void, reject: (error: Error) => void) => {
      let userIdInfo: number = userId ?? -2;
      let execFun = (): Array<BundleInfo> => {
        return bundleManager.getAllAppCloneBundleInfoNative(bundleName, bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
        resolve(resultBundleInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }
}

export default bundleManager;

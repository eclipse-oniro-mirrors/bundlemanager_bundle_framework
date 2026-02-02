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

import { BundleInfo, AppCloneIdentity, SignatureInfo, BundleOptions, DynamicIconInfo } from 'bundleManager.BundleInfo';
import { AsyncCallback, BusinessError } from '@ohos.base';
import { PreinstalledApplicationInfo, ApplicationInfo } from 'bundleManager.ApplicationInfo';
import { AbilityInfo } from 'bundleManager.AbilityInfo';
import { ExtensionAbilityInfo } from 'bundleManager.ExtensionAbilityInfo';
import { PermissionDef } from 'bundleManager.PermissionDef';
import { SharedBundleInfo } from 'bundleManager.SharedBundleInfo'
import { AppProvisionInfo } from 'bundleManager.AppProvisionInfo'
import { RecoverableApplicationInfo } from 'bundleManager.RecoverableApplicationInfo'
import { PluginBundleInfo } from 'bundleManager.PluginBundleInfo';
import Want from '@ohos.app.ability.Want';
import { BundleOptionsInner } from './bundleManager/BundleInfoInner';

namespace bundleManager {

  loadLibraryWithPermissionCheck("ani_bundle_manager.z", "@ohos.bundle.bundleManager");

  const EMPTY_VALUE: int = -500;
  const EMPTY_STRING: string = "ani empty string";
  const MAIN_APP_INDEX: int = 0;
  const CLONE_APP_INDEX_MAX: int = 5;
  const ERROR_INVALID_APPINDEX_CODE: int = 17700061;
  const ERROR_INVALID_APPINDEX_MSG: string = "BusinessError 17700061: The specified app index is invalid.";
  const ERROR_PARAM_CHECK_ERROR: int = 401;
  const PARAM_BUNDLENAME_EMPTY_ERROR: string = "BusinessError 401: Parameter error. parameter bundleName is empty";
  const ERROR_ABILITY_NOT_EXIST: int = 17700003;
  const GETABILITYINFO_ERROR_MSG: string = "BusinessError 17700003: The specified ability is not found.";
  const PARAM_BUNDLENAME_TYPE_ERROR: string = "BusinessError 401: Parameter error. The type of bundleName must be string.";
  const PARAM_TYPE_CHECK_ERROR: string = "param type check error";

  function createBusinessError(code: int, message: string) {
    let err = new BusinessError();
    err.code = code;
    err.name = 'Error';
    err.message = message;
    return err;
  }

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
    GET_BUNDLE_INFO_WITH_CLOUD_KIT = 0x00008000,
    GET_BUNDLE_INFO_WITH_ENTRY_MODULE = 0x00010000,
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
    CALLER_INFO_QUERY = 25,
    ASSET_ACCELERATION = 26,
    FORM_EDIT = 27,
    DISTRIBUTED = 28,
    APP_SERVICE = 29,
    LIVE_FORM = 30,
    WEB_NATIVE_MESSAGING = 32,
    FAULT_LOG = 33,
    NOTIFICATION_SUBSCRIBER = 34,
    CRYPTO = 35,
    PARTNER_AGENT = 36,
    AGENT = 37,
    AGENT_UI = 38,
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

  export enum AbilityProfileType {
    ABILITY_PROFILE = 0,
    EXTENSION_PROFILE = 1,
    UNKNOWN_PROFILE = 2
  }

  export enum BundleInstallStatus {
    BUNDLE_NOT_EXIST = 1,
    BUNDLE_INSTALLING = 2,
    BUNDLE_INSTALLED = 3
  }

  native function getBundleInfoForSelfNative(bundleFlags: int, isSync: boolean): BundleInfo;

  native function getBundleInfoNative(bundleName: string, bundleFlags: int, userId: int, isSync: boolean) : BundleInfo;

  native function getApplicationInfoNative(bundleName: string, applicationFlags: int, userId: int, isSync: boolean): ApplicationInfo;

  native function getAllBundleInfoNative(bundleFlags: int, userId: int): Array<BundleInfo>;

  native function getAllApplicationInfoNative(appFlags: int, userId: int): Array<ApplicationInfo>;

  native function isApplicationEnabledNative(bundleName: string, appIndex: int, isSync: boolean): boolean;

  native function queryAbilityInfoSyncNative(want: Want, abilityFlags: int, userId: int, isSync: boolean): Array<AbilityInfo>;

  native function getAppCloneIdentityNative(uid: int): AppCloneIdentity;

  native function getAbilityLabelNative(bundleName: string, moduleName: string, abilityName: string, isSync: boolean): string;

  native function getLaunchWantForBundleNative(bundleName: string, userId: int, isSync: boolean): Want;

  native function getAppCloneBundleInfoNative(bundleName: string, appIndex: int,
    bundleFlags: int, userId: int): BundleInfo;

  native function getSpecifiedDistributionType(bundleName: string): string;

  native function getBundleNameByUidNative(uid: int, isSync: boolean): string;

  native function isAbilityEnabledNative(info: AbilityInfo, appIndex: int, isSync: boolean): boolean;

  native function setAbilityEnabledNative(info: AbilityInfo, isEnabled: boolean, appIndex: int, isSync: boolean): void;

  native function setApplicationEnabledNative(bundleName: string, isEnabled: boolean, appIndex: int, isSync: boolean): void;

  native function setAbilityFileTypesForSelf(moduleName: string, abilityName: string, fileTypes: Array<string>): void;

  native function getDynamicIconNative(bundleName: string): string;

  native function queryAbilityInfoWithWantsNative(wants: Array<Want>, abilityFlags: int,
    userId: int): Array<AbilityInfo>;

  native function queryExtensionAbilityInfoNative(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityTypeName: string, extensionAbilityFlags: int,
    userId: int, isExtensionTypeName: boolean, isSync: boolean): Array<ExtensionAbilityInfo>;

  native function queryExAbilityInfoSyncWithoutWantNative(extensionAbilityType: string, extensionAbilityFlags: int,
    userId: int): Array<ExtensionAbilityInfo>;

  native function enableDynamicIconNative(bundleName: string, moduleName: string, option: BundleOptions): void;

  native function cleanBundleCacheFilesForSelfNative(): void;

  function getBundleInfoForSelfSync(bundleFlags: int): BundleInfo {
    return getBundleInfoForSelfNative(bundleFlags, true);
  }

  function getAbilityLabelSync(bundleName: string, moduleName: string, abilityName: string): string {
    return getAbilityLabelNative(bundleName, moduleName, abilityName, true);
  }

  function getBundleNameByUidSync(uid: int): string {
    return getBundleNameByUidNative(uid, true);
  }

  native function getBundleArchiveInfoNative(hapFilePath: string, bundleFlags: int, isSync: boolean): BundleInfo;

  native function getLaunchWant(): Want;

  native function getProfileByAbilityNative(moduleName: string,
    abilityName: string, metadataName: string, profileType: AbilityProfileType, isSync: boolean): Array<string>;
  
  native function getPermissionDefNative(permissionName: string, isSync: boolean): PermissionDef;

  native function cleanBundleCacheFilesNative(bundleName: string, appIndex: int): void;

  native function getAllBundleCacheSizeNative(): long;

  native function cleanAllBundleCacheNative(): void;

  native function getAppProvisionInfoNative(bundleName: string, userId: int, isSync: boolean): AppProvisionInfo;

  native function getAllAppProvisionInfoNative(userId: int): Array<AppProvisionInfo>;

  native function canOpenLink(link: string): boolean;

  native function getAllPreinstalledApplicationInfoNative(): Array<PreinstalledApplicationInfo>;

  native function getAllBundleInfoByDeveloperId(developerId: string): Array<BundleInfo>;

  native function switchUninstallState(bundleName: string, state: boolean): void;

  native function getSignatureInfo(uid: int): SignatureInfo;

  native function getAllAppCloneBundleInfoNative(bundleName: string,
    bundleFlags: int, userId: int): Array<BundleInfo>;

  native function getAllSharedBundleInfoNative(): Array<SharedBundleInfo>;

  native function getSharedBundleInfoNative(bundleName: string, moduleName: string): Array<SharedBundleInfo>;

  native function getAdditionalInfo(bundleName: string): string;

  native function getJsonProfileNative(profileType: ProfileType, bundleName: string, moduleName: string, userId: int): string;

  native function getExtResourceNative(bundleName: string): Array<string>;

  native function disableDynamicIconNative(bundleName: string, option: BundleOptions): void;
  
  native function getDynamicIconInfoNative(bundleName: string): Array<DynamicIconInfo>;

  native function getAllDynamicIconInfoNative(userId: int): Array<DynamicIconInfo>;

  native function verifyAbcNative(abcPaths: Array<string>, deleteOriginalFiles: boolean): void;

  native function getRecoverableApplicationInfoNative(): Array<RecoverableApplicationInfo>;

  native function setAdditionalInfo(bundleName: string, additionalInfo: string): void;

  native function deleteAbcNative(abcPath: string): void;

  native function getDeveloperIdsNative(appDistributionType: int): Array<string>;

  native function getAllPluginInfoNative(hostBundleName: string, userId: int): Array<PluginBundleInfo>;
  
  native function migrateDataNative(sourcePaths: Array<string>, destinationPath: string): void;

  native function getSandboxDataDir(bundleName: string, appIndex: int): string;

  native function getAppCloneIdentityBySandboxDataDir(sandboxDataDir: string): AppCloneIdentity;

  native function getAbilityInfoNative(uri: string, abilityFlags: int): Array<AbilityInfo>;

  native function getPluginBundlePathForSelfNative(pluginBundleName: string): string;
  
  native function recoverBackupBundleDataNative(bundleName: string, userId: int , appIndex: int): void;

  native function removeBackupBundleDataNative(bundleName: string, userId: int , appIndex: int): void;

  native function getBundleInstallStatusNative(bundleName: string): BundleInstallStatus;

  function isApplicationEnabledSync(bundleName: string): boolean {
    return isApplicationEnabledNative(bundleName, 0, true);
  }

  function queryAbilityInfoSync(want: Want, abilityFlags: int, userId?: int): Array<AbilityInfo> {
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    return queryAbilityInfoSyncNative(want, abilityFlags, userIdInfo, true);
  }

  function getLaunchWantForBundleSync(bundleName: string, userId?: int): Want {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
    }
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    return getLaunchWantForBundleNative(bundleName, userIdInfo, true);
  }

  function isAbilityEnabledSync(info: AbilityInfo): boolean {
    return isAbilityEnabledNative(info, 0, true);
  }

  function setAbilityEnabledSync(info: AbilityInfo, isEnabled: boolean): void {
    return setAbilityEnabledNative(info, isEnabled, 0, true);
  }

  function setApplicationEnabledSync(bundleName: string, isEnabled: boolean): void {
    return setApplicationEnabledNative(bundleName, isEnabled, 0, true);
  }

  function queryExtensionAbilityInfoSync(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: int, userId?: int): Array<ExtensionAbilityInfo> {
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    return queryExtensionAbilityInfoNative(
      want, extensionAbilityType, "", extensionAbilityFlags, userIdInfo, false, true);
  }

  function queryExtensionAbilityInfoSync(want: Want, extensionAbilityType: string, extensionAbilityFlags: int,
    userId?: int): Array<ExtensionAbilityInfo> {
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    return queryExtensionAbilityInfoNative(
      want, ExtensionAbilityType.UNSPECIFIED, extensionAbilityType, extensionAbilityFlags, userIdInfo, true, true);
  }

  function queryExtensionAbilityInfoSync(extensionAbilityType: string, extensionAbilityFlags: int,
    userId?: int): Array<ExtensionAbilityInfo> {
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    return queryExAbilityInfoSyncWithoutWantNative(extensionAbilityType, extensionAbilityFlags, userIdInfo);
  }

  function getBundleArchiveInfoSync(hapFilePath: string, bundleFlags: int): BundleInfo {
    return getBundleArchiveInfoNative(hapFilePath, bundleFlags, true);
  }

  function getProfileByAbilitySync(moduleName: string, abilityName: string, metadataName?: string): Array<string> {
    let metadataNameInfo: string = metadataName ?? "";
    return getProfileByAbilityNative(moduleName, abilityName, metadataNameInfo, AbilityProfileType.ABILITY_PROFILE, true);
  }

  function getProfileByExtensionAbilitySync(moduleName: string,
    extensionAbilityName: string, metadataName?: string): Array<string> {
    let metadataNameInfo: string = metadataName ?? "";
    return getProfileByAbilityNative(moduleName, extensionAbilityName, metadataNameInfo, AbilityProfileType.EXTENSION_PROFILE, true);
  }

  function getPermissionDefSync(permissionName: string): PermissionDef {
    return getPermissionDefNative(permissionName, true);
  }
  
  function getAppProvisionInfoSync(bundleName: string, userId?: int): AppProvisionInfo {
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    return getAppProvisionInfoNative(bundleName, userIdInfo, true);
  }

  function getJsonProfile(profileType: ProfileType, bundleName: string, moduleName?: string, userId?: int): string {
    let userIdInfo: int = userId ?? -2;
    let moduleNameInfo: string = moduleName ?? EMPTY_STRING;
    return getJsonProfileNative(profileType, bundleName, moduleNameInfo, userIdInfo);
  }

  function getDeveloperIds(appDistributionType?: int): Array<string> {
    let appDistributionTypeInfo: int = appDistributionType ?? EMPTY_VALUE;
    return getDeveloperIdsNative(appDistributionTypeInfo);
  }

  function getBundleInfoForSelf(bundleFlags: int, callback: AsyncCallback<BundleInfo, void>):void {
    let execFun = (): BundleInfo => {
      return getBundleInfoForSelfNative(bundleFlags, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      callback(null, resultBundleInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundleInfoForSelf(bundleFlags: int):Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): BundleInfo => {
        return getBundleInfoForSelfNative(bundleFlags, false);
      };
      let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
          let resultBundleInfo: BundleInfo = e as BundleInfo;
          resolve(resultBundleInfo);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
    }
    );
    return p;
  }

  function getBundleInfoSync(bundleName: string, bundleFlags: int, userId: int): BundleInfo {
    return getBundleInfoNative(bundleName, bundleFlags, userId, true);
  }

  function getBundleInfoSync(bundleName: string, bundleFlags: int): BundleInfo {
    return getBundleInfoNative(bundleName, bundleFlags, EMPTY_VALUE, true);
  }

  function getBundleInfo(bundleName: string, bundleFlags: int, userId?: int): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): BundleInfo => {
        return getBundleInfoNative(bundleName, bundleFlags, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let resultBundleInfo: BundleInfo = e as BundleInfo;
        resolve(resultBundleInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getBundleInfo(bundleName: string, bundleFlags: int, callback: AsyncCallback<BundleInfo>): void {
    let execFun = (): BundleInfo => {
      return getBundleInfoNative(bundleName, bundleFlags, EMPTY_VALUE, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      callback(null, resultBundleInfo);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundleInfo(bundleName: string, bundleFlags: int, userId: int, callback: AsyncCallback<BundleInfo>): void {
    let execFun = (): BundleInfo => {
      return getBundleInfoNative(bundleName, bundleFlags, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      callback(null, resultBundleInfo);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getApplicationInfoSync(bundleName: string, applicationFlags: int): ApplicationInfo {
    return getApplicationInfoNative(bundleName, applicationFlags, EMPTY_VALUE, true);
  }

  function getApplicationInfoSync(bundleName: string, applicationFlags: int, userId: int): ApplicationInfo {
    return getApplicationInfoNative(bundleName, applicationFlags, userId, true);
  }

  function getAllBundleInfo(bundleFlags: int, userId?: int): Promise<Array<BundleInfo>> {
    let p = new Promise<Array<BundleInfo>>((resolve: (bundleInfos: Array<BundleInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Array<BundleInfo> => {
        return getAllBundleInfoNative(bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
        resolve(resultBundleInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllBundleInfo(bundleFlags: int, callback: AsyncCallback<Array<BundleInfo>>): void {
    let execFun = (): Array<BundleInfo> => {
      return getAllBundleInfoNative(bundleFlags, EMPTY_VALUE);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
      callback(null, resultBundleInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllBundleInfo(bundleFlags: int, userId: int, callback: AsyncCallback<Array<BundleInfo>>): void {
    let execFun = (): Array<BundleInfo> => {
      return getAllBundleInfoNative(bundleFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
      callback(null, resultBundleInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllApplicationInfo(appFlags: int, userId?: int): Promise<Array<ApplicationInfo>> {
    let p = new Promise<Array<ApplicationInfo>>((resolve: (applicationInfos: Array<ApplicationInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Array<ApplicationInfo> => {
        return getAllApplicationInfoNative(appFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
        resolve(resultApplicationInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllApplicationInfo(appFlags: int, callback: AsyncCallback<Array<ApplicationInfo>>): void {
    let execFun = (): Array<ApplicationInfo> => {
      return getAllApplicationInfoNative(appFlags, EMPTY_VALUE);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
      callback(null, resultApplicationInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllApplicationInfo(appFlags: int, userId: int,
    callback: AsyncCallback<Array<ApplicationInfo>>): void {
    let execFun = (): Array<ApplicationInfo> => {
      return getAllApplicationInfoNative(appFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
      callback(null, resultApplicationInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function isApplicationEnabled(bundleName: string, appIndex: int): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return isApplicationEnabledNative(bundleName, appIndex, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
        return isApplicationEnabledNative(bundleName, 0, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
      return isApplicationEnabledNative(bundleName, 0, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let isEnabled: boolean = e as boolean;
      callback(null, isEnabled);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function queryAbilityInfo(want: Want, abilityFlags: int, userId?: int): Promise<Array<AbilityInfo>> {
    let p = new Promise<Array<AbilityInfo>>((resolve: (abilityInfos: Array<AbilityInfo>)
      => void, reject: (error: BusinessError) => void) => {
        let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Array<AbilityInfo> => {
        return queryAbilityInfoSyncNative(want, abilityFlags, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
        resolve(resultAbilityInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function queryAbilityInfo(want: Want, abilityFlags: int, callback: AsyncCallback<Array<AbilityInfo>>): void {
    let execFun = (): Array<AbilityInfo> => {
      return queryAbilityInfoSyncNative(want, abilityFlags, EMPTY_VALUE, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
      callback(null, resultAbilityInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function queryAbilityInfo(want: Want,
    abilityFlags: int, userId: int, callback: AsyncCallback<Array<AbilityInfo>>): void {
    let execFun = (): Array<AbilityInfo> => {
      return queryAbilityInfoSyncNative(want, abilityFlags, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
      callback(null, resultAbilityInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getApplicationInfo(bundleName: string, appFlags: int, userId?: int): Promise<ApplicationInfo> {
    let p = new Promise<ApplicationInfo>((
      resolve: (applicationInfo: ApplicationInfo) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): ApplicationInfo => {
        return getApplicationInfoNative(bundleName, appFlags, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
        resolve(resultApplicationInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getApplicationInfo(bundleName: string, appFlags: int, callback: AsyncCallback<ApplicationInfo>): void {
    let execFun = (): ApplicationInfo => {
      return getApplicationInfoNative(bundleName, appFlags, EMPTY_VALUE, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
      callback(null, resultApplicationInfo);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getApplicationInfo(bundleName: string,
    appFlags: int, userId: int, callback: AsyncCallback<ApplicationInfo>): void {
    let execFun = (): ApplicationInfo => {
      return getApplicationInfoNative(bundleName, appFlags, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
      callback(null, resultApplicationInfo);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAppCloneIdentity(uid: int): Promise<AppCloneIdentity> {
    let p = new Promise<AppCloneIdentity>((
      resolve: (appCloneIdentity: AppCloneIdentity) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): AppCloneIdentity => {
        return getAppCloneIdentityNative(uid);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
        return getAbilityLabelNative(bundleName, moduleName, abilityName, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
      return getAbilityLabelNative(bundleName, moduleName, abilityName, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let label: string = e as string;
      callback(null, label);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getLaunchWantForBundle(bundleName: string, userId?: int): Promise<Want> {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_TYPE_ERROR);
    }
    let p = new Promise<Want>((
      resolve: (want: Want) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Want => {
        return getLaunchWantForBundleNative(bundleName, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let want: Want = e as Want;
        resolve(want);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getLaunchWantForBundle(bundleName: string, userId: int, callback: AsyncCallback<Want>): void {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_TYPE_ERROR);
    }
    let execFun = (): Want => {
      return getLaunchWantForBundleNative(bundleName, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let want: Want = e as Want;
      callback(null, want);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getLaunchWantForBundle(bundleName: string, callback: AsyncCallback<Want>): void {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_TYPE_ERROR);
    }
    let execFun = (): Want => {
      return getLaunchWantForBundleNative(bundleName, EMPTY_VALUE, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let want: Want = e as Want;
      callback(null, want);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAppCloneBundleInfo(bundleName: string, appIndex: int,
    bundleFlags: int, userId?: int): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void,
      reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): BundleInfo => {
        return getAppCloneBundleInfoNative(bundleName, appIndex, bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let resultBundleInfo: BundleInfo = e as BundleInfo;
        resolve(resultBundleInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getBundleNameByUid(uid: int, callback: AsyncCallback<string>): void {
    let execFun = (): string => {
      return getBundleNameByUidNative(uid, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let result: string = e as string;
      callback(null, result);
    }).catch((err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundleNameByUid(uid: int): Promise<string> {
    let p = new Promise<string>((resolve: (result: string) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): string => {
        return getBundleNameByUidNative(uid, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
    extensionAbilityFlags: int, callback: AsyncCallback<Array<ExtensionAbilityInfo>>): void {
    let execFun = (): Array<ExtensionAbilityInfo> => {
      return queryExtensionAbilityInfoNative(
        want, extensionAbilityType, "", extensionAbilityFlags, EMPTY_VALUE, false, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
      callback(null, extensionAbilityInfos);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function queryExtensionAbilityInfo(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: int, userId: int, callback: AsyncCallback<Array<ExtensionAbilityInfo>>): void {
    let execFun = (): Array<ExtensionAbilityInfo> => {
      return queryExtensionAbilityInfoNative(
        want, extensionAbilityType, "", extensionAbilityFlags, userId, false, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
      callback(null, extensionAbilityInfos);
    },(err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function queryExtensionAbilityInfo(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: int, userId?: int): Promise<Array<ExtensionAbilityInfo>> {
    let p = new Promise<Array<ExtensionAbilityInfo>>((
      resolve: (extensionAbilityInfos: Array<ExtensionAbilityInfo>) => void,
      reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Array<ExtensionAbilityInfo> => {
        return queryExtensionAbilityInfoNative(
          want, extensionAbilityType, "", extensionAbilityFlags, userIdInfo, false, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
        resolve(extensionAbilityInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function isAbilityEnabled(info: AbilityInfo, appIndex: int): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return isAbilityEnabledNative(info, appIndex, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
        return isAbilityEnabledNative(info, 0, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
      return isAbilityEnabledNative(info, 0, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let isEnabled: boolean = e as boolean;
      callback(null, isEnabled);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setAbilityEnabled(info: AbilityInfo, appIndex: int, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return setAbilityEnabledNative(info, isEnabled, appIndex, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setAbilityEnabled(info: AbilityInfo, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return setAbilityEnabledNative(info, isEnabled, 0, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setAbilityEnabled(info: AbilityInfo, isEnabled: boolean, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return setAbilityEnabledNative(info, isEnabled, 0, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setApplicationEnabled(bundleName: string, appIndex: int, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return setApplicationEnabledNative(bundleName, isEnabled, appIndex, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setApplicationEnabled(bundleName: string, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return setApplicationEnabledNative(bundleName, isEnabled, 0, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setApplicationEnabled(bundleName: string, isEnabled: boolean, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return setApplicationEnabledNative(bundleName, isEnabled, 0, false);
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
        return getDynamicIconNative(bundleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let icon: string = e as string;
        resolve(icon);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function queryAbilityInfo(wants: Array<Want>, abilityFlags: int, userId?: int): Promise<Array<AbilityInfo>> {
    let p = new Promise<Array<AbilityInfo>>((resolve: (abilityInfos: Array<AbilityInfo>)
      => void, reject: (error: BusinessError) => void) => {
        let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Array<AbilityInfo> => {
        return queryAbilityInfoWithWantsNative(wants, abilityFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
        resolve(resultAbilityInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function enableDynamicIcon(bundleName: string, moduleName: string, option?: BundleOptions): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let bundleOptions = option ?? new BundleOptionsInner();
      let execFun = (): void => {
        return enableDynamicIconNative(bundleName, moduleName, bundleOptions);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getBundleArchiveInfo(hapFilePath: string, bundleFlags: int, callback: AsyncCallback<BundleInfo>): void {
    let execFun = (): BundleInfo => {
      return getBundleArchiveInfoNative(hapFilePath, bundleFlags, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      callback(null, resultBundleInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundleArchiveInfo(hapFilePath: string, bundleFlags: int): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void,
      reject: (error: Error) => void) => {
      let execFun = (): BundleInfo => {
        return getBundleArchiveInfoNative(hapFilePath, bundleFlags, false);
      };
      let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        return getProfileByAbilityNative(moduleName, abilityName, metadataNameInfo, AbilityProfileType.ABILITY_PROFILE, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
      return getProfileByAbilityNative(moduleName, abilityName, metadataName, AbilityProfileType.ABILITY_PROFILE, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
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
        return getProfileByAbilityNative(moduleName, extensionAbilityName, metadataNameInfo, AbilityProfileType.EXTENSION_PROFILE, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
      return getProfileByAbilityNative(moduleName, extensionAbilityName, metadataName, AbilityProfileType.EXTENSION_PROFILE, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
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
        return getPermissionDefNative(permissionName, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
      return getPermissionDefNative(permissionName, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let permissionDef: PermissionDef = e as PermissionDef;
      callback(null, permissionDef);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function cleanBundleCacheFiles(bundleName: string, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return cleanBundleCacheFilesNative(bundleName, 0);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function cleanBundleCacheFiles(bundleName: string): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        return cleanBundleCacheFilesNative(bundleName, 0);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function cleanBundleCacheFiles(bundleName: string, appIndex: int): Promise<void> {
    if (appIndex < MAIN_APP_INDEX || appIndex > CLONE_APP_INDEX_MAX) {
      throw createBusinessError(ERROR_INVALID_APPINDEX_CODE, ERROR_INVALID_APPINDEX_MSG);
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        return cleanBundleCacheFilesNative(bundleName, appIndex);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllBundleCacheSize(): Promise<long> {
    let p = new Promise<long>((resolve: (size: long) => void, reject: (error: Error) => void) => {
      let execFun = (): long => {
        return getAllBundleCacheSizeNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let size: long = e as long;
        resolve(size);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function cleanAllBundleCache(): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        return cleanAllBundleCacheNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }
  
  function getAllAppProvisionInfo(userId?: int): Promise<Array<AppProvisionInfo>>{
    let p = new Promise<Array<AppProvisionInfo>>((resolve: (appProvisionInfo: Array<AppProvisionInfo>)
      => void, reject: (error: Error) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Array<AppProvisionInfo> => {
        return getAllAppProvisionInfoNative(userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let appProvisionInfo: Array<AppProvisionInfo> = e as Array<AppProvisionInfo>;
        resolve(appProvisionInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAppProvisionInfo(bundleName: string, userId?: int): Promise<AppProvisionInfo> {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
    }
    let p = new Promise<AppProvisionInfo>((resolve: (appProvisionInfo: AppProvisionInfo)
      => void, reject: (error: Error) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): AppProvisionInfo => {
        return getAppProvisionInfoNative(bundleName, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let appProvisionInfo: AppProvisionInfo = e as AppProvisionInfo;
        resolve(appProvisionInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAppProvisionInfo(bundleName: string, userId: int, callback: AsyncCallback<AppProvisionInfo>): void {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
    }
    let execFun = (): AppProvisionInfo => {
      return getAppProvisionInfoNative(bundleName, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let appProvisionInfo: AppProvisionInfo = e as AppProvisionInfo;
      callback(null, appProvisionInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAppProvisionInfo(bundleName: string, callback: AsyncCallback<AppProvisionInfo>): void {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
    }
    let execFun = (): AppProvisionInfo => {
      return getAppProvisionInfoNative(bundleName, EMPTY_VALUE, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
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
        return getAllPreinstalledApplicationInfoNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
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
    int, userId?: int): Promise<Array<BundleInfo>> {
    let p = new Promise<Array<BundleInfo>>((resolve: (bundleInfos: Array<BundleInfo>)
      => void, reject: (error: Error) => void) => {
      let userIdInfo: int = userId ?? -2;
      let execFun = (): Array<BundleInfo> => {
        return getAllAppCloneBundleInfoNative(bundleName, bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
        resolve(resultBundleInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllSharedBundleInfo(): Promise<Array<SharedBundleInfo>> {
    let p = new Promise<Array<SharedBundleInfo>>((resolve: (sharedBundleInfos: Array<SharedBundleInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let execFun = (): Array<SharedBundleInfo> => {
        return getAllSharedBundleInfoNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let sharedBundleInfos: Array<SharedBundleInfo> = e as Array<SharedBundleInfo>;
        resolve(sharedBundleInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllSharedBundleInfo(callback: AsyncCallback<Array<SharedBundleInfo>>): void {
    let execFun = (): Array<SharedBundleInfo> => {
      return getAllSharedBundleInfoNative();
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let sharedBundleInfos: Array<SharedBundleInfo> = e as Array<SharedBundleInfo>;
      callback(null, sharedBundleInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getSharedBundleInfo(bundleName: string, moduleName: string): Promise<Array<SharedBundleInfo>> {
    let p = new Promise<Array<SharedBundleInfo>>((resolve: (sharedBundleInfos: Array<SharedBundleInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let execFun = (): Array<SharedBundleInfo> => {
        return getSharedBundleInfoNative(bundleName, moduleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let sharedBundleInfos: Array<SharedBundleInfo> = e as Array<SharedBundleInfo>;
        resolve(sharedBundleInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getSharedBundleInfo(bundleName: string, moduleName: string,
    callback: AsyncCallback<Array<SharedBundleInfo>>): void {
    let execFun = (): Array<SharedBundleInfo> => {
      return getSharedBundleInfoNative(bundleName, moduleName);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let sharedBundleInfos: Array<SharedBundleInfo> = e as Array<SharedBundleInfo>;
      callback(null, sharedBundleInfos);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getExtResource(bundleName: string): Promise<Array<string>> {
    let p = new Promise<Array<string>>((resolve: (extResource: Array<string>)
      => void, reject: (error: BusinessError) => void) => {
      let execFun = (): Array<string> => {
        return getExtResourceNative(bundleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let extResource: Array<string> = e as Array<string>;
        resolve(extResource);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function disableDynamicIcon(bundleName: string, option?: BundleOptions): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let bundleOptions = option ?? new BundleOptionsInner();
      let execFun = (): void => {
        return disableDynamicIconNative(bundleName, bundleOptions);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getDynamicIconInfo(bundleName: string): Promise<Array<DynamicIconInfo>> {
    let p = new Promise<Array<DynamicIconInfo>>((resolve: (dynamicIconInfos: Array<DynamicIconInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let execFun = (): Array<DynamicIconInfo> => {
        return getDynamicIconInfoNative(bundleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let dynamicIconInfos: Array<DynamicIconInfo> = e as Array<DynamicIconInfo>;
        resolve(dynamicIconInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllDynamicIconInfo(userId?: int): Promise<Array<DynamicIconInfo>> {
    let p = new Promise<Array<DynamicIconInfo>>((resolve: (dynamicIconInfos: Array<DynamicIconInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Array<DynamicIconInfo> => {
        return getAllDynamicIconInfoNative(userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let dynamicIconInfos: Array<DynamicIconInfo> = e as Array<DynamicIconInfo>;
        resolve(dynamicIconInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function verifyAbc(abcPaths: Array<string>, deleteOriginalFiles: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return verifyAbcNative(abcPaths, deleteOriginalFiles);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function verifyAbc(abcPaths: Array<string>, deleteOriginalFiles: boolean, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return verifyAbcNative(abcPaths, deleteOriginalFiles);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getRecoverableApplicationInfo(): Promise<Array<RecoverableApplicationInfo>> {
    let p = new Promise<Array<RecoverableApplicationInfo>>((resolve:
      (applicationInfo: Array<RecoverableApplicationInfo>) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): Array<RecoverableApplicationInfo> => {
        return getRecoverableApplicationInfoNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let applicationInfo: Array<RecoverableApplicationInfo> = e as Array<RecoverableApplicationInfo>;
        resolve(applicationInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getRecoverableApplicationInfo(callback: AsyncCallback<Array<RecoverableApplicationInfo>>): void {
    let execFun = (): Array<RecoverableApplicationInfo> => {
      return getRecoverableApplicationInfoNative();
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let applicationInfo: Array<RecoverableApplicationInfo> = e as Array<RecoverableApplicationInfo>;
      callback(null, applicationInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function deleteAbc(abcPath: string): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return deleteAbcNative(abcPath);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAllPluginInfo(hostBundleName: string, userId?: int): Promise<Array<PluginBundleInfo>> {
    let p = new Promise<Array<PluginBundleInfo>>((resolve: (pluginBundleInfo: Array<PluginBundleInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: int = userId ?? EMPTY_VALUE;
      let execFun = (): Array<PluginBundleInfo> => {
        return getAllPluginInfoNative(hostBundleName, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let pluginBundleInfo: Array<PluginBundleInfo> = e as Array<PluginBundleInfo>;
        resolve(pluginBundleInfo);
        }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function migrateData(sourcePaths: Array<string>, destinationPath: string): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return migrateDataNative(sourcePaths, destinationPath);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getAbilityInfo(uri: string, abilityFlags: int): Promise<Array<AbilityInfo>> {
    if (uri === "") {
      throw createBusinessError(ERROR_ABILITY_NOT_EXIST, GETABILITYINFO_ERROR_MSG);
    }
    let p = new Promise<Array<AbilityInfo>>((resolve: (abilityInfos: Array<AbilityInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let execFun = (): Array<AbilityInfo> => {
        return getAbilityInfoNative(uri, abilityFlags);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let abilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
        resolve(abilityInfos);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }
  
  function cleanBundleCacheFilesForSelf(): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return cleanBundleCacheFilesForSelfNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getPluginBundlePathForSelf(pluginBundleName: string): string {
    return getPluginBundlePathForSelfNative(pluginBundleName);
  }

  function recoverBackupBundleData(bundleName: string, userId: int , appIndex: int): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return recoverBackupBundleDataNative(bundleName, userId, appIndex);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function removeBackupBundleData(bundleName: string, userId: int , appIndex: int): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return removeBackupBundleDataNative(bundleName, userId, appIndex);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getBundleInstallStatus(bundleName: string): BundleInstallStatus {
    return getBundleInstallStatusNative(bundleName);
  }
}

export default bundleManager;

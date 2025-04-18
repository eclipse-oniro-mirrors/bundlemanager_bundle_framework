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

import { BundleInfo, AppCloneIdentity } from 'bundleManager.BundleInfo';
import { AsyncCallback, BusinessError } from '@ohos.base';
import { ApplicationInfo } from 'bundleManager.ApplicationInfo';
import { AbilityInfo } from 'bundleManager.AbilityInfo';
import { ExtensionAbilityInfo } from 'bundleManager.ExtensionAbilityInfo';
import Want from '@ohos.app.ability.Want';
import { BundleInfoInner } from './bundleManager/BundleInfoInner';
import { ApplicationInfoInner } from './bundleManager/ApplicationInfoInner';

namespace bundleManager {

  loadLibrary("ani_bundle_manager.z");

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

  export native function getBundleInfoForSelfSync(bundleFlags: number): BundleInfo;

  export native function getBundleInfoSync(bundleName: string, bundleFlags: number, userId: number) : BundleInfo;

  export native function getApplicationInfoSync(bundleName: string, applicationFlags: number, userId: number): ApplicationInfo;

  export native function getAllBundleInfoSync(bundleFlags: number, userId: number): Array<BundleInfo>;

  export native function getAllApplicationInfoSync(appFlags: number, userId: number): Array<ApplicationInfo>;

  export native function isApplicationEnabledSyncInner(bundleName: string, appIndex: number): boolean;

  export native function queryAbilityInfoSyncInner(want: Want, abilityFlags: number, userId: number): Array<AbilityInfo>;

  export native function getAppCloneIdentitySync(uid: number): AppCloneIdentity;

  export native function getAbilityLabelSync(bundleName: string, moduleName: string, abilityName: string): string;

  export native function getLaunchWantForBundleSyncInner(bundleName: string, userId: number): Want;

  export native function getAppCloneBundleInfoInner(bundleName: string, appIndex: number,
    bundleFlags: number, userId: number): BundleInfo;

  export native function getSpecifiedDistributionType(bundleName: string): string;

  export native function getBundleNameByUidSync(uid: number): string;

  export native function isAbilityEnabledSyncInner(info: AbilityInfo, appIndex: number): boolean;

  export native function setAbilityEnabledSyncInner(info: AbilityInfo, isEnabled: boolean, appIndex: number): void;

  export native function setApplicationEnabledSyncInner(bundleName: string, isEnabled: boolean, appIndex: number): void;

  export native function getDynamicIconInner(bundleName: string): string;

  export native function queryAbilityInfoWithWants(wants: Array<Want>, abilityFlags: number,
    userId: number): Array<AbilityInfo>;

  export native function queryExtensionAbilityInfoInner(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityTypeName: string, extensionAbilityFlags: number,
    userId: number, isExtensionTypeName: boolean): Array<ExtensionAbilityInfo>;

  export native function queryExAbilityInfoSyncWithoutWant(extensionAbilityType: string, extensionAbilityFlags: number,
    userId: number): Array<ExtensionAbilityInfo>;

  function isApplicationEnabledSync(bundleName: string): boolean {
    return bundleManager.isApplicationEnabledSyncInner(bundleName, 0);
  }

  function queryAbilityInfoSync(want: Want, abilityFlags: number, userId?: number): Array<AbilityInfo> {
    let userIdInfo: number = userId ?? -500;
    return bundleManager.queryAbilityInfoSyncInner(want, abilityFlags, userIdInfo);
  }

  function getLaunchWantForBundleSync(bundleName: string, userId?: number): Want {
    let userIdInfo: number = userId ?? -500;
    return bundleManager.getLaunchWantForBundleSyncInner(bundleName, userIdInfo);
  }

  function isAbilityEnabledSync(info: AbilityInfo): boolean {
    return bundleManager.isAbilityEnabledSyncInner(info, 0);
  }

  function setAbilityEnabledSync(info: AbilityInfo, isEnabled: boolean): void {
    return bundleManager.setAbilityEnabledSyncInner(info, isEnabled, 0);
  }

  function setApplicationEnabledSync(bundleName: string, isEnabled: boolean): void {
    return bundleManager.setApplicationEnabledSyncInner(bundleName, isEnabled, 0);
  }

  function queryExtensionAbilityInfoSync(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: number, userId?: number): Array<ExtensionAbilityInfo> {
    let userIdInfo: number = userId ?? -500;
    return bundleManager.queryExtensionAbilityInfoInner(
      want, extensionAbilityType, "", extensionAbilityFlags, userIdInfo, false);
  }

  function queryExtensionAbilityInfoSync(want: Want, extensionAbilityType: string, extensionAbilityFlags: number,
    userId?: number): Array<ExtensionAbilityInfo> {
    let userIdInfo: number = userId ?? -500;
    return bundleManager.queryExtensionAbilityInfoInner(
      want, ExtensionAbilityType.UNSPECIFIED, extensionAbilityType, extensionAbilityFlags, userIdInfo, true);
  }

  function queryExtensionAbilityInfoSync(extensionAbilityType: string, extensionAbilityFlags: number,
    userId?: number): Array<ExtensionAbilityInfo> {
    let userIdInfo: number = userId ?? -500;
    return bundleManager.queryExAbilityInfoSyncWithoutWant(extensionAbilityType, extensionAbilityFlags, userIdInfo);
  }

  function getBundleInfoForSelf(bundleFlags: number, callback: AsyncCallback<BundleInfo, void>):void {
    let execFun = (): BundleInfo => {
      return bundleManager.getBundleInfoForSelfSync(bundleFlags);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      let r = new BusinessError();
      callback(r, resultBundleInfo);
    }, (err: BusinessError): void => {
      let resultBundleInfo = new BundleInfoInner();
      callback(err, resultBundleInfo);
    });
  }

  function getBundleInfoForSelf(bundleFlags: number):Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): BundleInfo => {
        return bundleManager.getBundleInfoForSelfSync(bundleFlags);
      };
      let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let resultBundleInfo: BundleInfo = e as BundleInfo;
          resolve(resultBundleInfo);
        }, (err: BusinessError): void => {
          reject(err);
        });
    }
    );
    return p;
  }

  function getBundleInfoSync(bundleName: string, bundleFlags: number): BundleInfo {
    return bundleManager.getBundleInfoSync(bundleName, bundleFlags, -500);
  }

  function getBundleInfo(bundleName: string, bundleFlags: number, userId?: number): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? -500;
      let execFun = (): BundleInfo => {
        return bundleManager.getBundleInfoSync(bundleName, bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultBundleInfo: BundleInfo = e as BundleInfo;
        resolve(resultBundleInfo);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getBundleInfo(bundleName: string, bundleFlags: number, callback: AsyncCallback<BundleInfo, void>): void {
    let execFun = (): BundleInfo => {
      return bundleManager.getBundleInfoSync(bundleName, bundleFlags);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      let r = new BusinessError();
      callback(r, resultBundleInfo);
    },(err: BusinessError): void => {
      let resultBundleInfo = new BundleInfoInner();
      callback(err, resultBundleInfo);
    });
  }

  function getBundleInfo(bundleName: string, bundleFlags: number, userId: number, callback: AsyncCallback<BundleInfo, void>): void {
    let execFun = (): BundleInfo => {
      return bundleManager.getBundleInfoSync(bundleName, bundleFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfo: BundleInfo = e as BundleInfo;
      let r = new BusinessError();
      callback(r, resultBundleInfo);
    },(err: BusinessError): void => {
      let resultBundleInfo = new BundleInfoInner();
      callback(err, resultBundleInfo);
    });
  }

  function getApplicationInfoSync(bundleName: string, applicationFlags: number): ApplicationInfo {
    return bundleManager.getApplicationInfoSync(bundleName, applicationFlags, -500);
  }

  function getAllBundleInfo(bundleFlags: number, userId?: number): Promise<Array<BundleInfo>> {
    let p = new Promise<Array<BundleInfo>>((resolve: (bundleInfos: Array<BundleInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? -500;
      let execFun = (): Array<BundleInfo> => {
        return bundleManager.getAllBundleInfoSync(bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
        resolve(resultBundleInfos);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getAllBundleInfo(bundleFlags: number, callback: AsyncCallback<Array<BundleInfo>>): void {
    let execFun = (): Array<BundleInfo> => {
      return bundleManager.getAllBundleInfoSync(bundleFlags, -500);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
      let r = new BusinessError();
      callback(r, resultBundleInfos);
    }, (err: BusinessError): void => {
      let resultBundleInfos = new Array<BundleInfo>;
      callback(err, resultBundleInfos);
    });
  }

  function getAllBundleInfo(bundleFlags: number, userId: number, callback: AsyncCallback<Array<BundleInfo>>): void {
    let execFun = (): Array<BundleInfo> => {
      return bundleManager.getAllBundleInfoSync(bundleFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultBundleInfos: Array<BundleInfo> = e as Array<BundleInfo>;
      let r = new BusinessError();
      callback(r, resultBundleInfos);
    }, (err: BusinessError): void => {
      let resultBundleInfos = new Array<BundleInfo>;
      callback(err, resultBundleInfos);
    });
  }

  function getAllApplicationInfo(appFlags: number, userId?: number): Promise<Array<ApplicationInfo>> {
    let p = new Promise<Array<ApplicationInfo>>((resolve: (applicationInfos: Array<ApplicationInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? -500;
      let execFun = (): Array<ApplicationInfo> => {
        return bundleManager.getAllApplicationInfoSync(appFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
        resolve(resultApplicationInfos);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getAllApplicationInfo(appFlags: number, callback: AsyncCallback<Array<ApplicationInfo>>): void {
    let execFun = (): Array<ApplicationInfo> => {
      return bundleManager.getAllApplicationInfoSync(appFlags, -500);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
      let r = new BusinessError();
      callback(r, resultApplicationInfos);
    }, (err: BusinessError): void => {
      let resultApplicationInfos = new Array<ApplicationInfo>;
      callback(err, resultApplicationInfos);
    });
  }

  function getAllApplicationInfo(appFlags: number, userId: number,
    callback: AsyncCallback<Array<ApplicationInfo>>): void {
    let execFun = (): Array<ApplicationInfo> => {
      return bundleManager.getAllApplicationInfoSync(appFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultApplicationInfos: Array<ApplicationInfo> = e as Array<ApplicationInfo>;
      let r = new BusinessError();
      callback(r, resultApplicationInfos);
    }, (err: BusinessError): void => {
      let resultApplicationInfos = new Array<ApplicationInfo>;
      callback(err, resultApplicationInfos);
    });
  }

  function isApplicationEnabled(bundleName: string, appIndex: number): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return bundleManager.isApplicationEnabledSyncInner(bundleName, appIndex);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let isEnabled: boolean = e as boolean;
        resolve(isEnabled);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function isApplicationEnabled(bundleName: string): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return bundleManager.isApplicationEnabledSyncInner(bundleName, 0);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let isEnabled: boolean = e as boolean;
        resolve(isEnabled);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function isApplicationEnabled(bundleName: string, callback: AsyncCallback<boolean>): void {
    let execFun = (): boolean => {
      return bundleManager.isApplicationEnabledSyncInner(bundleName, 0);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let isEnabled: boolean = e as boolean;
      let r = new BusinessError();
      callback(r, isEnabled);
    }, (err: BusinessError): void => {
      callback(err, false);
    });
  }

  function queryAbilityInfo(want: Want, abilityFlags: number, userId?: number): Promise<Array<AbilityInfo>> {
    let p = new Promise<Array<AbilityInfo>>((resolve: (abilityInfos: Array<AbilityInfo>)
      => void, reject: (error: BusinessError) => void) => {
        let userIdInfo: number = userId ?? -500;
      let execFun = (): Array<AbilityInfo> => {
        return bundleManager.queryAbilityInfoSyncInner(want, abilityFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
        resolve(resultAbilityInfos);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function queryAbilityInfo(want: Want, abilityFlags: number, callback: AsyncCallback<Array<AbilityInfo>>): void {
    let execFun = (): Array<AbilityInfo> => {
      return bundleManager.queryAbilityInfoSyncInner(want, abilityFlags, -500);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
      let r = new BusinessError();
      callback(r, resultAbilityInfos);
    }, (err: BusinessError): void => {
      let resultAbilityInfos = new Array<AbilityInfo>;
      callback(err, resultAbilityInfos);
    });
  }

  function queryAbilityInfo(want: Want,
    abilityFlags: number, userId: number, callback: AsyncCallback<Array<AbilityInfo>>): void {
    let execFun = (): Array<AbilityInfo> => {
      return bundleManager.queryAbilityInfoSyncInner(want, abilityFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
      let r = new BusinessError();
      callback(r, resultAbilityInfos);
    }, (err: BusinessError): void => {
      let resultAbilityInfos = new Array<AbilityInfo>;
      callback(err, resultAbilityInfos);
    });
  }

  function getApplicationInfo(bundleName: string, appFlags: number, userId?: number): Promise<ApplicationInfo> {
    let p = new Promise<ApplicationInfo>((
      resolve: (applicationInfo: ApplicationInfo) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? -500;
      let execFun = (): ApplicationInfo => {
        return bundleManager.getApplicationInfoSync(bundleName, appFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
        resolve(resultApplicationInfo);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getApplicationInfo(bundleName: string, appFlags: number, callback: AsyncCallback<ApplicationInfo>): void {
    let execFun = (): ApplicationInfo => {
      return bundleManager.getApplicationInfoSync(bundleName, appFlags);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
      let r = new BusinessError();
      callback(r, resultApplicationInfo);
    },(err: BusinessError): void => {
      let resultApplicationInfo = new ApplicationInfoInner();
      callback(err, resultApplicationInfo);
    });
  }

  function getApplicationInfo(bundleName: string,
    appFlags: number, userId: number, callback: AsyncCallback<ApplicationInfo>): void {
    let execFun = (): ApplicationInfo => {
      return bundleManager.getApplicationInfoSync(bundleName, appFlags, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let resultApplicationInfo: ApplicationInfo = e as ApplicationInfo;
      let r = new BusinessError();
      callback(r, resultApplicationInfo);
    },(err: BusinessError): void => {
      let resultApplicationInfo = new ApplicationInfoInner();
      callback(err, resultApplicationInfo);
    });
  }

  function getAppCloneIdentity(uid: number): Promise<AppCloneIdentity> {
    let p = new Promise<AppCloneIdentity>((
      resolve: (appCloneIdentity: AppCloneIdentity) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): AppCloneIdentity => {
        return bundleManager.getAppCloneIdentitySync(uid);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultAppCloneIdentity: AppCloneIdentity = e as AppCloneIdentity;
        resolve(resultAppCloneIdentity);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getAbilityLabel(bundleName: string, moduleName: string, abilityName: string): Promise<string> {
    let p = new Promise<string>((
      resolve: (label: string) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): string => {
        return bundleManager.getAbilityLabelSync(bundleName, moduleName, abilityName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let label: string = e as string;
        resolve(label);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getAbilityLabel(
    bundleName: string, moduleName: string, abilityName: string, callback: AsyncCallback<string>): void {
    let execFun = (): string => {
      return bundleManager.getAbilityLabelSync(bundleName, moduleName, abilityName);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let label: string = e as string;
      let r = new BusinessError();
      callback(r, label);
    },(err: BusinessError): void => {
      callback(err, "");
    });
  }

  function getLaunchWantForBundle(bundleName: string, userId?: number): Promise<Want> {
    let p = new Promise<Want>((
      resolve: (want: Want) => void, reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? -500;
      let execFun = (): Want => {
        return bundleManager.getLaunchWantForBundleSyncInner(bundleName, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let want: Want = e as Want;
        resolve(want);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getLaunchWantForBundle(bundleName: string, userId: number, callback: AsyncCallback<Want>): void {
    let execFun = (): Want => {
      return bundleManager.getLaunchWantForBundleSyncInner(bundleName, userId);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let want: Want = e as Want;
      let r = new BusinessError();
      callback(r, want);
    },(err: BusinessError): void => {
      let want : Want = {};
      callback(err, want);
    });
  }

  function getLaunchWantForBundle(bundleName: string, callback: AsyncCallback<Want>): void {
    let execFun = (): Want => {
      return bundleManager.getLaunchWantForBundleSyncInner(bundleName, -500);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let want: Want = e as Want;
      let r = new BusinessError();
      callback(r, want);
    },(err: BusinessError): void => {
      let want : Want = {};
      callback(err, want);
    });
  }

  function getAppCloneBundleInfo(bundleName: string, appIndex: number,
    bundleFlags: number, userId?: number): Promise<BundleInfo> {
    let p = new Promise<BundleInfo>((resolve: (bundleInfo: BundleInfo) => void,
      reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? -500;
      let execFun = (): BundleInfo => {
        return bundleManager.getAppCloneBundleInfoInner(bundleName, appIndex, bundleFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultBundleInfo: BundleInfo = e as BundleInfo;
        resolve(resultBundleInfo);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getBundleNameByUid(uid: number, callback: AsyncCallback<string>): void {
    let execFun = (): string => {
      return bundleManager.getBundleNameByUidSync(uid);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let result: string = e as string;
      let r = new BusinessError();
      callback(r, result);
    }).catch((err: BusinessError): void => {
      callback(err, "");
    });
  }

  function getBundleNameByUid(uid: number): Promise<string> {
    let p = new Promise<string>((resolve: (result: string) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): string => {
        return bundleManager.getBundleNameByUidSync(uid);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let result: string = e as string;
        resolve(result);
      }).catch((err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function queryExtensionAbilityInfo(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: number, callback: AsyncCallback<Array<ExtensionAbilityInfo>>): void {
    let execFun = (): Array<ExtensionAbilityInfo> => {
      return bundleManager.queryExtensionAbilityInfoInner(
        want, extensionAbilityType, "", extensionAbilityFlags, -500, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
      let r = new BusinessError();
      callback(r, extensionAbilityInfos);
    },(err: BusinessError): void => {
      let extensionAbilityInfos = new Array<ExtensionAbilityInfo>;
      callback(err, extensionAbilityInfos);
    });
  }

  function queryExtensionAbilityInfo(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: number, userId: number, callback: AsyncCallback<Array<ExtensionAbilityInfo>>): void {
    let execFun = (): Array<ExtensionAbilityInfo> => {
      return bundleManager.queryExtensionAbilityInfoInner(
        want, extensionAbilityType, "", extensionAbilityFlags, userId, false);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
      let r = new BusinessError();
      callback(r, extensionAbilityInfos);
    },(err: BusinessError): void => {
      let extensionAbilityInfos = new Array<ExtensionAbilityInfo>;
      callback(err, extensionAbilityInfos);
    });
  }

  function queryExtensionAbilityInfo(want: Want, extensionAbilityType: ExtensionAbilityType,
    extensionAbilityFlags: number, userId?: number): Promise<Array<ExtensionAbilityInfo>> {
    let p = new Promise<Array<ExtensionAbilityInfo>>((
      resolve: (extensionAbilityInfos: Array<ExtensionAbilityInfo>) => void,
      reject: (error: BusinessError) => void) => {
      let userIdInfo: number = userId ?? -500;
      let execFun = (): Array<ExtensionAbilityInfo> => {
        return bundleManager.queryExtensionAbilityInfoInner(
          want, extensionAbilityType, "", extensionAbilityFlags, userIdInfo, false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let extensionAbilityInfos: Array<ExtensionAbilityInfo> = e as Array<ExtensionAbilityInfo>;
        resolve(extensionAbilityInfos);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function isAbilityEnabled(info: AbilityInfo, appIndex: number): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return bundleManager.isAbilityEnabledSyncInner(info, appIndex);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let isEnabled: boolean = e as boolean;
        resolve(isEnabled);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function isAbilityEnabled(info: AbilityInfo): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (isEnabled: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return bundleManager.isAbilityEnabledSyncInner(info, 0);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let isEnabled: boolean = e as boolean;
        resolve(isEnabled);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function isAbilityEnabled(info: AbilityInfo, callback: AsyncCallback<boolean>): void {
    let execFun = (): boolean => {
      return bundleManager.isAbilityEnabledSyncInner(info, 0);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let isEnabled: boolean = e as boolean;
      let r = new BusinessError();
      callback(r, isEnabled);
    }, (err: BusinessError): void => {
      callback(err, false);
    });
  }

  function setAbilityEnabled(info: AbilityInfo, appIndex: number, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.setAbilityEnabledSyncInner(info, isEnabled, appIndex);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function setAbilityEnabled(info: AbilityInfo, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.setAbilityEnabledSyncInner(info, isEnabled, 0);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function setAbilityEnabled(info: AbilityInfo, isEnabled: boolean, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return bundleManager.setAbilityEnabledSyncInner(info, isEnabled, 0);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      let r = new BusinessError();
      callback(r, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  function setApplicationEnabled(bundleName: string, appIndex: number, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.setApplicationEnabledSyncInner(bundleName, isEnabled, appIndex);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function setApplicationEnabled(bundleName: string, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): void => {
        return bundleManager.setApplicationEnabledSyncInner(bundleName, isEnabled, 0);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function setApplicationEnabled(bundleName: string, isEnabled: boolean, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      return bundleManager.setApplicationEnabledSyncInner(bundleName, isEnabled, 0);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      let r = new BusinessError();
      callback(r, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  function getDynamicIcon(bundleName: string): Promise<string> {
    let p = new Promise<string>((
      resolve: (icon: string) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): string => {
        return bundleManager.getDynamicIconInner(bundleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let icon: string = e as string;
        resolve(icon);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function queryAbilityInfo(wants: Array<Want>, abilityFlags: number, userId?: number): Promise<Array<AbilityInfo>> {
    let p = new Promise<Array<AbilityInfo>>((resolve: (abilityInfos: Array<AbilityInfo>)
      => void, reject: (error: BusinessError) => void) => {
        let userIdInfo: number = userId ?? -500;
      let execFun = (): Array<AbilityInfo> => {
        return bundleManager.queryAbilityInfoWithWants(wants, abilityFlags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let resultAbilityInfos: Array<AbilityInfo> = e as Array<AbilityInfo>;
        resolve(resultAbilityInfos);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

}

export default bundleManager;

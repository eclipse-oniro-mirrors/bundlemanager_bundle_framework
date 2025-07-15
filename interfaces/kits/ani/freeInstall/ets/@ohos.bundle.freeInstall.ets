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

import { AsyncCallback, BusinessError } from '@ohos.base';
import { DispatchInfo as _DispatchInfo } from 'bundleManager.DispatchInfo';
import { BundlePackInfo as _BundlePackInfo, PackageConfig as _PackageConfig, PackageSummary as _PackageSummary,
  BundleConfigInfo as _BundleConfigInfo, ExtensionAbility as _ExtensionAbility, ModuleConfigInfo as _ModuleConfigInfo,
  ModuleDistroInfo as _ModuleDistroInfo, ModuleAbilityInfo as _ModuleAbilityInfo, AbilityFormInfo as _AbilityFormInfo,
  Version as _Version, ApiVersion as _ApiVersion } from 'bundleManager.BundlePackInfo';

namespace freeInstall {

  loadLibrary("ani_freeInstall.z");

  export enum UpgradeFlag {
    NOT_UPGRADE = 0,
    SINGLE_UPGRADE = 1,
    RELATION_UPGRADE = 2
  }

  export enum BundlePackFlag {
    GET_PACK_INFO_ALL = 0x00000000,
    GET_PACKAGES = 0x00000001,
    GET_BUNDLE_SUMMARY = 0x00000002,
    GET_MODULE_SUMMARY = 0x00000004
  }

  export native function setHapModuleUpgradeFlagNative(bundleName: string, moduleName: string, upgradeFlag: UpgradeFlag): void;
  export native function isHapModuleRemovableNative(bundleName: string, moduleName: string): boolean;
  export native function getBundlePackInfoNative(bundleName: string, bundlePackFlag: BundlePackFlag): BundlePackInfo;
  export native function getDispatchInfoNative(): DispatchInfo;

  function setHapModuleUpgradeFlag(bundleName: string, moduleName: string, upgradeFlag: UpgradeFlag, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      freeInstall.setHapModuleUpgradeFlagNative(bundleName, moduleName, upgradeFlag);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }).catch((err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setHapModuleUpgradeFlag(bundleName: string, moduleName: string, upgradeFlag: UpgradeFlag): Promise<void> {
    let p: Promise<void> = new Promise<void>((resolve: (v:PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        freeInstall.setHapModuleUpgradeFlagNative(bundleName, moduleName, upgradeFlag);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function isHapModuleRemovable(bundleName: string, moduleName: string, callback: AsyncCallback<boolean>): void {
    let execFun = (): boolean => {
      return freeInstall.isHapModuleRemovableNative(bundleName, moduleName);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let result: boolean = e as boolean;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function isHapModuleRemovable(bundleName: string, moduleName: string): Promise<boolean> {
    let p = new Promise<boolean>((resolve: (result: boolean) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): boolean => {
        return freeInstall.isHapModuleRemovableNative(bundleName, moduleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let result: boolean = e as boolean;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getBundlePackInfo(bundleName: string, bundlePackFlag: BundlePackFlag, callback: AsyncCallback<BundlePackInfo>): void {
    let execFun = (): BundlePackInfo => {
      return freeInstall.getBundlePackInfoNative(bundleName, bundlePackFlag);
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let result: BundlePackInfo = e as BundlePackInfo;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getBundlePackInfo(bundleName: string, bundlePackFlag: BundlePackFlag): Promise<BundlePackInfo> {
    let p = new Promise<BundlePackInfo>((resolve: (result: BundlePackInfo) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): BundlePackInfo => {
        return freeInstall.getBundlePackInfoNative(bundleName, bundlePackFlag);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let result: BundlePackInfo = e as BundlePackInfo;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getDispatchInfo(callback: AsyncCallback<DispatchInfo>): void {
    let execFun = (): DispatchInfo => {
      return freeInstall.getDispatchInfoNative();
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: Any) => {
      let result: DispatchInfo = e as DispatchInfo;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getDispatchInfo(): Promise<DispatchInfo> {
    let p = new Promise<DispatchInfo>((resolve: (result: DispatchInfo) => void, reject: (error: BusinessError) => void) => {
      let execFun = (): DispatchInfo => {
        return freeInstall.getDispatchInfoNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let result: DispatchInfo = e as DispatchInfo;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export type DispatchInfo = _DispatchInfo;
  export type BundlePackInfo = _BundlePackInfo;
  export type PackageConfig = _PackageConfig;
  export type PackageSummary = _PackageSummary;
  export type BundleConfigInfo = _BundleConfigInfo;
  export type ExtensionAbility = _ExtensionAbility;
  export type ModuleConfigInfo = _ModuleConfigInfo;
  export type ModuleDistroInfo = _ModuleDistroInfo;
  export type ModuleAbilityInfo = _ModuleAbilityInfo;
  export type AbilityFormInfo = _AbilityFormInfo;
  export type Version = _Version;
  export type ApiVersion = _ApiVersion;
}

export default freeInstall;

/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

/**
 * @file
 * @kit AbilityKit
 */

import { AsyncCallback, BusinessError } from '@ohos.base';
import { BundleResourceInfo } from 'bundleManager.BundleResourceInfo';
import { LauncherAbilityResourceInfo } from 'bundleManager.LauncherAbilityResourceInfo';
import bundleManager from '@ohos.bundle.bundleManager';

export default namespace bundleResourceManager {

  loadLibraryWithPermissionCheck("ani_bundle_res_manager.z", "@ohos.bundle.bundleResourceManager");

  const INVALID_VALUE: int = 0;

  enum ResourceFlag {
    GET_RESOURCE_INFO_ALL = 0x00000001,
    GET_RESOURCE_INFO_WITH_LABEL = 0x00000002,
    GET_RESOURCE_INFO_WITH_ICON = 0x00000004,
    GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL = 0x00000008,
    GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR = 0x00000010,
    GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY = 0x00000020
  }

  native function getBundleResourceInfoNative(bundleName: string, resourceFlags: int, appIndex: int): BundleResourceInfo;
  native function getLauncherAbilityResourceInfoNative(bundleName: string, resourceFlags: int, appIndex: int): Array<LauncherAbilityResourceInfo>;
  native function getAllBundleResourceInfoNative(resourceFlags: int): Array<BundleResourceInfo>;
  native function getAllLauncherAbilityResourceInfoNative(resourceFlags: int): Array<LauncherAbilityResourceInfo>;
  native function getExtensionAbilityResourceInfoNative(bundleName: string, extensionAbilityType: bundleManager.ExtensionAbilityType, resourceFlags: int, appIndex: int): Array<LauncherAbilityResourceInfo>;
  native function getAllUninstalledBundleResourceInfoNative(resourceFlags: int): Array<BundleResourceInfo>;

  function getBundleResourceInfo(bundleName: string, resourceFlags?: int, appIndex?: int): BundleResourceInfo
  {
    let resFlag = resourceFlags ?? INVALID_VALUE;
    let appIdx = appIndex ?? INVALID_VALUE;
    return getBundleResourceInfoNative(bundleName, resFlag, appIdx);
  }

  function getLauncherAbilityResourceInfo(bundleName: string, resourceFlags?: int, appIndex?: int): Array<LauncherAbilityResourceInfo>
  {
    let resFlag = resourceFlags ?? INVALID_VALUE;
    let appIdx = appIndex ?? INVALID_VALUE;
    return getLauncherAbilityResourceInfoNative(bundleName, resFlag, appIdx);
  }

  function getExtensionAbilityResourceInfo(bundleName: string, extensionAbilityType: bundleManager.ExtensionAbilityType, resourceFlags: int, appIndex?: int): Array<LauncherAbilityResourceInfo> {
    let appIdx = appIndex ?? INVALID_VALUE;
    return getExtensionAbilityResourceInfoNative(bundleName, extensionAbilityType, resourceFlags, appIdx);
  }

  function getAllBundleResourceInfo(resourceFlags: int, callback: AsyncCallback<Array<BundleResourceInfo>>): void {
    let cb = (): (Array<BundleResourceInfo>) => {
      return getAllBundleResourceInfoNative(resourceFlags);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let resultArray: Array<BundleResourceInfo> = e as Array<BundleResourceInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllBundleResourceInfo(resourceFlags: int): Promise<Array<BundleResourceInfo>> {
    let p = new Promise<Array<BundleResourceInfo>>((resolve: (arrBundleResourceInfo: Array<BundleResourceInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<BundleResourceInfo>) => {
        return getAllBundleResourceInfoNative(resourceFlags);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let resultArray: Array<BundleResourceInfo> = e as Array<BundleResourceInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getAllUninstalledBundleResourceInfo(resourceFlags: int): Promise<Array<BundleResourceInfo>> {
    let p = new Promise<Array<BundleResourceInfo>>((resolve: (arrBundleResourceInfo: Array<BundleResourceInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<BundleResourceInfo>) => {
        return getAllUninstalledBundleResourceInfoNative(resourceFlags);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let resultArray: Array<BundleResourceInfo> = e as Array<BundleResourceInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getAllLauncherAbilityResourceInfo(resourceFlags: int, callback: AsyncCallback<Array<LauncherAbilityResourceInfo>>): void {
    let cb = (): (Array<LauncherAbilityResourceInfo>) => {
      return getAllLauncherAbilityResourceInfoNative(resourceFlags);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let resultArray: Array<LauncherAbilityResourceInfo> = e as Array<LauncherAbilityResourceInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllLauncherAbilityResourceInfo(resourceFlags: int): Promise<Array<LauncherAbilityResourceInfo>> {
    let p = new Promise<Array<LauncherAbilityResourceInfo>>((resolve: (arrLauncherAbilityResourceInfo: Array<LauncherAbilityResourceInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<LauncherAbilityResourceInfo>) => {
        return getAllLauncherAbilityResourceInfoNative(resourceFlags);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let resultArray: Array<LauncherAbilityResourceInfo> = e as Array<LauncherAbilityResourceInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }
}
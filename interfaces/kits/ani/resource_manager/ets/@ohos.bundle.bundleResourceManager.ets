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

export default namespace bundleResourceManager {

  loadLibrary("ani_bundle_res_manager.z");

  const INVALID_INT: number = -500;

  enum ResourceFlag {
    GET_RESOURCE_INFO_ALL = 0x00000001,
    GET_RESOURCE_INFO_WITH_LABEL = 0x00000002,
    GET_RESOURCE_INFO_WITH_ICON = 0x00000004,
    GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL = 0x00000008,
    GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR = 0x00000010,
    GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY = 0x00000020
  }

  export native function getBundleResourceInfoNative(bundleName: string, resourceFlags: number, appIndex: number): BundleResourceInfo;
  export native function getLauncherAbilityResourceInfoNative(bundleName: string, resourceFlags: number, appIndex: number): Array<LauncherAbilityResourceInfo>;
  export native function getAllBundleResourceInfoNative(resourceFlags: number): Array<BundleResourceInfo>;
  export native function getAllLauncherAbilityResourceInfoNative(resourceFlags: number): Array<LauncherAbilityResourceInfo>;

  function getBundleResourceInfo(bundleName: string, resourceFlags?: number): BundleResourceInfo
  {
    let resFlag = resourceFlags ?? INVALID_INT;
    return bundleResourceManager.getBundleResourceInfoNative(bundleName, resFlag, INVALID_INT);
  }

  function getBundleResourceInfo(bundleName: string, resourceFlags?: number, appIndex?: number): BundleResourceInfo
  {
    let resFlag = resourceFlags ?? INVALID_INT;
    let appIdx = appIndex ?? INVALID_INT;
    return bundleResourceManager.getBundleResourceInfoNative(bundleName, resFlag, appIdx);
  }

  function getLauncherAbilityResourceInfo(bundleName: string, resourceFlags?: number): Array<LauncherAbilityResourceInfo>
  {
    let resFlag = resourceFlags ?? INVALID_INT;
    return bundleResourceManager.getLauncherAbilityResourceInfoNative(bundleName, resFlag, INVALID_INT);
  }

  function getLauncherAbilityResourceInfo(bundleName: string, resourceFlags?: number, appIndex?: number): Array<LauncherAbilityResourceInfo>
  {
    let resFlag = resourceFlags ?? INVALID_INT;
    let appIdx = appIndex ?? INVALID_INT;
    return bundleResourceManager.getLauncherAbilityResourceInfoNative(bundleName, resFlag, appIdx);
  }

  function getAllBundleResourceInfo(resourceFlags: number, callback: AsyncCallback<Array<BundleResourceInfo>>): void {
    let cb = (): (Array<BundleResourceInfo>) => {
      return bundleResourceManager.getAllBundleResourceInfoNative(resourceFlags);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<BundleResourceInfo> = e as Array<BundleResourceInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllBundleResourceInfo(resourceFlags: number): Promise<Array<BundleResourceInfo>> {
    let p = new Promise<Array<BundleResourceInfo>>((resolve: (arrBundleResourceInfo: Array<BundleResourceInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<BundleResourceInfo>) => {
        return bundleResourceManager.getAllBundleResourceInfoNative(resourceFlags);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<BundleResourceInfo> = e as Array<BundleResourceInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getAllLauncherAbilityResourceInfo(resourceFlags: number, callback: AsyncCallback<Array<LauncherAbilityResourceInfo>>): void {
    let cb = (): (Array<LauncherAbilityResourceInfo>) => {
      return bundleResourceManager.getAllLauncherAbilityResourceInfoNative(resourceFlags);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<LauncherAbilityResourceInfo> = e as Array<LauncherAbilityResourceInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllLauncherAbilityResourceInfo(resourceFlags: number): Promise<Array<LauncherAbilityResourceInfo>> {
    let p = new Promise<Array<LauncherAbilityResourceInfo>>((resolve: (arrLauncherAbilityResourceInfo: Array<LauncherAbilityResourceInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<LauncherAbilityResourceInfo>) => {
        return bundleResourceManager.getAllLauncherAbilityResourceInfoNative(resourceFlags);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<LauncherAbilityResourceInfo> = e as Array<LauncherAbilityResourceInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }
}
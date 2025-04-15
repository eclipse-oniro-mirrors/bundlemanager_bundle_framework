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
import { ShortcutInfo as _ShortcutInfo, ShortcutWant as _ShortcutWant, ParameterItem as _ParameterItem } from 'bundleManager.ShortcutInfo';
import { LauncherAbilityInfo } from 'bundleManager.LauncherAbilityInfo';

export default namespace launcherBundleManager {
  loadLibrary("ani_launcher_bundle_manager.z");

  export native function StartShortcutSync(shortcutInfo: ShortcutInfo): void;
  export native function GetShortcutInfoSync(bundleName: string, userId: number): Array<ShortcutInfo>;
  export native function GetLauncherAbilityInfoSync(bundleName: string, userId: number): Array<LauncherAbilityInfo>;
  export native function GetAllLauncherAbilityInfo(userId: number): Array<LauncherAbilityInfo>;

  function startShortcut(shortcutInfo: ShortcutInfo): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): NullishType => {
        launcherBundleManager.StartShortcutSync(shortcutInfo);
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }

  function getShortcutInfoSync(bundleName: string): Array<ShortcutInfo> {
    return launcherBundleManager.GetShortcutInfoSync(bundleName, -500);
  }

  function getShortcutInfoSync(bundleName: string, userId: number): Array<ShortcutInfo> {
    return launcherBundleManager.GetShortcutInfoSync(bundleName, userId);
  }

  function getShortcutInfo(bundleName: string, callback: AsyncCallback<Array<ShortcutInfo>>): void {
    let cb = (): (Array<ShortcutInfo>) => {
      return launcherBundleManager.GetShortcutInfoSync(bundleName, -500);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultShortcutInfo: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
      let br: BusinessError = new BusinessError();
      callback(br, resultShortcutInfo);
    }, (err: BusinessError): void => {
      let resultShortcutInfo: Array<ShortcutInfo> = new Array<ShortcutInfo>;
      callback(err, resultShortcutInfo);
    });
  }

  function getShortcutInfo(bundleName: string): Promise<Array<ShortcutInfo>> {
    let p = new Promise<Array<ShortcutInfo>>((resolve: (arrShortcutInfo: Array<ShortcutInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<ShortcutInfo>) => {
        return launcherBundleManager.GetShortcutInfoSync(bundleName, -500);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultShortcutInfo: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
        resolve(resultShortcutInfo);
      }, (err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }

  function getLauncherAbilityInfo(bundleName: string, userId: number, callback: AsyncCallback<Array<LauncherAbilityInfo>, void>): void {
    let cb = (): (Array<LauncherAbilityInfo>) => {
      return launcherBundleManager.GetLauncherAbilityInfoSync(bundleName, userId);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<LauncherAbilityInfo> = e as Array<LauncherAbilityInfo>;
      let br: BusinessError = new BusinessError();
      callback(br, resultArray);
    }, (err: BusinessError): void => {
      let resultArray: Array<LauncherAbilityInfo> = new Array<LauncherAbilityInfo>;
      callback(err, resultArray);
    });
  }

  function getLauncherAbilityInfo(bundleName: string, userId: number): Promise<Array<LauncherAbilityInfo>> {
    let p = new Promise<Array<LauncherAbilityInfo>>((resolve: (arrLauncherAbilityInfo: Array<LauncherAbilityInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<LauncherAbilityInfo>) => {
        return launcherBundleManager.GetLauncherAbilityInfoSync(bundleName, userId);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<LauncherAbilityInfo> = e as Array<LauncherAbilityInfo>;
        resolve(resultArray);
      }, (err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }

  function getLauncherAbilityInfoSync(bundleName: string, userId: number): Array<LauncherAbilityInfo> {
    return launcherBundleManager.GetLauncherAbilityInfoSync(bundleName, userId);
  }

  function getAllLauncherAbilityInfo(userId: number, callback: AsyncCallback<Array<LauncherAbilityInfo>, void>): void {
    let cb = (): (Array<LauncherAbilityInfo>) => {
      return launcherBundleManager.GetAllLauncherAbilityInfo(userId);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<LauncherAbilityInfo> = e as Array<LauncherAbilityInfo>;
      let br: BusinessError = new BusinessError();
      callback(br, resultArray);
    }, (err: BusinessError): void => {
      let resultArray: Array<LauncherAbilityInfo> = new Array<LauncherAbilityInfo>;
      callback(err, resultArray);
    });
  }

  function getAllLauncherAbilityInfo(userId: number): Promise<Array<LauncherAbilityInfo>>{
    let p = new Promise<Array<LauncherAbilityInfo>>((resolve: (arrLauncherAbilityInfo: Array<LauncherAbilityInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<LauncherAbilityInfo>) => {
        return launcherBundleManager.GetAllLauncherAbilityInfo(userId);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<LauncherAbilityInfo> = e as Array<LauncherAbilityInfo>;
        resolve(resultArray);
      }, (err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }

  export type ShortcutInfo = _ShortcutInfo;
  export type ShortcutWant = _ShortcutWant;
  export type ParameterItem = _ParameterItem;
}

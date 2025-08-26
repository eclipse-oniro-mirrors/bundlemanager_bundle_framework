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
import StartOptions from '@ohos.app.ability.StartOptions';

export default namespace launcherBundleManager {
  loadLibraryWithPermissionCheck("ani_launcher_bundle_manager.z", "@ohos.bundle.launcherBundleManager");

  const EMPTY_USER_ID: number = -500;

  export native function startShortcutNative(shortcutInfo: ShortcutInfo, options: StartOptions): void;
  export native function getShortcutInfoNative(bundleName: string, userId: number, isSync: boolean): Array<ShortcutInfo>;
  export native function getLauncherAbilityInfoNative(bundleName: string, userId: number, isSync: boolean): Array<LauncherAbilityInfo>;
  export native function getAllLauncherAbilityInfoNative(userId: number): Array<LauncherAbilityInfo>;

  function startShortcut(shortcutInfo: ShortcutInfo, options?: StartOptions): Promise<void> {
    let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void): void => {
      let startOptions : StartOptions = {};
      if (options != undefined) {
        startOptions = options;
      }
      let cb = (): NullishType => {
        launcherBundleManager.startShortcutNative(shortcutInfo, startOptions);
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getShortcutInfoSync(bundleName: string): Array<ShortcutInfo> {
    return launcherBundleManager.getShortcutInfoNative(bundleName, EMPTY_USER_ID, true);
  }

  function getShortcutInfoSync(bundleName: string, userId: number): Array<ShortcutInfo> {
    return launcherBundleManager.getShortcutInfoNative(bundleName, userId, true);
  }

  function getShortcutInfo(bundleName: string, callback: AsyncCallback<Array<ShortcutInfo>>): void {
    let cb = (): (Array<ShortcutInfo>) => {
      return launcherBundleManager.getShortcutInfoNative(bundleName, EMPTY_USER_ID, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultShortcutInfo: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
      callback(null, resultShortcutInfo);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getShortcutInfo(bundleName: string): Promise<Array<ShortcutInfo>> {
    let p = new Promise<Array<ShortcutInfo>>((resolve: (arrShortcutInfo: Array<ShortcutInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<ShortcutInfo>) => {
        return launcherBundleManager.getShortcutInfoNative(bundleName, EMPTY_USER_ID, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultShortcutInfo: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
        resolve(resultShortcutInfo);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getLauncherAbilityInfo(bundleName: string, userId: number, callback: AsyncCallback<Array<LauncherAbilityInfo>, void>): void {
    let cb = (): (Array<LauncherAbilityInfo>) => {
      return launcherBundleManager.getLauncherAbilityInfoNative(bundleName, userId, false);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<LauncherAbilityInfo> = e as Array<LauncherAbilityInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getLauncherAbilityInfo(bundleName: string, userId: number): Promise<Array<LauncherAbilityInfo>> {
    let p = new Promise<Array<LauncherAbilityInfo>>((resolve: (arrLauncherAbilityInfo: Array<LauncherAbilityInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<LauncherAbilityInfo>) => {
        return launcherBundleManager.getLauncherAbilityInfoNative(bundleName, userId, false);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<LauncherAbilityInfo> = e as Array<LauncherAbilityInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getLauncherAbilityInfoSync(bundleName: string, userId: number): Array<LauncherAbilityInfo> {
    return launcherBundleManager.getLauncherAbilityInfoNative(bundleName, userId, true);
  }

  function getAllLauncherAbilityInfo(userId: number, callback: AsyncCallback<Array<LauncherAbilityInfo>, void>): void {
    let cb = (): (Array<LauncherAbilityInfo>) => {
      return launcherBundleManager.getAllLauncherAbilityInfoNative(userId);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<LauncherAbilityInfo> = e as Array<LauncherAbilityInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getAllLauncherAbilityInfo(userId: number): Promise<Array<LauncherAbilityInfo>>{
    let p = new Promise<Array<LauncherAbilityInfo>>((resolve: (arrLauncherAbilityInfo: Array<LauncherAbilityInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<LauncherAbilityInfo>) => {
        return launcherBundleManager.getAllLauncherAbilityInfoNative(userId);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<LauncherAbilityInfo> = e as Array<LauncherAbilityInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export type ShortcutInfo = _ShortcutInfo;
  export type ShortcutWant = _ShortcutWant;
  export type ParameterItem = _ParameterItem;
}

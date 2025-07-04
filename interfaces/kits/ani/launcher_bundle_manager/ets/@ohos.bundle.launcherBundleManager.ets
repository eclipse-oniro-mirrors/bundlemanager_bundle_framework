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

import { BusinessError } from '@ohos.base';
import { ShortcutInfo as _ShortcutInfo, ShortcutWant as _ShortcutWant, ParameterItem as _ParameterItem } from 'bundleManager.ShortcutInfo';
import StartOptions from '@ohos.app.ability.StartOptions';

export default namespace launcherBundleManager {

  loadLibrary("ani_launcher_bundle_manager.z");

  const EMPTY_USER_ID: number = -500;

  export native function startShortcutNative(shortcutInfo: ShortcutInfo, options: StartOptions): void;
  export native function getShortcutInfoNative(bundleName: string, userId: number, isSync: boolean): Array<ShortcutInfo>;

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

  export type ShortcutInfo = _ShortcutInfo;
  export type ShortcutWant = _ShortcutWant;
  export type ParameterItem = _ParameterItem;
}

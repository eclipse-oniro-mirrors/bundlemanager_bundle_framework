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

import { ShortcutInfo as _ShortcutInfo, ShortcutWant as _ShortcutWant, ParameterItem as _ParameterItem } from 'bundleManager.ShortcutInfo';
import { BusinessError } from '@ohos.base';

namespace shortcutManager {

  loadLibrary("ani_shortcut_manager.z");

  export native function addDesktopShortcutInfoNative(shortcutInfo: ShortcutInfo, userId: number): void;
  export native function deleteDesktopShortcutInfoNative(shortcutInfo: ShortcutInfo, userId: number): void;
  export native function getAllDesktopShortcutInfoNative(userId: number): Array<ShortcutInfo>;

  function addDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: number): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): NullishType => {
        return shortcutManager.addDesktopShortcutInfoNative(shortcutInfo, userId);
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

  function deleteDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: number): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): NullishType => {
        return shortcutManager.deleteDesktopShortcutInfoNative(shortcutInfo, userId)
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

  function getAllDesktopShortcutInfo(userId: number): Promise<Array<ShortcutInfo>> {
    let p = new Promise<Array<ShortcutInfo>>((resolve: (arrShortcutInfo: Array<ShortcutInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<ShortcutInfo>) => {
        return shortcutManager.getAllDesktopShortcutInfoNative(userId);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let result: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
        resolve(result);
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

export default shortcutManager;

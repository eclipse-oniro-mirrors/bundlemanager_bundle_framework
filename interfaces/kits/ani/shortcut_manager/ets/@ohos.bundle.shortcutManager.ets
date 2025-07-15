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

  function createBusinessError(code: int, message: string) {
    let err = new BusinessError();
    err.code = code;
    err.name = 'Error';
    err.message = message;
    return err;
  }
  
  const ERROR_SOURCETYPE : int = -1;
  const MAIN_APP_INDEX: int = 0;
  const ERROR_PARAM_CHECK_ERROR: int = 401;
  const INVALID_SHORTCUT_INFO_ERROR: string = "invalid ShortcutInfo: parameter type error, or appIndex is less than 0";

  export native function addDesktopShortcutInfoNative(shortcutInfo: ShortcutInfo, userId: int): void;
  export native function deleteDesktopShortcutInfoNative(shortcutInfo: ShortcutInfo, userId: int): void;
  export native function getAllDesktopShortcutInfoNative(userId: int): Array<ShortcutInfo>;
  export native function setShortcutVisibleForSelfNative(id: string, visible: boolean): void;
  export native function getAllShortcutInfoForSelfNative(): Array<ShortcutInfo>;

  function addDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: int): Promise<void> {
    if (shortcutInfo.appIndex < MAIN_APP_INDEX || shortcutInfo?.sourceType === ERROR_SOURCETYPE) {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, INVALID_SHORTCUT_INFO_ERROR);
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): Any => {
        return shortcutManager.addDesktopShortcutInfoNative(shortcutInfo, userId);
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function deleteDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: int): Promise<void> {
    if (shortcutInfo.appIndex < MAIN_APP_INDEX || shortcutInfo.sourceType === ERROR_SOURCETYPE) {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, INVALID_SHORTCUT_INFO_ERROR);
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): Any => {
        return shortcutManager.deleteDesktopShortcutInfoNative(shortcutInfo, userId)
      }
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getAllDesktopShortcutInfo(userId: int): Promise<Array<ShortcutInfo>> {
    let p = new Promise<Array<ShortcutInfo>>((resolve: (arrShortcutInfo: Array<ShortcutInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<ShortcutInfo>) => {
        return shortcutManager.getAllDesktopShortcutInfoNative(userId);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let result: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function setShortcutVisibleForSelf(id: string, visible: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
      let cb = (): Any => {
        return shortcutManager.setShortcutVisibleForSelfNative(id, visible);
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

  function getAllShortcutInfoForSelf(): Promise<Array<ShortcutInfo>> {
    let p = new Promise<Array<ShortcutInfo>>((resolve: (arrShortcutInfo: Array<ShortcutInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<ShortcutInfo>) => {
        return shortcutManager.getAllShortcutInfoForSelfNative();
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
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

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

  loadLibrary("anishortcutmanager.z");

  export native function AddDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: number): void;

  export function addDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: number): Promise<void> {
    let p:Promise<void> = new Promise<void>((resolve:(v:undefined) =>void, reject: (error: Object) => void):void=> {
      let cb = ():NullishType=>{shortcutManager.AddDesktopShortcutInfo(shortcutInfo, userId);return undefined;}
      let p1 = taskpool.execute(cb);
      p1.then(():void =>  {
        resolve(undefined);
      }, (err: Object): void => {
        let br = err as BusinessError<void>;
        reject(br);
      });
    });
    return p;
  }

  export native function DeleteDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: number): void;

  export function deleteDesktopShortcutInfo(shortcutInfo: ShortcutInfo, userId: number): Promise<void> {
    let p:Promise<void> = new Promise<void>((resolve:(v:undefined) =>void, reject: (error: Object) => void):void=> {
      let cb = ():NullishType=>{shortcutManager.DeleteDesktopShortcutInfo(shortcutInfo, userId);return undefined;}
      let p1 = taskpool.execute(cb);
      p1.then(():void =>  {
        resolve(undefined);
      }, (err: Object): void => {
        let br = err as BusinessError<void>;
        reject(br);
      });
    });
    return p;
  }

  export native function GetAllDesktopShortcutInfo(userId: number): Array<ShortcutInfo>;

  export function getAllDesktopShortcutInfo(userId: number): Promise<Array<ShortcutInfo>> {
    let p = new Promise<Array<ShortcutInfo>>((resolve: (arrShortcutInfo: Array<ShortcutInfo>) => void, reject: (error: Object)=>void) => {
      let cb = ():(Array<ShortcutInfo>)=>{return shortcutManager.GetAllDesktopShortcutInfo(userId);};
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultShortcutInfo: Array<ShortcutInfo> = e as Array<ShortcutInfo>;
        resolve(resultShortcutInfo);
      }, (err: Object): void => {
        let br = err as BusinessError<void>;
        reject(br);
      });
    });
    return p;
  }

  export type ShortcutInfo = _ShortcutInfo;
  export type ShortcutWant = _ShortcutWant;
  export type ParameterItem = _ParameterItem;
}

export default shortcutManager;
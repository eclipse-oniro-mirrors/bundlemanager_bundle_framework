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

export default namespace launcherBundleManager {
    loadLibrary("ani_launcher_bundle_manager.z");

    export native function StartShortcutSync(shortcutInfo: ShortcutInfo): void;
    export native function GetShortcutInfoSync(bundleName: string, userId: number) : Array<ShortcutInfo>;

    function startShortcut(shortcutInfo: ShortcutInfo): Promise<void> {
      let p:Promise<void> = new Promise<void>((resolve:(v:undefined) =>void, reject: (error: Object) => void):void=> {
          let cb = ():NullishType=>{ launcherBundleManager.StartShortcutSync(shortcutInfo); }
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

    function getShortcutInfoSync(bundleName: string): Array<ShortcutInfo>{
      return launcherBundleManager.GetShortcutInfoSync(bundleName, -500);
    }

    function getShortcutInfoSync(bundleName: string, userId: number) : Array<ShortcutInfo> {
      return launcherBundleManager.GetShortcutInfoSync(bundleName, userId);
    }

  export type ShortcutInfo = _ShortcutInfo;
  export type ShortcutWant = _ShortcutWant;
  export type ParameterItem = _ParameterItem;
}

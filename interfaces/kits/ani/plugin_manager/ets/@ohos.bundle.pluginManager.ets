/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import { BusinessError } from '@ohos.base';
import { PluginBundleInfo } from 'bundleManager.PluginBundleInfo';

namespace pluginManager {
  loadLibraryWithPermissionCheck("ani_plugin_manager.z", "@ohos.bundle.pluginManager");

  native function getAllLocalPluginInfoForSelfNative(): Array<PluginBundleInfo>;

  function getAllLocalPluginInfoForSelf(): Promise<Array<PluginBundleInfo>> {
    let p = new Promise<Array<PluginBundleInfo>>((resolve: (pluginBundleInfo: Array<PluginBundleInfo>)
      => void, reject: (error: BusinessError) => void) => {
      let execFun = (): Array<PluginBundleInfo> => {
        return getAllLocalPluginInfoForSelfNative();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let pluginBundleInfo: Array<PluginBundleInfo> = e as Array<PluginBundleInfo>;
        resolve(pluginBundleInfo);
        }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }
}

export default pluginManager;

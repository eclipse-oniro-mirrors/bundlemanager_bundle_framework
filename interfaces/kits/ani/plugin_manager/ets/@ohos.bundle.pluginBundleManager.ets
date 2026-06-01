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

namespace pluginBundleManager {
  loadLibraryWithPermissionCheck("ani_plugin_bundle_manager.z", "@ohos.bundle.pluginBundleManager");

  native function installLocalPluginNative(pluginFilePaths: Array<string>): void;
  native function uninstallLocalPluginNative(pluginBundleName: string): void;

  function installLocalPlugin(pluginFilePaths: Array<string>): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
      reject: (error: BusinessError) => void): void => {
      let execFun = (): void => {
        installLocalPluginNative(pluginFilePaths);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function uninstallLocalPlugin(pluginBundleName: string): Promise<void> {
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
      reject: (error: BusinessError) => void): void => {
      let execFun = (): void => {
        uninstallLocalPluginNative(pluginBundleName);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }
}

export default pluginBundleManager;
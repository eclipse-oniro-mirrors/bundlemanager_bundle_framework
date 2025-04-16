/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

namespace installer {
  loadLibrary("ani_bundle_installer.z");

  function getBundleInstaller(callback: AsyncCallback<BundleInstaller>): void {
    let execFun = (): BundleInstaller => {
      return installer.getBundleInstallerSync();
    };
    let p1 = taskpool.execute(execFun);
    p1.then((e: NullishType) => {
      let installer: BundleInstaller = e as BundleInstaller;
      let r: BusinessError = { code: 0, name: "noerror", message: "noerror", data: undefined };
      callback(r, installer);
    }, (err: Object): void => {
    });
  }

  function getBundleInstaller(): Promise<BundleInstaller> {
    let p = new Promise<BundleInstaller>((resolve: (bundleInstaller: BundleInstaller) => void, reject: (error: Object) => void) => {
      let execFun = (): BundleInstaller => {
        return installer.getBundleInstallerSync();
      };
      let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let installer: BundleInstaller = e as BundleInstaller;
          resolve(installer);
        }, (err: Object): void => {
            let br = err as BusinessError<void>;
            reject(br);
        });
    });
    return p;
  }

  export native function getBundleInstallerSync(): BundleInstaller;

  interface BundleInstaller {
   
    install(hapFilePaths: Array<string>, installParam: InstallParam, callback: AsyncCallback<void>): void;

    install(hapFilePaths: Array<string>, callback: AsyncCallback<void>): void;
    
    install(hapFilePaths: Array<string>, installParam?: InstallParam): Promise<void>;

    uninstall(bundleName: string, installParam: InstallParam, callback: AsyncCallback<void>): void;
   
    uninstall(bundleName: string, callback: AsyncCallback<void>): void;

    uninstall(bundleName: string, installParam?: InstallParam): Promise<void>;

    recover(bundleName: string, installParam: InstallParam, callback: AsyncCallback<void>): void;

    recover(bundleName: string, callback: AsyncCallback<void>): void;

    recover(bundleName: string, installParam?: InstallParam): Promise<void>;

    uninstall(uninstallParam: UninstallParam, callback: AsyncCallback<void>): void;

    uninstall(uninstallParam: UninstallParam): Promise<void>;

    updateBundleForSelf(hapFilePaths: Array<string>, installParam: InstallParam, callback: AsyncCallback<void>): void;

    updateBundleForSelf(hapFilePaths: Array<string>, callback: AsyncCallback<void>): void;

    updateBundleForSelf(hapFilePaths: Array<string>, installParam?: InstallParam): Promise<void>;

    uninstallUpdates(bundleName: string, installParam?: InstallParam): Promise<void>;

    addExtResource(bundleName: string, filePaths: Array<string>): Promise<void>;

    removeExtResource(bundleName: string, moduleNames: Array<string>): Promise<void>;

    createAppClone(bundleName: string, createAppCloneParam?: CreateAppCloneParam): Promise<number>;

    destroyAppClone(bundleName: string, appIndex: number, options?: number | DestroyAppCloneParam): Promise<void>;

    installPreexistingApp(bundleName: string, userId?: number): Promise<void>;
  }

  export interface HashParam {
    moduleName: string;
    hashValue: string;
  }

  export interface PGOParam {
    moduleName: string;
    pgoFilePath: string;
  }

  export interface Parameters {
    key: string;
    value: string;
  }

  export interface InstallParam {
    userId?: number;
    installFlag?: number;
    isKeepData?: boolean;
    hashParams?: Array<HashParam>;
    crowdtestDeadline?: number;
    sharedBundleDirPaths?: Array<string>;
    specifiedDistributionType?: string;
    additionalInfo?: string;
    pgoParams?: Array<PGOParam>;
    parameters?: Array<Parameters>;
  }

  export interface UninstallParam {
    bundleName: string;
    versionCode?: number;
  }

  export interface CreateAppCloneParam {
    userId?: number;
    appIndex?: number;
  }

  export interface DestroyAppCloneParam {
    userId?: number;
    parameters?: Array<Parameters>;
  }

  export interface PluginParam {
    userId?: number;
    parameters?: Array<Parameters>;
  }
}

export default installer;

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

import { AsyncCallback, BusinessError } from '@ohos.base';
import installer from '@ohos.bundle.installer';

export class HashParamInner implements installer.HashParam {
  moduleName: string = "";
  hashValue: string = "";
}

export class PGOParamInner implements installer.PGOParam {
  moduleName: string = "";
  pgoFilePath: string = "";
}

export class ParametersInner implements installer.Parameters {
  key: string = "";
  value: string = "";
}

export class InstallParamInner implements installer.InstallParam {
  userId?: int;
  installFlag?: int;
  isKeepData?: boolean;
  hashParams?: Array<installer.HashParam>;
  crowdtestDeadline?: long;
  sharedBundleDirPaths?: Array<string>;
  specifiedDistributionType?: string;
  additionalInfo?: string;
  pgoParams?: Array<installer.PGOParam>;
  parameters?: Array<installer.Parameters>;
}

export class UninstallParamInner implements installer.UninstallParam {
  bundleName: string = "";
  versionCode?: int;
}

export class CreateAppCloneParamInner implements installer.CreateAppCloneParam {
  userId?: int;
  appIndex?: int;
}

export class DestroyAppCloneParamInner implements installer.DestroyAppCloneParam {
  userId?: int;
  parameters?: Array<installer.Parameters>;
  constructor() {
    super();
  }
  constructor(param: installer.DestroyAppCloneParam) {
    super();
    this.userId = param.userId;
    this.parameters = param.parameters;
  }
}

export class PluginParamInner implements installer.PluginParam {
  userId?: int;
  parameters?: Array<installer.Parameters>;
}

const UNSPECIFIED_USERID: int = -2;
const SPECIFIED_DISTRIBUTION_TYPE_MAX_SIZE : int = 128;
const ADDITIONAL_INFO_MAX_SIZE: int = 3000;
const ERROR_PARAM_CHECK_ERROR: int = 401;
const SPECIFIED_DISTRIBUTION_TYPE_ERROR: string = "BusinessError 401: The size of specifiedDistributionType is greater than 128";
const ADDITIONALINFO_ERROR: string = "BusinessError 401: The size of additionalInfo is greater than 3000";
const PARAMETERTYPE_ERROR: string = "BusinessError 401: Parameter error. The type of parameters must be corresponding type.";

function createBusinessError(code: int, message: string) {
  let err = new BusinessError();
  err.code = code;
  err.name = 'Error';
  err.message = message;
  return err;
}

function checkInstallParam(params: installer.InstallParam, needExtras: boolean): void {
  
  const hashParams = params.hashParams ?? new Array<installer.HashParam>;
  const moduleNameSet = new Set<string>();
  for (const hashParam of hashParams) {
    if (hashParam.moduleName === "" || hashParam.hashValue === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAMETERTYPE_ERROR);
    }
    if (moduleNameSet.has(hashParam.moduleName)) {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAMETERTYPE_ERROR);
    }
    moduleNameSet.add(hashParam.moduleName);
  }

  const pgoParams = params.pgoParams ?? new Array<installer.PGOParam>;
  for (const pgoParam of pgoParams) {
    if (pgoParam.moduleName === "" || pgoParam.pgoFilePath === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAMETERTYPE_ERROR);
    }
  }
  if (!needExtras) {
    return;
  }
  let specifiedDistributionType: string = params.specifiedDistributionType ?? "";
  if (specifiedDistributionType.length > SPECIFIED_DISTRIBUTION_TYPE_MAX_SIZE) {
    throw createBusinessError(ERROR_PARAM_CHECK_ERROR, SPECIFIED_DISTRIBUTION_TYPE_ERROR);
  }
  let additionalInfo: string = params.additionalInfo ?? "";
  if (additionalInfo.length > ADDITIONAL_INFO_MAX_SIZE) {
    throw createBusinessError(ERROR_PARAM_CHECK_ERROR, ADDITIONALINFO_ERROR);
  }
}

export class BundleInstallerInner implements installer.BundleInstaller {
  native installNative(hapFilePaths: Array<string>, installParam: installer.InstallParam): void;
  native uninstallNative(bundleName: string, installParam: installer.InstallParam): void;
  native recoverNative(bundleName: string, installParam: installer.InstallParam): void;
  native uninstallByOwnParamNative(uninstallParam: installer.UninstallParam): void;
  native updateBundleForSelfNative(hapFilePaths: Array<string>, installParam: installer.InstallParam): void;
  native uninstallUpdatesNative(bundleName: string, installParam: installer.InstallParam): void;
  native addExtResourceNative(bundleName: string, filePaths: Array<string>): void;
  native removeExtResourceNative(bundleName: string, moduleNames: Array<string>): void;
  native createAppCloneNative(bundleName: string, createAppCloneParam: installer.CreateAppCloneParam): int;
  native destroyAppCloneNative(bundleName: string, appIndex: int, options: installer.DestroyAppCloneParam): void;
  native installPreexistingAppNative(bundleName: string, userId: int): void;
  native installPluginNative(hostBundleName: string, pluginFilePaths: Array<string>, pluginParam: installer.PluginParam): void;
  native uninstallPluginNative(hostBundleName: string, pluginBundleName: string, pluginParam: installer.PluginParam): void;

  install(hapFilePaths: Array<string>, installParam?: installer.InstallParam): Promise<void> {
      if (installParam) {
        checkInstallParam(installParam, true);
      }
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.installNative(hapFilePaths, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  install(hapFilePaths: Array<string>, installParam: installer.InstallParam, callback: AsyncCallback<void>): void {
      checkInstallParam(installParam, true);
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.installNative(hapFilePaths, installParam); }
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  install(hapFilePaths: Array<string>, callback: AsyncCallback<void>): void {
      let emptyParam = new InstallParamInner();
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.installNative(hapFilePaths, emptyParam); }
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  uninstall(bundleName: string, installParam?: installer.InstallParam): Promise<void> {
      if (installParam) {
        checkInstallParam(installParam, false);
      }
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.uninstallNative(bundleName, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  uninstall(bundleName: string, installParam: installer.InstallParam, callback: AsyncCallback<void>): void {
      checkInstallParam(installParam, false);
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.uninstallNative(bundleName, installParam); }

          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  uninstall(bundleName: string, callback: AsyncCallback<void>): void {
      let emptyParam = new InstallParamInner();
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.uninstallNative(bundleName, emptyParam); }

          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  recover(bundleName: string, installParam?: installer.InstallParam): Promise<void> {
      if (installParam) {
        checkInstallParam(installParam, false);
      }
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.recoverNative(bundleName, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  recover(bundleName: string, installParam: installer.InstallParam, callback: AsyncCallback<void>): void {
      checkInstallParam(installParam, false);
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.recoverNative(bundleName, installParam); }

          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  recover(bundleName: string, callback: AsyncCallback<void>): void {
      let emptyParam = new InstallParamInner();
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.recoverNative(bundleName, emptyParam); }
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  uninstall(uninstallParam: installer.UninstallParam): Promise<void> {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.uninstallByOwnParamNative(uninstallParam); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  uninstall(uninstallParam: installer.UninstallParam, callback: AsyncCallback<void>): void {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.uninstallByOwnParamNative(uninstallParam); }
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  updateBundleForSelf(hapFilePaths: Array<string>, installParam?: installer.InstallParam): Promise<void> {
      if (installParam) {
        checkInstallParam(installParam, true);
      }
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.updateBundleForSelfNative(hapFilePaths, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  updateBundleForSelf(hapFilePaths: Array<string>, installParam: installer.InstallParam, callback: AsyncCallback<void>): void {
      checkInstallParam(installParam, true);
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.updateBundleForSelfNative(hapFilePaths, installParam); }
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  updateBundleForSelf(hapFilePaths: Array<string>, callback: AsyncCallback<void>): void {
      let emptyParam = new InstallParamInner();
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.updateBundleForSelfNative(hapFilePaths, emptyParam); }

          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              callback(null, undefined);
          }, (err: Error): void => {
              callback(err as BusinessError, undefined);
          });
      });
  }

  uninstallUpdates(bundleName: string, installParam?: installer.InstallParam): Promise<void> {
      if (installParam) {
        checkInstallParam(installParam, false);
      }
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.uninstallUpdatesNative(bundleName, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  addExtResource(bundleName: string, filePaths: Array<string>): Promise<void> {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.addExtResourceNative(bundleName, filePaths); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  removeExtResource(bundleName: string, moduleNames: Array<string>): Promise<void> {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.removeExtResourceNative(bundleName, moduleNames); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  createAppClone(bundleName: string, createAppCloneParam?: installer.CreateAppCloneParam): Promise<int> {
      let emptyParam = new CreateAppCloneParamInner();
      let params = createAppCloneParam ?? emptyParam;
      let p = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():int=>{ return this.createAppCloneNative(bundleName, params); }
      let p1 = taskpool.execute(execFun);
      p1.then((appIdx: NullishType) => {
          resolve(appIdx as int);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  destroyAppClone(bundleName: string, appIndex: int, options?: int | installer.DestroyAppCloneParam): Promise<void> {
      let defaultParam = new DestroyAppCloneParamInner();
      let option = options ?? defaultParam;
      if (option instanceof installer.DestroyAppCloneParam) {
        defaultParam = new DestroyAppCloneParamInner(option);
      } else if (typeof option === "number") {
        defaultParam.userId = option;
      }
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{
          this.destroyAppCloneNative(bundleName, appIndex, defaultParam);
      }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  installPreexistingApp(bundleName: string, userId?: int): Promise<void> {
      let userIdNum = userId ?? UNSPECIFIED_USERID;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.installPreexistingAppNative(bundleName, userIdNum); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
  }

  installPlugin(hostBundleName: string, pluginFilePaths: Array<string>, pluginParam?: installer.PluginParam): Promise<void> {
    let emptyParam = new PluginParamInner();
    let params = pluginParam ?? emptyParam;
    let p = new Promise<void> ((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
      let execFun = (): void => { return this.installPluginNative(hostBundleName, pluginFilePaths, params); }
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  uninstallPlugin(hostBundleName: string, pluginBundleName: string, pluginParam?: installer.PluginParam): Promise<void> {
    let emptyParam = new PluginParamInner();
    let params = pluginParam ?? emptyParam;
    let p = new Promise<void> ((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
      let execFun = (): void => { return this.uninstallPluginNative(hostBundleName, pluginBundleName, params); }
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }
}
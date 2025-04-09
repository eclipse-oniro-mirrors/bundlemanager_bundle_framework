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
  userId?: number;
  installFlag?: number;
  isKeepData?: boolean;
  hashParams?: Array<installer.HashParam>;
  crowdtestDeadline?: number;
  sharedBundleDirPaths?: Array<String>;
  specifiedDistributionType?: string;
  additionalInfo?: string;
  pgoParams?: Array<installer.PGOParam>;
  parameters?: Array<installer.Parameters>;
}

export class UninstallParamInner implements installer.UninstallParam {
  bundleName: string = "";
  versionCode?: number;
}

export class CreateAppCloneParamInner implements installer.CreateAppCloneParam {
  userId?: number;
  appIndex?: number;
}

export class DestroyAppCloneParamInner implements installer.DestroyAppCloneParam {
  userId?: number;
  parameters?: Array<installer.Parameters>;
}

export class PluginParamInner implements installer.PluginParam {
  userId?: number;
  parameters?: Array<installer.Parameters>;
}

export class BundleInstallerInner implements installer.BundleInstaller {
  native installNative(hapFilePaths: Array<string>, installParam: installer.InstallParam): void;
  native uninstallNative(bundleName: string, installParam: installer.InstallParam): void;
  native recoverNative(bundleName: string, installParam: installer.InstallParam): void;
  native uninstallByOwnParam(uninstallParam: installer.UninstallParam): void;
  native updateBundleForSelfNative(hapFilePaths: Array<string>, installParam: installer.InstallParam): void;
  native uninstallUpdatesNative(bundleName: string, installParam: installer.InstallParam): void;
  native addExtResourceNative(bundleName: string, filePaths: Array<string>): void;
  native removeExtResourceNative(bundleName: string, moduleNames: Array<string>): void;
  native createAppCloneNative(bundleName: string, createAppCloneParam: installer.CreateAppCloneParam): number;
  native destroyAppCloneNative(bundleName: string, appIndex: number, userId: number): void;
  native installPreexistingAppNative(bundleName: string, userId: number): void;
  
  install(hapFilePaths: Array<string>, installParam?: installer.InstallParam): Promise<void> {
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.installNative(hapFilePaths, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  install(hapFilePaths: Array<string>, installParam: installer.InstallParam, callback: AsyncCallback<void>): void {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.installNative(hapFilePaths, installParam); }
          
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  install(hapFilePaths: Array<string>, callback: AsyncCallback<void>): void {
      let emptyParam = new InstallParamInner();
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.installNative(hapFilePaths, emptyParam); }
          
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  uninstall(bundleName: string, installParam?: installer.InstallParam): Promise<void> {
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.uninstallNative(bundleName, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  uninstall(bundleName: string, installParam: installer.InstallParam, callback: AsyncCallback<void>): void {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.uninstallNative(bundleName, installParam); }
          
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  uninstall(bundleName: string, callback: AsyncCallback<void>): void {
      let emptyParam = new InstallParamInner();
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.uninstallNative(bundleName, emptyParam); }
          
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  recover(bundleName: string, installParam?: installer.InstallParam): Promise<void> {
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.recoverNative(bundleName, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  recover(bundleName: string, installParam: installer.InstallParam, callback: AsyncCallback<void>): void {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.recoverNative(bundleName, installParam); }
          
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  recover(bundleName: string, callback: AsyncCallback<void>): void {
      let emptyParam = new InstallParamInner();
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.recoverNative(bundleName, emptyParam); }
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  uninstall(uninstallParam: installer.UninstallParam): Promise<void> {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.uninstallByOwnParam(uninstallParam); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  uninstall(uninstallParam: installer.UninstallParam, callback: AsyncCallback<void>): void {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.uninstallByOwnParam(uninstallParam); }
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  updateBundleForSelf(hapFilePaths: Array<string>, installParam?: installer.InstallParam): Promise<void> {
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.updateBundleForSelfNative(hapFilePaths, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  updateBundleForSelf(hapFilePaths: Array<string>, installParam: installer.InstallParam, callback: AsyncCallback<void>): void {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.updateBundleForSelfNative(hapFilePaths, installParam); }
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  updateBundleForSelf(hapFilePaths: Array<string>, callback: AsyncCallback<void>): void {
      let emptyParam = new InstallParamInner();
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
          let execFun = ():NullishType=>{ this.updateBundleForSelfNative(hapFilePaths, emptyParam); }
          
          let p1 = taskpool.execute(execFun);
          p1.then(() => {
              let r = new BusinessError();
              callback(r, undefined);
          }, (err: BusinessError): void => {
              callback(err, undefined);
          });
      });
  }

  uninstallUpdates(bundleName: string, installParam?: installer.InstallParam): Promise<void> {
      let emptyParam = new InstallParamInner();
      let params = installParam ?? emptyParam;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.uninstallUpdatesNative(bundleName, params); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
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
        }, (err: BusinessError): void => {
          reject(err);
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
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  createAppClone(bundleName: string, createAppCloneParam?: installer.CreateAppCloneParam): Promise<number> {
      let emptyParam = new CreateAppCloneParamInner();
      let params = createAppCloneParam ?? emptyParam;
      let p = new Promise<number>((resolve: (v:number) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():number=>{ return this.createAppCloneNative(bundleName, emptyParam); }
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
          resolve(e as number);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  destroyAppClone(bundleName: string, appIndex: number, options?: number | installer.DestroyAppCloneParam): Promise<void> {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{}
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  installPreexistingApp(bundleName: string, userId?: number): Promise<void> {
      let userIdNum = userId ?? -500;
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{ this.installPreexistingAppNative(bundleName, userIdNum); }
      let p1 = taskpool.execute(execFun);
      p1.then(():void =>  {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  installPlugin(hostBundleName: string, pluginFilePaths: Array<string>, pluginParam?: installer.PluginParam): Promise<void> {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{}
      let p1 = taskpool.execute(execFun);
      p1.then(():void => {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }

  uninstallPlugin(hostBundleName: string, pluginBundleName: string, pluginParam?: installer.PluginParam): Promise<void> {
      let p = new Promise<void>((resolve: (v:undefined) => void, reject: (error: BusinessError) => void):void => {
      let execFun = ():NullishType=>{}
      let p1 = taskpool.execute(execFun);
      p1.then(():void => {
          resolve(undefined);
        }, (err: BusinessError): void => {
          reject(err);
        });
      });
      return p;
  }
}
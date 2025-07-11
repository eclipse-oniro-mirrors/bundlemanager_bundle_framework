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

/**
 * @file
 * @kit AbilityKit
 */

import { AsyncCallback, BusinessError } from '@ohos.base';
import { OverlayModuleInfo as _OverlayModuleInfo } from 'bundleManager.OverlayModuleInfo';

export default namespace overlay {

  loadLibrary("ani_overlay.z");

  export native function setOverlayEnabledNative(moduleName: string, isEnabled: boolean): void;
  export native function setOverlayEnabledByBundleNameNative(bundleName: string, moduleName: string, isEnabled: boolean): void;
  export native function getOverlayModuleInfoNative(moduleName: string): OverlayModuleInfo;
  export native function getTargetOverlayModuleInfosNative(targetModuleName: string): Array<OverlayModuleInfo>;
  export native function getOverlayModuleInfoByBundleNameNative(bundleName: string, moduleName: string): Array<OverlayModuleInfo>;
  export native function getTargetOverlayModuleInfosByBundleNameNative(targetBundleName: string, moduleName: string): Array<OverlayModuleInfo>;

  function setOverlayEnabled(moduleName: string, isEnabled: boolean, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return overlay.setOverlayEnabledNative(moduleName, isEnabled);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setOverlayEnabled(moduleName: string, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return overlay.setOverlayEnabledNative(moduleName, isEnabled);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setOverlayEnabledByBundleName(bundleName: string, moduleName: string, isEnabled: boolean, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return overlay.setOverlayEnabledByBundleNameNative(bundleName, moduleName, isEnabled);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setOverlayEnabledByBundleName(bundleName: string, moduleName: string, isEnabled: boolean): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return overlay.setOverlayEnabledByBundleNameNative(bundleName, moduleName, isEnabled);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getOverlayModuleInfo(moduleName: string, callback: AsyncCallback<OverlayModuleInfo>): void {
    let cb = (): OverlayModuleInfo => {
      return overlay.getOverlayModuleInfoNative(moduleName);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let result: OverlayModuleInfo = e as OverlayModuleInfo;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getOverlayModuleInfo(moduleName: string): Promise<OverlayModuleInfo> {
    let p = new Promise<OverlayModuleInfo>((resolve: (overlayModuleInfo: OverlayModuleInfo) => void, reject: (error: BusinessError) => void) => {
      let cb = (): OverlayModuleInfo => {
        return overlay.getOverlayModuleInfoNative(moduleName);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let result: OverlayModuleInfo = e as OverlayModuleInfo;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getTargetOverlayModuleInfos(targetModuleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    let cb = (): (Array<OverlayModuleInfo>) => {
      return overlay.getTargetOverlayModuleInfosNative(targetModuleName);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getTargetOverlayModuleInfos(targetModuleName: string): Promise<Array<OverlayModuleInfo>> {
    let p = new Promise<Array<OverlayModuleInfo>>((resolve: (arrOverlayModuleInfo: Array<OverlayModuleInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<OverlayModuleInfo>) => {
        return overlay.getTargetOverlayModuleInfosNative(targetModuleName);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getOverlayModuleInfoByBundleName(bundleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    let cb = (): (Array<OverlayModuleInfo>) => {
      return overlay.getOverlayModuleInfoByBundleNameNative(bundleName, '');
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getOverlayModuleInfoByBundleName(bundleName: string, moduleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    let cb = (): (Array<OverlayModuleInfo>) => {
      return overlay.getOverlayModuleInfoByBundleNameNative(bundleName, moduleName);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getOverlayModuleInfoByBundleName(bundleName: string, moduleName?: string): Promise<Array<OverlayModuleInfo>> {
    let moduleNameInfo: string = moduleName ?? '';
    let p = new Promise<Array<OverlayModuleInfo>>((resolve: (arrOverlayModuleInfo: Array<OverlayModuleInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<OverlayModuleInfo>) => {
        return overlay.getOverlayModuleInfoByBundleNameNative(bundleName, moduleNameInfo);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getTargetOverlayModuleInfosByBundleName(targetBundleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    let cb = (): (Array<OverlayModuleInfo>) => {
      return overlay.getTargetOverlayModuleInfosByBundleNameNative(targetBundleName, '');
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getTargetOverlayModuleInfosByBundleName(targetBundleName: string, moduleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    let cb = (): (Array<OverlayModuleInfo>) => {
      return overlay.getTargetOverlayModuleInfosByBundleNameNative(targetBundleName, moduleName);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getTargetOverlayModuleInfosByBundleName(targetBundleName: string, moduleName?: string): Promise<Array<OverlayModuleInfo>> {
    let moduleNameInfo: string = moduleName ?? '';
    let p = new Promise<Array<OverlayModuleInfo>>((resolve: (arrOverlayModuleInfo: Array<OverlayModuleInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<OverlayModuleInfo>) => {
        return overlay.getTargetOverlayModuleInfosByBundleNameNative(targetBundleName, moduleNameInfo);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export type OverlayModuleInfo = _OverlayModuleInfo;
}

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

  loadLibraryWithPermissionCheck("ani_overlay.z", "@ohos.bundle.overlay");

  const ERROR_PARAM_CHECK_ERROR: int = 401;
  const PARAM_MODULENAME_EMPTY_ERROR: string = "BusinessError 401: Parameter error. The type of moduleName must be string.";
  const PARAM_BUNDLENAME_EMPTY_ERROR: string = "BusinessError 401: Parameter error. The type of bundleName must be string.";
  const PARAM_TARGET_MODULENAME_EMPTY_ERROR: string = "BusinessError 401: Parameter error. The type of targetModuleName must be string.";
  const PARAM_TARGET_BUNDLENAME_EMPTY_ERROR: string = "BusinessError 401: Parameter error. The type of targetBundleName must be string.";

  function createBusinessError(code: int, message: string) {
    let err = new BusinessError();
    err.code = code;
    err.name = 'Error';
    err.message = message;
    return err;
  }

  native function setOverlayEnabledNative(moduleName: string, isEnabled: boolean): void;
  native function setOverlayEnabledByBundleNameNative(bundleName: string, moduleName: string, isEnabled: boolean): void;
  native function getOverlayModuleInfoNative(moduleName: string): OverlayModuleInfo;
  native function getTargetOverlayModuleInfosNative(targetModuleName: string): Array<OverlayModuleInfo>;
  native function getOverlayModuleInfoByBundleNameNative(bundleName: string, moduleName: string): Array<OverlayModuleInfo>;
  native function getTargetOverlayModuleInfosByBundleNameNative(targetBundleName: string, moduleName: string): Array<OverlayModuleInfo>;

  function setOverlayEnabled(moduleName: string, isEnabled: boolean, callback: AsyncCallback<void>): void {
    if (moduleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_MODULENAME_EMPTY_ERROR);
    }
    let cb = (): void => {
      return setOverlayEnabledNative(moduleName, isEnabled);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setOverlayEnabled(moduleName: string, isEnabled: boolean): Promise<void> {
    if (moduleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_MODULENAME_EMPTY_ERROR);
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return setOverlayEnabledNative(moduleName, isEnabled);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function setOverlayEnabledByBundleName(bundleName: string, moduleName: string, isEnabled: boolean, callback: AsyncCallback<void>): void {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
    }
    if (moduleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_MODULENAME_EMPTY_ERROR);
    }
    let cb = (): void => {
      return setOverlayEnabledByBundleNameNative(bundleName, moduleName, isEnabled);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      callback(null, undefined);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function setOverlayEnabledByBundleName(bundleName: string, moduleName: string, isEnabled: boolean): Promise<void> {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
    }
    if (moduleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_MODULENAME_EMPTY_ERROR);
    }
    let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return setOverlayEnabledByBundleNameNative(bundleName, moduleName, isEnabled);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    }
    );
    return p;
  }

  function getOverlayModuleInfo(moduleName: string, callback: AsyncCallback<OverlayModuleInfo>): void {
    if (moduleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_MODULENAME_EMPTY_ERROR);
    }
    let cb = (): OverlayModuleInfo => {
      return getOverlayModuleInfoNative(moduleName);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let result: OverlayModuleInfo = e as OverlayModuleInfo;
      callback(null, result);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getOverlayModuleInfo(moduleName: string): Promise<OverlayModuleInfo> {
    if (moduleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_MODULENAME_EMPTY_ERROR);
    }
    let p = new Promise<OverlayModuleInfo>((resolve: (overlayModuleInfo: OverlayModuleInfo) => void, reject: (error: BusinessError) => void) => {
      let cb = (): OverlayModuleInfo => {
        return getOverlayModuleInfoNative(moduleName);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let result: OverlayModuleInfo = e as OverlayModuleInfo;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getTargetOverlayModuleInfos(targetModuleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    if (targetModuleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_TARGET_MODULENAME_EMPTY_ERROR);
    }
    let cb = (): (Array<OverlayModuleInfo>) => {
      return getTargetOverlayModuleInfosNative(targetModuleName);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getTargetOverlayModuleInfos(targetModuleName: string): Promise<Array<OverlayModuleInfo>> {
    if (targetModuleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_TARGET_MODULENAME_EMPTY_ERROR);
    }
    let p = new Promise<Array<OverlayModuleInfo>>((resolve: (arrOverlayModuleInfo: Array<OverlayModuleInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<OverlayModuleInfo>) => {
        return getTargetOverlayModuleInfosNative(targetModuleName);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getOverlayModuleInfoByBundleName(bundleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
    }
    let cb = (): (Array<OverlayModuleInfo>) => {
      return getOverlayModuleInfoByBundleNameNative(bundleName, '');
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getOverlayModuleInfoByBundleName(bundleName: string, moduleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
    }
    let cb = (): (Array<OverlayModuleInfo>) => {
      return getOverlayModuleInfoByBundleNameNative(bundleName, moduleName);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getOverlayModuleInfoByBundleName(bundleName: string, moduleName?: string): Promise<Array<OverlayModuleInfo>> {
    if (bundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_BUNDLENAME_EMPTY_ERROR);
    }
    let moduleNameInfo: string = moduleName ?? '';
    let p = new Promise<Array<OverlayModuleInfo>>((resolve: (arrOverlayModuleInfo: Array<OverlayModuleInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<OverlayModuleInfo>) => {
        return getOverlayModuleInfoByBundleNameNative(bundleName, moduleNameInfo);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
        let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
        resolve(resultArray);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getTargetOverlayModuleInfosByBundleName(targetBundleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    if (targetBundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_TARGET_BUNDLENAME_EMPTY_ERROR);
    }
    let cb = (): (Array<OverlayModuleInfo>) => {
      return getTargetOverlayModuleInfosByBundleNameNative(targetBundleName, '');
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getTargetOverlayModuleInfosByBundleName(targetBundleName: string, moduleName: string, callback: AsyncCallback<Array<OverlayModuleInfo>>): void {
    if (targetBundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_TARGET_BUNDLENAME_EMPTY_ERROR);
    }
    let cb = (): (Array<OverlayModuleInfo>) => {
      return getTargetOverlayModuleInfosByBundleNameNative(targetBundleName, moduleName);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: Any) => {
      let resultArray: Array<OverlayModuleInfo> = e as Array<OverlayModuleInfo>;
      callback(null, resultArray);
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  function getTargetOverlayModuleInfosByBundleName(targetBundleName: string, moduleName?: string): Promise<Array<OverlayModuleInfo>> {
    if (targetBundleName === "") {
      throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_TARGET_BUNDLENAME_EMPTY_ERROR);
    }
    let moduleNameInfo: string = moduleName ?? '';
    let p = new Promise<Array<OverlayModuleInfo>>((resolve: (arrOverlayModuleInfo: Array<OverlayModuleInfo>) => void, reject: (error: BusinessError) => void) => {
      let cb = (): (Array<OverlayModuleInfo>) => {
        return getTargetOverlayModuleInfosByBundleNameNative(targetBundleName, moduleNameInfo);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: Any) => {
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

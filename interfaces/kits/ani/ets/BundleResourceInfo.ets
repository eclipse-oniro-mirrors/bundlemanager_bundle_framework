/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

// import { DrawableDescriptor } from './../@ohos.arkui.drawableDescriptor';

/**
 * Obtains resource information about a bundle
 *
 * @typedef BundleResourceInfo
 * @syscap SystemCapability.BundleManager.BundleFramework.Resource
 * @systemapi
 * @since 11
 */
export interface BundleResourceInfo {
  /**
   * Indicates the bundleName of this bundle
   *
   * @type { string }
   * @readonly
   * @syscap SystemCapability.BundleManager.BundleFramework.Resource
   * @systemapi
   * @since 11
   */
  readonly bundleName: string;

  /**
   * Indicates the icon of this bundle, which is base64 format
   *
   * @type { string }
   * @readonly
   * @syscap SystemCapability.BundleManager.BundleFramework.Resource
   * @systemapi
   * @since 11
   */
  readonly icon: string;

  /**
   * Indicates the label of this bundle
   *
   * @type { string }
   * @readonly
   * @syscap SystemCapability.BundleManager.BundleFramework.Resource
   * @systemapi
   * @since 11
   */
  readonly label: string;

//  /**
//   * Indicates the drawable descriptor of this bundle icon
//   *
//   * @type { DrawableDescriptor }
//   * @readonly
//   * @syscap SystemCapability.BundleManager.BundleFramework.Resource
//   * @systemapi
//   * @since 12
//   */
//  readonly drawableDescriptor: DrawableDescriptor;

  /**
   * Indicates the index of the bundle
   *
   * @type { number }
   * @readonly
   * @syscap SystemCapability.BundleManager.BundleFramework.Resource
   * @systemapi
   * @since 12
   */
  readonly appIndex: int;
}

class BundleResourceInfoInner implements BundleResourceInfo {
    readonly bundleName: string = '';
    readonly icon: string = '';
    readonly label: string = '';
    readonly appIndex: int;
}

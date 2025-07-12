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

import { AppProvisionInfo, Validity } from 'bundleManager.AppProvisionInfo'

export class AppProvisionInfoInner implements AppProvisionInfo {
  public readonly versionCode: long;
  public readonly versionName: string = '';
  public readonly uuid: string = '';
  public readonly type: string = '';
  public readonly appDistributionType: string = '';
  public readonly validity: Validity = new ValidityInner;
  public readonly developerId: string = '';
  public readonly certificate: string = '';
  public readonly apl: string = '';
  public readonly issuer: string = '';
  public readonly appIdentifier: string = '';
  public readonly organization: string = '';
}

export class ValidityInner implements Validity {
  public readonly notBefore: long;
  public readonly notAfter: long;
}

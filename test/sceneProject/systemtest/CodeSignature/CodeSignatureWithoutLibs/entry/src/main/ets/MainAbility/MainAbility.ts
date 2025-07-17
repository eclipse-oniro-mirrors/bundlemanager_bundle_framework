/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

import UIAbility from '@ohos.app.ability.UIAbility';
import window from '@ohos.window';
import Want from '@ohos.app.ability.Want';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';

export default class MainAbility extends UIAbility {
    onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
        // Ability is creating, initialize resources for this ability
        console.log("[Demo] MainAbility onCreate");
        globalThis.abilityWant = want;
    }

    onDestroy(): void {
        // Ability is destroying, release resources for this ability
        console.log("[Demo] MainAbility onDestroy");
    }

    onWindowStageCreate(windowStage: window.WindowStage): void {
        // Main window is created, set main page for this ability
        console.log("[Demo] MainAbility onWindowStageCreate");
        globalThis.abilityContext = this.context;
        windowStage.loadContent("pages/index/index", (err, data) => {
            if (err.code) {
                console.error('Failed to load the content. Cause: ' + JSON.stringify(err));
                return;
            }
            console.info('Succeeded in loading the content. Data: ' + JSON.stringify(data));
        });
    }

    onWindowStageDestroy(): void {
        //Main window is destroyed, release UI related resources
        console.log("[Demo] MainAbility onWindowStageDestroy");
    }

    onForeground(): void {
        // Ability has brought to foreground
        console.log("[Demo] MainAbility onForeground");
    }

    onBackground(): void {
        // Ability has back to background
        console.log("[Demo] MainAbility onBackground");
    }
}

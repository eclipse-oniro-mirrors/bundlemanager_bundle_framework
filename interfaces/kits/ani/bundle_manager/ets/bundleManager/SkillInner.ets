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

import { Skill, SkillUri } from 'bundleManager.Skill'

export class SkillInner implements Skill {
    readonly actions: Array<string> = new Array<string>;
    readonly entities: Array<string> = new Array<string>;
    readonly uris: Array<SkillUri> = new Array<SkillUri>;
    readonly domainVerify: boolean;

    constructor() { }
    constructor(actions: Array<string>, entities: Array<string>, uris: Array<SkillUri>, domainVerify: boolean) {
        this.actions = actions;
        this.entities = entities;
        this.uris = uris;
        this.domainVerify = domainVerify;
    }
}
  
export class SkillUriInner implements SkillUri {
    readonly scheme: string = "";
    readonly host: string = "";
    readonly port: string = "";
    readonly path: string = "";
    readonly pathStartWith: string = "";
    readonly pathRegex: string = "";
    readonly type: string = "";
    readonly utd: string = "";
    readonly maxFileSupported: int;
    readonly linkFeature: string = "";

    constructor() { }
    constructor(scheme: string,
        host: string,
        port: string,
        path: string,
        pathStartWith: string,
        pathRegex: string,
        type: string,
        utd: string,
        maxFileSupported: int,
        linkFeature: string) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.path = path;
            this.pathStartWith = pathStartWith;
            this.pathRegex = pathRegex;
            this.type = type;
            this.utd = utd;
            this.maxFileSupported = maxFileSupported;
            this.linkFeature = linkFeature;
    }
}

/// <reference types="@cloudflare/workers-types/2023-07-01" />
import { DurableObject } from 'cloudflare:workers';
import { Profile } from './Profile';
import { Env } from './ApiKeysEnv';
declare const _default: {
    fetch: (req: Request, env: Env) => Response | Promise<Response>;
};
export default _default;
export declare class ApiKeys extends DurableObject<Env> {
    #private;
    constructor(state: DurableObjectState, env: Env);
    fetch(req: Request): Promise<Response>;
    getProfile(): Profile | undefined;
    revoke(): Promise<void>;
}

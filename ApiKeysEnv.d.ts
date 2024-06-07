/// <reference types="@cloudflare/workers-types/2023-07-01" />
import Jwt from './worker';
import { ApiKeys } from './ApiKeys';
export interface Env {
    APIKEYS: DurableObjectNamespace<ApiKeys>;
    JWT: Service<Jwt>;
    ADMIN_IDS: string;
    SUPPORT_EMAIL: string;
}

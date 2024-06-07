/// <reference types="@cloudflare/workers-types/2023-07-01" />
import { ApiKeys } from './ApiKeys';
export interface Env {
    ADMIN_IDS: string;
    APIKEYS: DurableObjectNamespace<ApiKeys>;
    JWT_SECRET: string;
}

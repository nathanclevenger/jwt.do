import { ApiKeys } from './ApiKeys';

export interface Env {
  ADMIN_IDS: string;
  APIKEYS: DurableObjectNamespace<ApiKeys>;
  JWT_SECRET: string;
}

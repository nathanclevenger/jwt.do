/// <reference types="@cloudflare/workers-types/2023-07-01" />
import { WorkerEntrypoint } from 'cloudflare:workers';
import { Env } from './Env';
export default class extends WorkerEntrypoint<Env> {
    #private;
    fetch(req: Request): Promise<Response>;
    extractDomain({ hostname }: URL): string;
    /**
     * Generates a JWT
     * @param {string|undefined} params.secret The secret used to encode and verify the JWT
     * @param {string|undefined} params.issuer The identity of the JWT issuer
     * @param {string|undefined} params.expirationTTL The JWT expiration timestamp as a timespan string
     * @param {Object|undefined} params.claims Additional claims to include in the JWT payload
     * @returns A JWT generated from the query
     * @throws The JWT could not be generated from the query
     */
    generate({ secret, issuer, expirationTTL, audience, claims }?: {
        secret?: string;
        issuer?: string;
        expirationTTL?: string;
        audience?: string;
        claims?: any;
    }): Promise<string>;
    /**
     * Verifies a JWT
     * @param {string|undefined} params.token The JWT to be verified
     * @param {string|undefined} params.secret The secret used to encode and verify the JWT
     * @param {string|undefined} params.issuer The issuer of the JWT
     * @returns The decoded payload and header
     * @throws The JWT is not valid
     */
    verify({ token, secret, issuer }?: {
        token?: string;
        secret?: string;
        issuer?: string;
    }): Promise<import("jose").JWTVerifyResult<import("jose").JWTPayload>>;
}

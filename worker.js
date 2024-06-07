var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _instances, _json;
import { WorkerEntrypoint } from 'cloudflare:workers';
import { jwtVerify, SignJWT } from 'jose';
import { nanoid } from 'nanoid';
import qs from 'qs';
const api = {
    icon: '🚀',
    name: 'jwt.do',
    description: 'JWT Token Generation & Verification API',
    url: 'https://jwt.do/api',
    type: 'https://apis.do/security',
    endpoints: {
        generate: 'https://jwt.do/generate',
        verify: 'https://jwt.do/verify',
    },
    site: 'https://jwt.do',
    login: 'https://jwt.do/login',
    signup: 'https://jwt.do/signup',
    subscribe: 'https://jwt.do/subscribe',
    repo: 'https://github.com/drivly/jwt.do',
};
const gettingStarted = [`If you don't already have a JSON Viewer Browser Extension, get that first:`, `https://extensions.do`];
const examples = {
    generate: 'https://jwt.do/generate?profile[id]=1234&secret=secret&issuer=jwt.do&scope=user:read&expirationTTL=2h',
    verify: 'https://jwt.do/verify?token=:token&secret=secret&issuer=jwt.do',
};
class extends WorkerEntrypoint {
    constructor() {
        super(...arguments);
        _instances.add(this);
    }
    async fetch(req) {
        let user = { authenticated: false };
        try {
            const url = new URL(req.url);
            const query = (url.search && qs.parse(url.search.substring(1))) || {};
            let profile;
            let apikey = query.apikey;
            if (apikey) {
                delete query.apikey;
            }
            else {
                const auth = req.headers.get('authorization')?.split(' ');
                apikey = req.headers.get('x-api-key') || auth?.[1] || auth?.[0];
            }
            if (apikey) {
                const stubId = this.env.APIKEYS.idFromName(apikey);
                const stub = this.env.APIKEYS.get(stubId);
                profile = await stub.getProfile();
            }
            if (!profile) {
                const url = new URL(req.url);
                const issuer = this.extractDomain(url);
                const cookie = req.headers.get('cookie');
                const cookies = cookie && Object.fromEntries(cookie.split(';').map((c) => c.trim().split('=')));
                const token = cookies?.['__Secure-worker.auth.providers-token'];
                if (token) {
                    try {
                        const jwt = await this.verify({ token, secret: undefined, issuer });
                        ({ profile } = jwt.payload);
                    }
                    catch (error) {
                        console.error({ error });
                    }
                }
            }
            if (profile) {
                if (this.env.ADMIN_IDS?.split(',')?.includes(profile.id.toString())) {
                    profile.role = 'admin';
                }
                else if (profile.role === 'admin') {
                    delete profile.role;
                }
                user = { authenticated: true, ...profile };
            }
            else
                user = { authenticated: false };
            let { secret, issuer, expirationTTL, audience, token } = query;
            if (!issuer)
                issuer = this.extractDomain(new URL(req.url));
            if (url.pathname === '/generate') {
                return __classPrivateFieldGet(this, _instances, "m", _json).call(this, { api, token: await this.generate({ secret, issuer, expirationTTL, audience, claims: { profile } }), user });
            }
            else if (url.pathname === '/verify')
                return __classPrivateFieldGet(this, _instances, "m", _json).call(this, { api, jwt: await this.verify({ token, secret, issuer }), user });
            else
                return __classPrivateFieldGet(this, _instances, "m", _json).call(this, { api, gettingStarted, examples, user });
        }
        catch (error) {
            return __classPrivateFieldGet(this, _instances, "m", _json).call(this, { api, error, user }, 400);
        }
    }
    extractDomain({ hostname }) {
        return hostname.split(/\./).slice(-2).join('.');
    }
    /**
     * Generates a JWT
     * @param {string|undefined} params.secret The secret used to encode and verify the JWT
     * @param {string|undefined} params.issuer The identity of the JWT issuer
     * @param {string|undefined} params.expirationTTL The JWT expiration timestamp as a timespan string
     * @param {Object|undefined} params.claims Additional claims to include in the JWT payload
     * @returns A JWT generated from the query
     * @throws The JWT could not be generated from the query
     */
    async generate({ secret, issuer, expirationTTL, audience, claims = {} } = {}) {
        let signJwt = new SignJWT({ ...claims }).setProtectedHeader({ alg: 'HS256' }).setJti(nanoid()).setIssuedAt();
        if (issuer)
            signJwt = signJwt.setIssuer(issuer);
        if (audience)
            signJwt = signJwt.setAudience(audience);
        if (expirationTTL)
            signJwt = signJwt.setExpirationTime(expirationTTL.match(/^\d+$/) ? parseInt(expirationTTL) : expirationTTL);
        return await signJwt.sign(new Uint8Array(await crypto.subtle.digest('SHA-512', new TextEncoder().encode(secret?.replaceAll(' ', '+')))));
    }
    /**
     * Verifies a JWT
     * @param {string|undefined} params.token The JWT to be verified
     * @param {string|undefined} params.secret The secret used to encode and verify the JWT
     * @param {string|undefined} params.issuer The issuer of the JWT
     * @returns The decoded payload and header
     * @throws The JWT is not valid
     */
    async verify({ token, secret, issuer } = {}) {
        const hash = await crypto.subtle.digest('SHA-512', new TextEncoder().encode((secret || this.env.JWT_SECRET + issuer)?.replaceAll(' ', '+')));
        return await jwtVerify(token || '', new Uint8Array(hash), { issuer });
    }
}
_instances = new WeakSet(), _json = function _json(obj, status) {
    return new Response(JSON.stringify(obj, null, 2), { headers: { 'content-type': 'application/json; charset=utf-8' }, status });
};
export default default_1;

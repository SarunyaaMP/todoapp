import { i as building, b as base, j as private_env } from "./internal.js";
import { setEnvDefaults as setEnvDefaults$1, Auth, raw, skipCSRFCheck, isAuthAction } from "@auth/core";
import { D as DEV } from "./prod-ssr.js";
import { r as redirect } from "./index.js";
import { parse } from "set-cookie-parser";
import Github from "@auth/core/providers/github";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { p as prisma } from "./prisma.js";
const dev = DEV;
function setEnvDefaults(envObject, config) {
  if (building)
    return;
  setEnvDefaults$1(envObject, config);
  config.trustHost ??= dev;
  config.basePath = `${base}/auth`;
}
async function signIn$1(provider, options = {}, authorizationParams, config, event) {
  const { request } = event;
  const headers = new Headers(request.headers);
  const { redirect: shouldRedirect = true, redirectTo, ...rest } = options instanceof FormData ? Object.fromEntries(options) : options;
  const callbackUrl = redirectTo?.toString() ?? headers.get("Referer") ?? "/";
  const base2 = createActionURL("signin", headers, config.basePath);
  if (!provider) {
    const url2 = `${base2}?${new URLSearchParams({ callbackUrl })}`;
    if (shouldRedirect)
      redirect(302, url2);
    return url2;
  }
  let url = `${base2}/${provider}?${new URLSearchParams(authorizationParams)}`;
  let foundProvider = void 0;
  for (const _provider of config.providers) {
    const { id } = typeof _provider === "function" ? _provider() : _provider;
    if (id === provider) {
      foundProvider = id;
      break;
    }
  }
  if (!foundProvider) {
    const url2 = `${base2}?${new URLSearchParams({ callbackUrl })}`;
    if (shouldRedirect)
      redirect(302, url2);
    return url2;
  }
  if (foundProvider === "credentials") {
    url = url.replace("signin", "callback");
  }
  headers.set("Content-Type", "application/x-www-form-urlencoded");
  const body = new URLSearchParams({ ...rest, callbackUrl });
  const req = new Request(url, { method: "POST", headers, body });
  const res = await Auth(req, { ...config, raw, skipCSRFCheck });
  for (const c of res?.cookies ?? []) {
    event.cookies.set(c.name, c.value, { path: "/", ...c.options });
  }
  if (shouldRedirect) {
    return redirect(302, res.redirect);
  }
  return res.redirect;
}
async function signOut$1(options, config, event) {
  const { request } = event;
  const headers = new Headers(request.headers);
  headers.set("Content-Type", "application/x-www-form-urlencoded");
  const url = createActionURL("signout", headers, config.basePath);
  const callbackUrl = options?.redirectTo ?? headers.get("Referer") ?? "/";
  const body = new URLSearchParams({ callbackUrl });
  const req = new Request(url, { method: "POST", headers, body });
  const res = await Auth(req, { ...config, raw, skipCSRFCheck });
  for (const c of res?.cookies ?? [])
    event.cookies.set(c.name, c.value, { path: "/", ...c.options });
  if (options?.redirect ?? true)
    return redirect(302, res.redirect);
  return res;
}
async function auth(event, config) {
  setEnvDefaults(private_env, config);
  config.trustHost ??= true;
  const { request: req } = event;
  const sessionUrl = createActionURL("session", req.headers, config.basePath);
  const request = new Request(sessionUrl, {
    headers: { cookie: req.headers.get("cookie") ?? "" }
  });
  const response = await Auth(request, config);
  const authCookies = parse(response.headers.getSetCookie());
  for (const cookie of authCookies) {
    const { name, value, ...options } = cookie;
    event.cookies.set(name, value, { path: "/", ...options });
  }
  const { status = 200 } = response;
  const data = await response.json();
  if (!data || !Object.keys(data).length)
    return null;
  if (status === 200)
    return data;
  throw new Error(data.message);
}
function createActionURL(action, headers, basePath) {
  let url = private_env.AUTH_URL;
  if (!url) {
    const host = headers.get("x-forwarded-host") ?? headers.get("host");
    const proto = headers.get("x-forwarded-proto");
    url = `${proto === "http" || dev ? "http" : "https"}://${host}${basePath}`;
  }
  return new URL(`${url.replace(/\/$/, "")}/${action}`);
}
const authorizationParamsPrefix = "authorizationParams-";
function SvelteKitAuth(config) {
  return {
    signIn: async (event) => {
      const { request } = event;
      const _config = typeof config === "object" ? config : await config(event);
      setEnvDefaults(private_env, _config);
      const formData = await request.formData();
      const { providerId: provider, ...options } = Object.fromEntries(formData);
      let authorizationParams = {};
      let _options = {};
      for (const key in options) {
        if (key.startsWith(authorizationParamsPrefix)) {
          authorizationParams[key.slice(authorizationParamsPrefix.length)] = options[key];
        } else {
          _options[key] = options[key];
        }
      }
      await signIn$1(provider, _options, authorizationParams, _config, event);
    },
    signOut: async (event) => {
      const _config = typeof config === "object" ? config : await config(event);
      setEnvDefaults(private_env, _config);
      const options = Object.fromEntries(await event.request.formData());
      await signOut$1(options, _config, event);
    },
    async handle({ event, resolve }) {
      const _config = typeof config === "object" ? config : await config(event);
      setEnvDefaults(private_env, _config);
      const { url, request } = event;
      event.locals.auth ??= () => auth(event, _config);
      event.locals.getSession ??= event.locals.auth;
      const action = url.pathname.slice(
        // @ts-expect-error - basePath is defined in setEnvDefaults
        _config.basePath.length + 1
      ).split("/")[0];
      if (isAuthAction(action) && url.pathname.startsWith(_config.basePath + "/")) {
        return Auth(request, _config);
      }
      return resolve(event);
    }
  };
}
const GITHUB_ID = "e96b52d6098bc20dd687";
const GITHUB_SECRET = "a13cd9a6aaa6fe51b1717e4561e4eb2eef87a6be";
const { handle, signIn, signOut } = SvelteKitAuth({
  adapter: PrismaAdapter(prisma),
  providers: [
    Github({ clientId: GITHUB_ID, clientSecret: GITHUB_SECRET })
  ]
});
console.log("On hooks.server.ts", handle.name);
export {
  handle,
  signIn,
  signOut
};

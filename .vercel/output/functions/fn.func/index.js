globalThis.global = globalThis;
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __defNormalProp = (obj, key2, value) => key2 in obj ? __defProp(obj, key2, { enumerable: true, configurable: true, writable: true, value }) : obj[key2] = value;
var __require = /* @__PURE__ */ ((x2) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x2, {
  get: (a3, b3) => (typeof require !== "undefined" ? require : a3)[b3]
}) : x2)(function(x2) {
  if (typeof require !== "undefined")
    return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x2 + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key2 of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key2) && key2 !== except)
        __defProp(to, key2, { get: () => from[key2], enumerable: !(desc = __getOwnPropDesc(from, key2)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __publicField = (obj, key2, value) => {
  __defNormalProp(obj, typeof key2 !== "symbol" ? key2 + "" : key2, value);
  return value;
};
var __accessCheck = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet = (obj, member, getter) => {
  __accessCheck(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet = (obj, member, value, setter) => {
  __accessCheck(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};

// .svelte-kit/output/server/chunks/prod-ssr.js
var DEV;
var init_prod_ssr = __esm({
  ".svelte-kit/output/server/chunks/prod-ssr.js"() {
    DEV = false;
  }
});

// .svelte-kit/output/server/chunks/ssr.js
function noop() {
}
function run(fn) {
  return fn();
}
function blank_object() {
  return /* @__PURE__ */ Object.create(null);
}
function run_all(fns) {
  fns.forEach(run);
}
function safe_not_equal(a3, b3) {
  return a3 != a3 ? b3 == b3 : a3 !== b3 || a3 && typeof a3 === "object" || typeof a3 === "function";
}
function subscribe(store, ...callbacks) {
  if (store == null) {
    for (const callback2 of callbacks) {
      callback2(void 0);
    }
    return noop;
  }
  const unsub = store.subscribe(...callbacks);
  return unsub.unsubscribe ? () => unsub.unsubscribe() : unsub;
}
function set_current_component(component5) {
  current_component = component5;
}
function get_current_component() {
  if (!current_component)
    throw new Error("Function called outside component initialization");
  return current_component;
}
function setContext(key2, context) {
  get_current_component().$$.context.set(key2, context);
  return context;
}
function getContext(key2) {
  return get_current_component().$$.context.get(key2);
}
function ensure_array_like(array_like_or_iterator) {
  return array_like_or_iterator?.length !== void 0 ? array_like_or_iterator : Array.from(array_like_or_iterator);
}
function escape(value, is_attr = false) {
  const str = String(value);
  const pattern2 = is_attr ? ATTR_REGEX : CONTENT_REGEX;
  pattern2.lastIndex = 0;
  let escaped2 = "";
  let last = 0;
  while (pattern2.test(str)) {
    const i3 = pattern2.lastIndex - 1;
    const ch = str[i3];
    escaped2 += str.substring(last, i3) + (ch === "&" ? "&amp;" : ch === '"' ? "&quot;" : "&lt;");
    last = i3 + 1;
  }
  return escaped2 + str.substring(last);
}
function each(items, fn) {
  items = ensure_array_like(items);
  let str = "";
  for (let i3 = 0; i3 < items.length; i3 += 1) {
    str += fn(items[i3], i3);
  }
  return str;
}
function validate_component(component5, name) {
  if (!component5 || !component5.$$render) {
    if (name === "svelte:component")
      name += " this={...}";
    throw new Error(
      `<${name}> is not a valid SSR component. You may need to review your build config to ensure that dependencies are compiled, rather than imported as pre-compiled modules. Otherwise you may need to fix a <${name}>.`
    );
  }
  return component5;
}
function create_ssr_component(fn) {
  function $$render(result, props, bindings, slots, context) {
    const parent_component = current_component;
    const $$ = {
      on_destroy,
      context: new Map(context || (parent_component ? parent_component.$$.context : [])),
      // these will be immediately discarded
      on_mount: [],
      before_update: [],
      after_update: [],
      callbacks: blank_object()
    };
    set_current_component({ $$ });
    const html = fn(result, props, bindings, slots);
    set_current_component(parent_component);
    return html;
  }
  return {
    render: (props = {}, { $$slots = {}, context = /* @__PURE__ */ new Map() } = {}) => {
      on_destroy = [];
      const result = { title: "", head: "", css: /* @__PURE__ */ new Set() };
      const html = $$render(result, props, {}, $$slots, context);
      run_all(on_destroy);
      return {
        html,
        css: {
          code: Array.from(result.css).map((css) => css.code).join("\n"),
          map: null
          // TODO
        },
        head: result.title + result.head
      };
    },
    $$render
  };
}
function add_attribute(name, value, boolean) {
  if (value == null || boolean && !value)
    return "";
  const assignment = boolean && value === true ? "" : `="${escape(value, true)}"`;
  return ` ${name}${assignment}`;
}
var current_component, ATTR_REGEX, CONTENT_REGEX, missing_component, on_destroy;
var init_ssr = __esm({
  ".svelte-kit/output/server/chunks/ssr.js"() {
    ATTR_REGEX = /[&"]/g;
    CONTENT_REGEX = /[&<]/g;
    missing_component = {
      $$render: () => ""
    };
  }
});

// node_modules/@auth/core/lib/utils/cookie.js
function defaultCookies(useSecureCookies) {
  const cookiePrefix = useSecureCookies ? "__Secure-" : "";
  return {
    // default cookie options
    sessionToken: {
      name: `${cookiePrefix}authjs.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    callbackUrl: {
      name: `${cookiePrefix}authjs.callback-url`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    csrfToken: {
      // Default to __Host- for CSRF token for additional protection if using useSecureCookies
      // NB: The `__Host-` prefix is stricter than the `__Secure-` prefix.
      name: `${useSecureCookies ? "__Host-" : ""}authjs.csrf-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    pkceCodeVerifier: {
      name: `${cookiePrefix}authjs.pkce.code_verifier`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15
        // 15 minutes in seconds
      }
    },
    state: {
      name: `${cookiePrefix}authjs.state`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15
        // 15 minutes in seconds
      }
    },
    nonce: {
      name: `${cookiePrefix}authjs.nonce`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies
      }
    },
    webauthnChallenge: {
      name: `${cookiePrefix}authjs.challenge`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: useSecureCookies,
        maxAge: 60 * 15
        // 15 minutes in seconds
      }
    }
  };
}
var __classPrivateFieldSet, __classPrivateFieldGet, _SessionStore_instances, _SessionStore_chunks, _SessionStore_option, _SessionStore_logger, _SessionStore_chunk, _SessionStore_clean, ALLOWED_COOKIE_SIZE, ESTIMATED_EMPTY_COOKIE_SIZE, CHUNK_SIZE, SessionStore;
var init_cookie = __esm({
  "node_modules/@auth/core/lib/utils/cookie.js"() {
    __classPrivateFieldSet = function(receiver, state2, value, kind, f3) {
      if (kind === "m")
        throw new TypeError("Private method is not writable");
      if (kind === "a" && !f3)
        throw new TypeError("Private accessor was defined without a setter");
      if (typeof state2 === "function" ? receiver !== state2 || !f3 : !state2.has(receiver))
        throw new TypeError("Cannot write private member to an object whose class did not declare it");
      return kind === "a" ? f3.call(receiver, value) : f3 ? f3.value = value : state2.set(receiver, value), value;
    };
    __classPrivateFieldGet = function(receiver, state2, kind, f3) {
      if (kind === "a" && !f3)
        throw new TypeError("Private accessor was defined without a getter");
      if (typeof state2 === "function" ? receiver !== state2 || !f3 : !state2.has(receiver))
        throw new TypeError("Cannot read private member from an object whose class did not declare it");
      return kind === "m" ? f3 : kind === "a" ? f3.call(receiver) : f3 ? f3.value : state2.get(receiver);
    };
    ALLOWED_COOKIE_SIZE = 4096;
    ESTIMATED_EMPTY_COOKIE_SIZE = 160;
    CHUNK_SIZE = ALLOWED_COOKIE_SIZE - ESTIMATED_EMPTY_COOKIE_SIZE;
    SessionStore = class {
      constructor(option, cookies, logger2) {
        _SessionStore_instances.add(this);
        _SessionStore_chunks.set(this, {});
        _SessionStore_option.set(this, void 0);
        _SessionStore_logger.set(this, void 0);
        __classPrivateFieldSet(this, _SessionStore_logger, logger2, "f");
        __classPrivateFieldSet(this, _SessionStore_option, option, "f");
        if (!cookies)
          return;
        const { name: sessionCookiePrefix } = option;
        for (const [name, value] of Object.entries(cookies)) {
          if (!name.startsWith(sessionCookiePrefix) || !value)
            continue;
          __classPrivateFieldGet(this, _SessionStore_chunks, "f")[name] = value;
        }
      }
      /**
       * The JWT Session or database Session ID
       * constructed from the cookie chunks.
       */
      get value() {
        const sortedKeys = Object.keys(__classPrivateFieldGet(this, _SessionStore_chunks, "f")).sort((a3, b3) => {
          const aSuffix = parseInt(a3.split(".").pop() || "0");
          const bSuffix = parseInt(b3.split(".").pop() || "0");
          return aSuffix - bSuffix;
        });
        return sortedKeys.map((key2) => __classPrivateFieldGet(this, _SessionStore_chunks, "f")[key2]).join("");
      }
      /**
       * Given a cookie value, return new cookies, chunked, to fit the allowed cookie size.
       * If the cookie has changed from chunked to unchunked or vice versa,
       * it deletes the old cookies as well.
       */
      chunk(value, options2) {
        const cookies = __classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_clean).call(this);
        const chunked = __classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_chunk).call(this, {
          name: __classPrivateFieldGet(this, _SessionStore_option, "f").name,
          value,
          options: { ...__classPrivateFieldGet(this, _SessionStore_option, "f").options, ...options2 }
        });
        for (const chunk of chunked) {
          cookies[chunk.name] = chunk;
        }
        return Object.values(cookies);
      }
      /** Returns a list of cookies that should be cleaned. */
      clean() {
        return Object.values(__classPrivateFieldGet(this, _SessionStore_instances, "m", _SessionStore_clean).call(this));
      }
    };
    _SessionStore_chunks = /* @__PURE__ */ new WeakMap(), _SessionStore_option = /* @__PURE__ */ new WeakMap(), _SessionStore_logger = /* @__PURE__ */ new WeakMap(), _SessionStore_instances = /* @__PURE__ */ new WeakSet(), _SessionStore_chunk = function _SessionStore_chunk2(cookie) {
      const chunkCount = Math.ceil(cookie.value.length / CHUNK_SIZE);
      if (chunkCount === 1) {
        __classPrivateFieldGet(this, _SessionStore_chunks, "f")[cookie.name] = cookie.value;
        return [cookie];
      }
      const cookies = [];
      for (let i3 = 0; i3 < chunkCount; i3++) {
        const name = `${cookie.name}.${i3}`;
        const value = cookie.value.substr(i3 * CHUNK_SIZE, CHUNK_SIZE);
        cookies.push({ ...cookie, name, value });
        __classPrivateFieldGet(this, _SessionStore_chunks, "f")[name] = value;
      }
      __classPrivateFieldGet(this, _SessionStore_logger, "f").debug("CHUNKING_SESSION_COOKIE", {
        message: `Session cookie exceeds allowed ${ALLOWED_COOKIE_SIZE} bytes.`,
        emptyCookieSize: ESTIMATED_EMPTY_COOKIE_SIZE,
        valueSize: cookie.value.length,
        chunks: cookies.map((c3) => c3.value.length + ESTIMATED_EMPTY_COOKIE_SIZE)
      });
      return cookies;
    }, _SessionStore_clean = function _SessionStore_clean2() {
      const cleanedChunks = {};
      for (const name in __classPrivateFieldGet(this, _SessionStore_chunks, "f")) {
        delete __classPrivateFieldGet(this, _SessionStore_chunks, "f")?.[name];
        cleanedChunks[name] = {
          name,
          value: "",
          options: { ...__classPrivateFieldGet(this, _SessionStore_option, "f").options, maxAge: 0 }
        };
      }
      return cleanedChunks;
    };
  }
});

// node_modules/@auth/core/errors.js
function isClientError(error) {
  if (error instanceof AuthError)
    return clientErrors.has(error.type);
  return false;
}
var AuthError, SignInError, AdapterError, AccessDenied, CallbackRouteError, ErrorPageLoop, EventError, InvalidCallbackUrl, CredentialsSignin, InvalidEndpoints, InvalidCheck, JWTSessionError, MissingAdapter, MissingAdapterMethods, MissingAuthorize, MissingSecret, OAuthAccountNotLinked, OAuthCallbackError, OAuthProfileParseError, SessionTokenError, OAuthSignInError, EmailSignInError, SignOutError, UnknownAction, UnsupportedStrategy, InvalidProvider, UntrustedHost, Verification, MissingCSRF, clientErrors, DuplicateConditionalUI, MissingWebAuthnAutocomplete, WebAuthnVerificationError, AccountNotLinked, ExperimentalFeatureNotEnabled;
var init_errors = __esm({
  "node_modules/@auth/core/errors.js"() {
    AuthError = class extends Error {
      constructor(message2, errorOptions) {
        if (message2 instanceof Error) {
          super(void 0, {
            cause: { err: message2, ...message2.cause, ...errorOptions }
          });
        } else if (typeof message2 === "string") {
          if (errorOptions instanceof Error) {
            errorOptions = { err: errorOptions, ...errorOptions.cause };
          }
          super(message2, errorOptions);
        } else {
          super(void 0, message2);
        }
        this.name = this.constructor.name;
        this.type = this.constructor.type ?? "AuthError";
        this.kind = this.constructor.kind ?? "error";
        Error.captureStackTrace?.(this, this.constructor);
        const url = `https://errors.authjs.dev#${this.type.toLowerCase()}`;
        this.message += `${this.message ? " ." : ""}Read more at ${url}`;
      }
    };
    SignInError = class extends AuthError {
    };
    SignInError.kind = "signIn";
    AdapterError = class extends AuthError {
    };
    AdapterError.type = "AdapterError";
    AccessDenied = class extends AuthError {
    };
    AccessDenied.type = "AccessDenied";
    CallbackRouteError = class extends AuthError {
    };
    CallbackRouteError.type = "CallbackRouteError";
    ErrorPageLoop = class extends AuthError {
    };
    ErrorPageLoop.type = "ErrorPageLoop";
    EventError = class extends AuthError {
    };
    EventError.type = "EventError";
    InvalidCallbackUrl = class extends AuthError {
    };
    InvalidCallbackUrl.type = "InvalidCallbackUrl";
    CredentialsSignin = class extends SignInError {
      constructor() {
        super(...arguments);
        this.code = "credentials";
      }
    };
    CredentialsSignin.type = "CredentialsSignin";
    InvalidEndpoints = class extends AuthError {
    };
    InvalidEndpoints.type = "InvalidEndpoints";
    InvalidCheck = class extends AuthError {
    };
    InvalidCheck.type = "InvalidCheck";
    JWTSessionError = class extends AuthError {
    };
    JWTSessionError.type = "JWTSessionError";
    MissingAdapter = class extends AuthError {
    };
    MissingAdapter.type = "MissingAdapter";
    MissingAdapterMethods = class extends AuthError {
    };
    MissingAdapterMethods.type = "MissingAdapterMethods";
    MissingAuthorize = class extends AuthError {
    };
    MissingAuthorize.type = "MissingAuthorize";
    MissingSecret = class extends AuthError {
    };
    MissingSecret.type = "MissingSecret";
    OAuthAccountNotLinked = class extends SignInError {
    };
    OAuthAccountNotLinked.type = "OAuthAccountNotLinked";
    OAuthCallbackError = class extends SignInError {
    };
    OAuthCallbackError.type = "OAuthCallbackError";
    OAuthProfileParseError = class extends AuthError {
    };
    OAuthProfileParseError.type = "OAuthProfileParseError";
    SessionTokenError = class extends AuthError {
    };
    SessionTokenError.type = "SessionTokenError";
    OAuthSignInError = class extends SignInError {
    };
    OAuthSignInError.type = "OAuthSignInError";
    EmailSignInError = class extends SignInError {
    };
    EmailSignInError.type = "EmailSignInError";
    SignOutError = class extends AuthError {
    };
    SignOutError.type = "SignOutError";
    UnknownAction = class extends AuthError {
    };
    UnknownAction.type = "UnknownAction";
    UnsupportedStrategy = class extends AuthError {
    };
    UnsupportedStrategy.type = "UnsupportedStrategy";
    InvalidProvider = class extends AuthError {
    };
    InvalidProvider.type = "InvalidProvider";
    UntrustedHost = class extends AuthError {
    };
    UntrustedHost.type = "UntrustedHost";
    Verification = class extends AuthError {
    };
    Verification.type = "Verification";
    MissingCSRF = class extends SignInError {
    };
    MissingCSRF.type = "MissingCSRF";
    clientErrors = /* @__PURE__ */ new Set([
      "CredentialsSignin",
      "OAuthAccountNotLinked",
      "OAuthCallbackError",
      "AccessDenied",
      "Verification",
      "MissingCSRF",
      "AccountNotLinked",
      "WebAuthnVerificationError"
    ]);
    DuplicateConditionalUI = class extends AuthError {
    };
    DuplicateConditionalUI.type = "DuplicateConditionalUI";
    MissingWebAuthnAutocomplete = class extends AuthError {
    };
    MissingWebAuthnAutocomplete.type = "MissingWebAuthnAutocomplete";
    WebAuthnVerificationError = class extends AuthError {
    };
    WebAuthnVerificationError.type = "WebAuthnVerificationError";
    AccountNotLinked = class extends SignInError {
    };
    AccountNotLinked.type = "AccountNotLinked";
    ExperimentalFeatureNotEnabled = class extends AuthError {
    };
    ExperimentalFeatureNotEnabled.type = "ExperimentalFeatureNotEnabled";
  }
});

// node_modules/@auth/core/lib/utils/assert.js
function isValidHttpUrl(url, baseUrl) {
  try {
    return /^https?:/.test(new URL(url, url.startsWith("/") ? baseUrl : void 0).protocol);
  } catch {
    return false;
  }
}
function isSemverString(version) {
  return /^v\d+(?:\.\d+){0,2}$/.test(version);
}
function assertConfig(request, options2) {
  const { url } = request;
  const warnings = [];
  if (!warned && options2.debug)
    warnings.push("debug-enabled");
  if (!options2.trustHost) {
    return new UntrustedHost(`Host must be trusted. URL was: ${request.url}`);
  }
  if (!options2.secret) {
    return new MissingSecret("Please define a `secret`.");
  }
  const callbackUrlParam = request.query?.callbackUrl;
  if (callbackUrlParam && !isValidHttpUrl(callbackUrlParam, url.origin)) {
    return new InvalidCallbackUrl(`Invalid callback URL. Received: ${callbackUrlParam}`);
  }
  const { callbackUrl: defaultCallbackUrl } = defaultCookies(options2.useSecureCookies ?? url.protocol === "https:");
  const callbackUrlCookie = request.cookies?.[options2.cookies?.callbackUrl?.name ?? defaultCallbackUrl.name];
  if (callbackUrlCookie && !isValidHttpUrl(callbackUrlCookie, url.origin)) {
    return new InvalidCallbackUrl(`Invalid callback URL. Received: ${callbackUrlCookie}`);
  }
  let hasConditionalUIProvider = false;
  for (const p3 of options2.providers) {
    const provider = typeof p3 === "function" ? p3() : p3;
    if ((provider.type === "oauth" || provider.type === "oidc") && !(provider.issuer ?? provider.options?.issuer)) {
      const { authorization: a3, token: t2, userinfo: u3 } = provider;
      let key2;
      if (typeof a3 !== "string" && !a3?.url)
        key2 = "authorization";
      else if (typeof t2 !== "string" && !t2?.url)
        key2 = "token";
      else if (typeof u3 !== "string" && !u3?.url)
        key2 = "userinfo";
      if (key2) {
        return new InvalidEndpoints(`Provider "${provider.id}" is missing both \`issuer\` and \`${key2}\` endpoint config. At least one of them is required.`);
      }
    }
    if (provider.type === "credentials")
      hasCredentials = true;
    else if (provider.type === "email")
      hasEmail = true;
    else if (provider.type === "webauthn") {
      hasWebAuthn = true;
      if (provider.simpleWebAuthnBrowserVersion && !isSemverString(provider.simpleWebAuthnBrowserVersion)) {
        return new AuthError(`Invalid provider config for "${provider.id}": simpleWebAuthnBrowserVersion "${provider.simpleWebAuthnBrowserVersion}" must be a valid semver string.`);
      }
      if (provider.enableConditionalUI) {
        if (hasConditionalUIProvider) {
          return new DuplicateConditionalUI(`Multiple webauthn providers have 'enableConditionalUI' set to True. Only one provider can have this option enabled at a time.`);
        }
        hasConditionalUIProvider = true;
        const hasWebauthnFormField = Object.values(provider.formFields).some((f3) => f3.autocomplete && f3.autocomplete.toString().indexOf("webauthn") > -1);
        if (!hasWebauthnFormField) {
          return new MissingWebAuthnAutocomplete(`Provider "${provider.id}" has 'enableConditionalUI' set to True, but none of its formFields have 'webauthn' in their autocomplete param.`);
        }
      }
    }
  }
  if (hasCredentials) {
    const dbStrategy = options2.session?.strategy === "database";
    const onlyCredentials = !options2.providers.some((p3) => (typeof p3 === "function" ? p3() : p3).type !== "credentials");
    if (dbStrategy && onlyCredentials) {
      return new UnsupportedStrategy("Signing in with credentials only supported if JWT strategy is enabled");
    }
    const credentialsNoAuthorize = options2.providers.some((p3) => {
      const provider = typeof p3 === "function" ? p3() : p3;
      return provider.type === "credentials" && !provider.authorize;
    });
    if (credentialsNoAuthorize) {
      return new MissingAuthorize("Must define an authorize() handler to use credentials authentication provider");
    }
  }
  const { adapter, session: session2 } = options2;
  let requiredMethods = [];
  if (hasEmail || session2?.strategy === "database" || !session2?.strategy && adapter) {
    if (hasEmail) {
      if (!adapter)
        return new MissingAdapter("Email login requires an adapter.");
      requiredMethods.push(...emailMethods);
    } else {
      if (!adapter)
        return new MissingAdapter("Database session requires an adapter.");
      requiredMethods.push(...sessionMethods);
    }
  }
  if (hasWebAuthn) {
    if (options2.experimental?.enableWebAuthn) {
      warnings.push("experimental-webauthn");
    } else {
      return new ExperimentalFeatureNotEnabled("WebAuthn is an experimental feature. To enable it, set `experimental.enableWebAuthn` to `true` in your config.");
    }
    if (!adapter)
      return new MissingAdapter("WebAuthn requires an adapter.");
    requiredMethods.push(...webauthnMethods);
  }
  if (adapter) {
    const missing = requiredMethods.filter((m3) => !(m3 in adapter));
    if (missing.length) {
      return new MissingAdapterMethods(`Required adapter methods were missing: ${missing.join(", ")}`);
    }
  }
  if (!warned)
    warned = true;
  return warnings;
}
var warned, hasCredentials, hasEmail, hasWebAuthn, emailMethods, sessionMethods, webauthnMethods;
var init_assert = __esm({
  "node_modules/@auth/core/lib/utils/assert.js"() {
    init_cookie();
    init_errors();
    warned = false;
    hasCredentials = false;
    hasEmail = false;
    hasWebAuthn = false;
    emailMethods = [
      "createVerificationToken",
      "useVerificationToken",
      "getUserByEmail"
    ];
    sessionMethods = [
      "createUser",
      "getUser",
      "getUserByEmail",
      "getUserByAccount",
      "updateUser",
      "linkAccount",
      "createSession",
      "getSessionAndUser",
      "updateSession",
      "deleteSession"
    ];
    webauthnMethods = [
      "createUser",
      "getUser",
      "linkAccount",
      "getAccount",
      "getAuthenticator",
      "createAuthenticator",
      "listAuthenticatorsByUserId",
      "updateAuthenticatorCounter"
    ];
  }
});

// node_modules/@panva/hkdf/dist/web/runtime/hkdf.js
var getGlobal, hkdf_default;
var init_hkdf = __esm({
  "node_modules/@panva/hkdf/dist/web/runtime/hkdf.js"() {
    getGlobal = () => {
      if (typeof globalThis !== "undefined")
        return globalThis;
      if (typeof self !== "undefined")
        return self;
      if (typeof window !== "undefined")
        return window;
      throw new Error("unable to locate global object");
    };
    hkdf_default = async (digest2, ikm, salt, info, keylen) => {
      const { crypto: { subtle } } = getGlobal();
      return new Uint8Array(await subtle.deriveBits({
        name: "HKDF",
        hash: `SHA-${digest2.substr(3)}`,
        salt,
        info
      }, await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]), keylen << 3));
    };
  }
});

// node_modules/@panva/hkdf/dist/web/index.js
function normalizeDigest(digest2) {
  switch (digest2) {
    case "sha256":
    case "sha384":
    case "sha512":
    case "sha1":
      return digest2;
    default:
      throw new TypeError('unsupported "digest" value');
  }
}
function normalizeUint8Array(input, label) {
  if (typeof input === "string")
    return new TextEncoder().encode(input);
  if (!(input instanceof Uint8Array))
    throw new TypeError(`"${label}"" must be an instance of Uint8Array or a string`);
  return input;
}
function normalizeIkm(input) {
  const ikm = normalizeUint8Array(input, "ikm");
  if (!ikm.byteLength)
    throw new TypeError(`"ikm" must be at least one byte in length`);
  return ikm;
}
function normalizeInfo(input) {
  const info = normalizeUint8Array(input, "info");
  if (info.byteLength > 1024) {
    throw TypeError('"info" must not contain more than 1024 bytes');
  }
  return info;
}
function normalizeKeylen(input, digest2) {
  if (typeof input !== "number" || !Number.isInteger(input) || input < 1) {
    throw new TypeError('"keylen" must be a positive integer');
  }
  const hashlen = parseInt(digest2.substr(3), 10) >> 3 || 20;
  if (input > 255 * hashlen) {
    throw new TypeError('"keylen" too large');
  }
  return input;
}
async function hkdf(digest2, ikm, salt, info, keylen) {
  return hkdf_default(normalizeDigest(digest2), normalizeIkm(ikm), normalizeUint8Array(salt, "salt"), normalizeInfo(info), normalizeKeylen(keylen, digest2));
}
var init_web = __esm({
  "node_modules/@panva/hkdf/dist/web/index.js"() {
    init_hkdf();
  }
});

// node_modules/jose/dist/browser/runtime/webcrypto.js
var webcrypto_default, isCryptoKey;
var init_webcrypto = __esm({
  "node_modules/jose/dist/browser/runtime/webcrypto.js"() {
    webcrypto_default = crypto;
    isCryptoKey = (key2) => key2 instanceof CryptoKey;
  }
});

// node_modules/jose/dist/browser/runtime/digest.js
var digest, digest_default;
var init_digest = __esm({
  "node_modules/jose/dist/browser/runtime/digest.js"() {
    init_webcrypto();
    digest = async (algorithm, data) => {
      const subtleDigest = `SHA-${algorithm.slice(-3)}`;
      return new Uint8Array(await webcrypto_default.subtle.digest(subtleDigest, data));
    };
    digest_default = digest;
  }
});

// node_modules/jose/dist/browser/lib/buffer_utils.js
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf2 = new Uint8Array(size);
  let i3 = 0;
  for (const buffer of buffers) {
    buf2.set(buffer, i3);
    i3 += buffer.length;
  }
  return buf2;
}
function p2s(alg2, p2sInput) {
  return concat(encoder.encode(alg2), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf2, value, offset) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  }
  buf2.set([value >>> 24, value >>> 16, value >>> 8, value & 255], offset);
}
function uint64be(value) {
  const high = Math.floor(value / MAX_INT32);
  const low = value % MAX_INT32;
  const buf2 = new Uint8Array(8);
  writeUInt32BE(buf2, high, 0);
  writeUInt32BE(buf2, low, 4);
  return buf2;
}
function uint32be(value) {
  const buf2 = new Uint8Array(4);
  writeUInt32BE(buf2, value);
  return buf2;
}
function lengthAndInput(input) {
  return concat(uint32be(input.length), input);
}
async function concatKdf(secret, bits, value) {
  const iterations = Math.ceil((bits >> 3) / 32);
  const res = new Uint8Array(iterations * 32);
  for (let iter = 0; iter < iterations; iter++) {
    const buf2 = new Uint8Array(4 + secret.length + value.length);
    buf2.set(uint32be(iter + 1));
    buf2.set(secret, 4);
    buf2.set(value, 4 + secret.length);
    res.set(await digest_default("sha256", buf2), iter * 32);
  }
  return res.slice(0, bits >> 3);
}
var encoder, decoder, MAX_INT32;
var init_buffer_utils = __esm({
  "node_modules/jose/dist/browser/lib/buffer_utils.js"() {
    init_digest();
    encoder = new TextEncoder();
    decoder = new TextDecoder();
    MAX_INT32 = 2 ** 32;
  }
});

// node_modules/jose/dist/browser/runtime/base64url.js
var encodeBase64, encode, decodeBase64, decode;
var init_base64url = __esm({
  "node_modules/jose/dist/browser/runtime/base64url.js"() {
    init_buffer_utils();
    encodeBase64 = (input) => {
      let unencoded = input;
      if (typeof unencoded === "string") {
        unencoded = encoder.encode(unencoded);
      }
      const CHUNK_SIZE3 = 32768;
      const arr = [];
      for (let i3 = 0; i3 < unencoded.length; i3 += CHUNK_SIZE3) {
        arr.push(String.fromCharCode.apply(null, unencoded.subarray(i3, i3 + CHUNK_SIZE3)));
      }
      return btoa(arr.join(""));
    };
    encode = (input) => {
      return encodeBase64(input).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    };
    decodeBase64 = (encoded) => {
      const binary = atob(encoded);
      const bytes = new Uint8Array(binary.length);
      for (let i3 = 0; i3 < binary.length; i3++) {
        bytes[i3] = binary.charCodeAt(i3);
      }
      return bytes;
    };
    decode = (input) => {
      let encoded = input;
      if (encoded instanceof Uint8Array) {
        encoded = decoder.decode(encoded);
      }
      encoded = encoded.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
      try {
        return decodeBase64(encoded);
      } catch {
        throw new TypeError("The input to be decoded is not correctly encoded.");
      }
    };
  }
});

// node_modules/jose/dist/browser/util/errors.js
var JOSEError, JWTClaimValidationFailed, JWTExpired, JOSEAlgNotAllowed, JOSENotSupported, JWEDecryptionFailed, JWEInvalid, JWTInvalid, JWKInvalid;
var init_errors2 = __esm({
  "node_modules/jose/dist/browser/util/errors.js"() {
    JOSEError = class extends Error {
      static get code() {
        return "ERR_JOSE_GENERIC";
      }
      constructor(message2) {
        super(message2);
        this.code = "ERR_JOSE_GENERIC";
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
      }
    };
    JWTClaimValidationFailed = class extends JOSEError {
      static get code() {
        return "ERR_JWT_CLAIM_VALIDATION_FAILED";
      }
      constructor(message2, claim = "unspecified", reason = "unspecified") {
        super(message2);
        this.code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
        this.claim = claim;
        this.reason = reason;
      }
    };
    JWTExpired = class extends JOSEError {
      static get code() {
        return "ERR_JWT_EXPIRED";
      }
      constructor(message2, claim = "unspecified", reason = "unspecified") {
        super(message2);
        this.code = "ERR_JWT_EXPIRED";
        this.claim = claim;
        this.reason = reason;
      }
    };
    JOSEAlgNotAllowed = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JOSE_ALG_NOT_ALLOWED";
      }
      static get code() {
        return "ERR_JOSE_ALG_NOT_ALLOWED";
      }
    };
    JOSENotSupported = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JOSE_NOT_SUPPORTED";
      }
      static get code() {
        return "ERR_JOSE_NOT_SUPPORTED";
      }
    };
    JWEDecryptionFailed = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JWE_DECRYPTION_FAILED";
        this.message = "decryption operation failed";
      }
      static get code() {
        return "ERR_JWE_DECRYPTION_FAILED";
      }
    };
    JWEInvalid = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JWE_INVALID";
      }
      static get code() {
        return "ERR_JWE_INVALID";
      }
    };
    JWTInvalid = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JWT_INVALID";
      }
      static get code() {
        return "ERR_JWT_INVALID";
      }
    };
    JWKInvalid = class extends JOSEError {
      constructor() {
        super(...arguments);
        this.code = "ERR_JWK_INVALID";
      }
      static get code() {
        return "ERR_JWK_INVALID";
      }
    };
  }
});

// node_modules/jose/dist/browser/runtime/random.js
var random_default;
var init_random = __esm({
  "node_modules/jose/dist/browser/runtime/random.js"() {
    init_webcrypto();
    random_default = webcrypto_default.getRandomValues.bind(webcrypto_default);
  }
});

// node_modules/jose/dist/browser/lib/iv.js
function bitLength(alg2) {
  switch (alg2) {
    case "A128GCM":
    case "A128GCMKW":
    case "A192GCM":
    case "A192GCMKW":
    case "A256GCM":
    case "A256GCMKW":
      return 96;
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return 128;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg2}`);
  }
}
var iv_default;
var init_iv = __esm({
  "node_modules/jose/dist/browser/lib/iv.js"() {
    init_errors2();
    init_random();
    iv_default = (alg2) => random_default(new Uint8Array(bitLength(alg2) >> 3));
  }
});

// node_modules/jose/dist/browser/lib/check_iv_length.js
var checkIvLength, check_iv_length_default;
var init_check_iv_length = __esm({
  "node_modules/jose/dist/browser/lib/check_iv_length.js"() {
    init_errors2();
    init_iv();
    checkIvLength = (enc2, iv) => {
      if (iv.length << 3 !== bitLength(enc2)) {
        throw new JWEInvalid("Invalid Initialization Vector length");
      }
    };
    check_iv_length_default = checkIvLength;
  }
});

// node_modules/jose/dist/browser/runtime/check_cek_length.js
var checkCekLength, check_cek_length_default;
var init_check_cek_length = __esm({
  "node_modules/jose/dist/browser/runtime/check_cek_length.js"() {
    init_errors2();
    checkCekLength = (cek, expected) => {
      const actual = cek.byteLength << 3;
      if (actual !== expected) {
        throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
      }
    };
    check_cek_length_default = checkCekLength;
  }
});

// node_modules/jose/dist/browser/runtime/timing_safe_equal.js
var timingSafeEqual, timing_safe_equal_default;
var init_timing_safe_equal = __esm({
  "node_modules/jose/dist/browser/runtime/timing_safe_equal.js"() {
    timingSafeEqual = (a3, b3) => {
      if (!(a3 instanceof Uint8Array)) {
        throw new TypeError("First argument must be a buffer");
      }
      if (!(b3 instanceof Uint8Array)) {
        throw new TypeError("Second argument must be a buffer");
      }
      if (a3.length !== b3.length) {
        throw new TypeError("Input buffers must have the same length");
      }
      const len = a3.length;
      let out = 0;
      let i3 = -1;
      while (++i3 < len) {
        out |= a3[i3] ^ b3[i3];
      }
      return out === 0;
    };
    timing_safe_equal_default = timingSafeEqual;
  }
});

// node_modules/jose/dist/browser/lib/crypto_key.js
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}
function getHashLength(hash2) {
  return parseInt(hash2.name.slice(4), 10);
}
function checkUsage(key2, usages) {
  if (usages.length && !usages.some((expected) => key2.usages.includes(expected))) {
    let msg = "CryptoKey does not support this operation, its usages must include ";
    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(", ")}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }
    throw new TypeError(msg);
  }
}
function checkEncCryptoKey(key2, alg2, ...usages) {
  switch (alg2) {
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (!isAlgorithm(key2.algorithm, "AES-GCM"))
        throw unusable("AES-GCM");
      const expected = parseInt(alg2.slice(1, 4), 10);
      const actual = key2.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (!isAlgorithm(key2.algorithm, "AES-KW"))
        throw unusable("AES-KW");
      const expected = parseInt(alg2.slice(1, 4), 10);
      const actual = key2.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "ECDH": {
      switch (key2.algorithm.name) {
        case "ECDH":
        case "X25519":
        case "X448":
          break;
        default:
          throw unusable("ECDH, X25519, or X448");
      }
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW":
      if (!isAlgorithm(key2.algorithm, "PBKDF2"))
        throw unusable("PBKDF2");
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (!isAlgorithm(key2.algorithm, "RSA-OAEP"))
        throw unusable("RSA-OAEP");
      const expected = parseInt(alg2.slice(9), 10) || 1;
      const actual = getHashLength(key2.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key2, usages);
}
var init_crypto_key = __esm({
  "node_modules/jose/dist/browser/lib/crypto_key.js"() {
  }
});

// node_modules/jose/dist/browser/lib/invalid_key_input.js
function message(msg, actual, ...types2) {
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `one of type ${types2.join(", ")}, or ${last}.`;
  } else if (types2.length === 2) {
    msg += `one of type ${types2[0]} or ${types2[1]}.`;
  } else {
    msg += `of type ${types2[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor?.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
function withAlg(alg2, actual, ...types2) {
  return message(`Key for the ${alg2} algorithm must be `, actual, ...types2);
}
var invalid_key_input_default;
var init_invalid_key_input = __esm({
  "node_modules/jose/dist/browser/lib/invalid_key_input.js"() {
    invalid_key_input_default = (actual, ...types2) => {
      return message("Key must be ", actual, ...types2);
    };
  }
});

// node_modules/jose/dist/browser/runtime/is_key_like.js
var is_key_like_default, types;
var init_is_key_like = __esm({
  "node_modules/jose/dist/browser/runtime/is_key_like.js"() {
    init_webcrypto();
    is_key_like_default = (key2) => {
      return isCryptoKey(key2);
    };
    types = ["CryptoKey"];
  }
});

// node_modules/jose/dist/browser/runtime/decrypt.js
async function cbcDecrypt(enc2, cek, ciphertext, iv, tag, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(invalid_key_input_default(cek, "Uint8Array"));
  }
  const keySize = parseInt(enc2.slice(1, 4), 10);
  const encKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, ["decrypt"]);
  const macKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const expectedTag = new Uint8Array((await webcrypto_default.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
  let macCheckPassed;
  try {
    macCheckPassed = timing_safe_equal_default(tag, expectedTag);
  } catch {
  }
  if (!macCheckPassed) {
    throw new JWEDecryptionFailed();
  }
  let plaintext;
  try {
    plaintext = new Uint8Array(await webcrypto_default.subtle.decrypt({ iv, name: "AES-CBC" }, encKey, ciphertext));
  } catch {
  }
  if (!plaintext) {
    throw new JWEDecryptionFailed();
  }
  return plaintext;
}
async function gcmDecrypt(enc2, cek, ciphertext, iv, tag, aad) {
  let encKey;
  if (cek instanceof Uint8Array) {
    encKey = await webcrypto_default.subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  } else {
    checkEncCryptoKey(cek, enc2, "decrypt");
    encKey = cek;
  }
  try {
    return new Uint8Array(await webcrypto_default.subtle.decrypt({
      additionalData: aad,
      iv,
      name: "AES-GCM",
      tagLength: 128
    }, encKey, concat(ciphertext, tag)));
  } catch {
    throw new JWEDecryptionFailed();
  }
}
var decrypt, decrypt_default;
var init_decrypt = __esm({
  "node_modules/jose/dist/browser/runtime/decrypt.js"() {
    init_buffer_utils();
    init_check_iv_length();
    init_check_cek_length();
    init_timing_safe_equal();
    init_errors2();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    decrypt = async (enc2, cek, ciphertext, iv, tag, aad) => {
      if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalid_key_input_default(cek, ...types, "Uint8Array"));
      }
      if (!iv) {
        throw new JWEInvalid("JWE Initialization Vector missing");
      }
      if (!tag) {
        throw new JWEInvalid("JWE Authentication Tag missing");
      }
      check_iv_length_default(enc2, iv);
      switch (enc2) {
        case "A128CBC-HS256":
        case "A192CBC-HS384":
        case "A256CBC-HS512":
          if (cek instanceof Uint8Array)
            check_cek_length_default(cek, parseInt(enc2.slice(-3), 10));
          return cbcDecrypt(enc2, cek, ciphertext, iv, tag, aad);
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
          if (cek instanceof Uint8Array)
            check_cek_length_default(cek, parseInt(enc2.slice(1, 4), 10));
          return gcmDecrypt(enc2, cek, ciphertext, iv, tag, aad);
        default:
          throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
      }
    };
    decrypt_default = decrypt;
  }
});

// node_modules/jose/dist/browser/lib/is_disjoint.js
var isDisjoint, is_disjoint_default;
var init_is_disjoint = __esm({
  "node_modules/jose/dist/browser/lib/is_disjoint.js"() {
    isDisjoint = (...headers2) => {
      const sources = headers2.filter(Boolean);
      if (sources.length === 0 || sources.length === 1) {
        return true;
      }
      let acc;
      for (const header of sources) {
        const parameters = Object.keys(header);
        if (!acc || acc.size === 0) {
          acc = new Set(parameters);
          continue;
        }
        for (const parameter of parameters) {
          if (acc.has(parameter)) {
            return false;
          }
          acc.add(parameter);
        }
      }
      return true;
    };
    is_disjoint_default = isDisjoint;
  }
});

// node_modules/jose/dist/browser/lib/is_object.js
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isObject(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}
var init_is_object = __esm({
  "node_modules/jose/dist/browser/lib/is_object.js"() {
  }
});

// node_modules/jose/dist/browser/runtime/bogus.js
var bogusWebCrypto, bogus_default;
var init_bogus = __esm({
  "node_modules/jose/dist/browser/runtime/bogus.js"() {
    bogusWebCrypto = [
      { hash: "SHA-256", name: "HMAC" },
      true,
      ["sign"]
    ];
    bogus_default = bogusWebCrypto;
  }
});

// node_modules/jose/dist/browser/runtime/aeskw.js
function checkKeySize(key2, alg2) {
  if (key2.algorithm.length !== parseInt(alg2.slice(1, 4), 10)) {
    throw new TypeError(`Invalid key size for alg: ${alg2}`);
  }
}
function getCryptoKey(key2, alg2, usage) {
  if (isCryptoKey(key2)) {
    checkEncCryptoKey(key2, alg2, usage);
    return key2;
  }
  if (key2 instanceof Uint8Array) {
    return webcrypto_default.subtle.importKey("raw", key2, "AES-KW", true, [usage]);
  }
  throw new TypeError(invalid_key_input_default(key2, ...types, "Uint8Array"));
}
var wrap, unwrap;
var init_aeskw = __esm({
  "node_modules/jose/dist/browser/runtime/aeskw.js"() {
    init_bogus();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    wrap = async (alg2, key2, cek) => {
      const cryptoKey = await getCryptoKey(key2, alg2, "wrapKey");
      checkKeySize(cryptoKey, alg2);
      const cryptoKeyCek = await webcrypto_default.subtle.importKey("raw", cek, ...bogus_default);
      return new Uint8Array(await webcrypto_default.subtle.wrapKey("raw", cryptoKeyCek, cryptoKey, "AES-KW"));
    };
    unwrap = async (alg2, key2, encryptedKey) => {
      const cryptoKey = await getCryptoKey(key2, alg2, "unwrapKey");
      checkKeySize(cryptoKey, alg2);
      const cryptoKeyCek = await webcrypto_default.subtle.unwrapKey("raw", encryptedKey, cryptoKey, "AES-KW", ...bogus_default);
      return new Uint8Array(await webcrypto_default.subtle.exportKey("raw", cryptoKeyCek));
    };
  }
});

// node_modules/jose/dist/browser/runtime/ecdhes.js
async function deriveKey(publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) {
  if (!isCryptoKey(publicKey)) {
    throw new TypeError(invalid_key_input_default(publicKey, ...types));
  }
  checkEncCryptoKey(publicKey, "ECDH");
  if (!isCryptoKey(privateKey)) {
    throw new TypeError(invalid_key_input_default(privateKey, ...types));
  }
  checkEncCryptoKey(privateKey, "ECDH", "deriveBits");
  const value = concat(lengthAndInput(encoder.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
  let length;
  if (publicKey.algorithm.name === "X25519") {
    length = 256;
  } else if (publicKey.algorithm.name === "X448") {
    length = 448;
  } else {
    length = Math.ceil(parseInt(publicKey.algorithm.namedCurve.substr(-3), 10) / 8) << 3;
  }
  const sharedSecret = new Uint8Array(await webcrypto_default.subtle.deriveBits({
    name: publicKey.algorithm.name,
    public: publicKey
  }, privateKey, length));
  return concatKdf(sharedSecret, keyLength, value);
}
async function generateEpk(key2) {
  if (!isCryptoKey(key2)) {
    throw new TypeError(invalid_key_input_default(key2, ...types));
  }
  return webcrypto_default.subtle.generateKey(key2.algorithm, true, ["deriveBits"]);
}
function ecdhAllowed(key2) {
  if (!isCryptoKey(key2)) {
    throw new TypeError(invalid_key_input_default(key2, ...types));
  }
  return ["P-256", "P-384", "P-521"].includes(key2.algorithm.namedCurve) || key2.algorithm.name === "X25519" || key2.algorithm.name === "X448";
}
var init_ecdhes = __esm({
  "node_modules/jose/dist/browser/runtime/ecdhes.js"() {
    init_buffer_utils();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
  }
});

// node_modules/jose/dist/browser/lib/check_p2s.js
function checkP2s(p2s2) {
  if (!(p2s2 instanceof Uint8Array) || p2s2.length < 8) {
    throw new JWEInvalid("PBES2 Salt Input must be 8 or more octets");
  }
}
var init_check_p2s = __esm({
  "node_modules/jose/dist/browser/lib/check_p2s.js"() {
    init_errors2();
  }
});

// node_modules/jose/dist/browser/runtime/pbes2kw.js
function getCryptoKey2(key2, alg2) {
  if (key2 instanceof Uint8Array) {
    return webcrypto_default.subtle.importKey("raw", key2, "PBKDF2", false, ["deriveBits"]);
  }
  if (isCryptoKey(key2)) {
    checkEncCryptoKey(key2, alg2, "deriveBits", "deriveKey");
    return key2;
  }
  throw new TypeError(invalid_key_input_default(key2, ...types, "Uint8Array"));
}
async function deriveKey2(p2s2, alg2, p2c, key2) {
  checkP2s(p2s2);
  const salt = p2s(alg2, p2s2);
  const keylen = parseInt(alg2.slice(13, 16), 10);
  const subtleAlg = {
    hash: `SHA-${alg2.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt
  };
  const wrapAlg = {
    length: keylen,
    name: "AES-KW"
  };
  const cryptoKey = await getCryptoKey2(key2, alg2);
  if (cryptoKey.usages.includes("deriveBits")) {
    return new Uint8Array(await webcrypto_default.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
  }
  if (cryptoKey.usages.includes("deriveKey")) {
    return webcrypto_default.subtle.deriveKey(subtleAlg, cryptoKey, wrapAlg, false, ["wrapKey", "unwrapKey"]);
  }
  throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');
}
var encrypt, decrypt2;
var init_pbes2kw = __esm({
  "node_modules/jose/dist/browser/runtime/pbes2kw.js"() {
    init_random();
    init_buffer_utils();
    init_base64url();
    init_aeskw();
    init_check_p2s();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    encrypt = async (alg2, key2, cek, p2c = 2048, p2s2 = random_default(new Uint8Array(16))) => {
      const derived = await deriveKey2(p2s2, alg2, p2c, key2);
      const encryptedKey = await wrap(alg2.slice(-6), derived, cek);
      return { encryptedKey, p2c, p2s: encode(p2s2) };
    };
    decrypt2 = async (alg2, key2, encryptedKey, p2c, p2s2) => {
      const derived = await deriveKey2(p2s2, alg2, p2c, key2);
      return unwrap(alg2.slice(-6), derived, encryptedKey);
    };
  }
});

// node_modules/jose/dist/browser/runtime/subtle_rsaes.js
function subtleRsaEs(alg2) {
  switch (alg2) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      return "RSA-OAEP";
    default:
      throw new JOSENotSupported(`alg ${alg2} is not supported either by JOSE or your javascript runtime`);
  }
}
var init_subtle_rsaes = __esm({
  "node_modules/jose/dist/browser/runtime/subtle_rsaes.js"() {
    init_errors2();
  }
});

// node_modules/jose/dist/browser/runtime/check_key_length.js
var check_key_length_default;
var init_check_key_length = __esm({
  "node_modules/jose/dist/browser/runtime/check_key_length.js"() {
    check_key_length_default = (alg2, key2) => {
      if (alg2.startsWith("RS") || alg2.startsWith("PS")) {
        const { modulusLength } = key2.algorithm;
        if (typeof modulusLength !== "number" || modulusLength < 2048) {
          throw new TypeError(`${alg2} requires key modulusLength to be 2048 bits or larger`);
        }
      }
    };
  }
});

// node_modules/jose/dist/browser/runtime/rsaes.js
var encrypt2, decrypt3;
var init_rsaes = __esm({
  "node_modules/jose/dist/browser/runtime/rsaes.js"() {
    init_subtle_rsaes();
    init_bogus();
    init_webcrypto();
    init_crypto_key();
    init_check_key_length();
    init_invalid_key_input();
    init_is_key_like();
    encrypt2 = async (alg2, key2, cek) => {
      if (!isCryptoKey(key2)) {
        throw new TypeError(invalid_key_input_default(key2, ...types));
      }
      checkEncCryptoKey(key2, alg2, "encrypt", "wrapKey");
      check_key_length_default(alg2, key2);
      if (key2.usages.includes("encrypt")) {
        return new Uint8Array(await webcrypto_default.subtle.encrypt(subtleRsaEs(alg2), key2, cek));
      }
      if (key2.usages.includes("wrapKey")) {
        const cryptoKeyCek = await webcrypto_default.subtle.importKey("raw", cek, ...bogus_default);
        return new Uint8Array(await webcrypto_default.subtle.wrapKey("raw", cryptoKeyCek, key2, subtleRsaEs(alg2)));
      }
      throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation');
    };
    decrypt3 = async (alg2, key2, encryptedKey) => {
      if (!isCryptoKey(key2)) {
        throw new TypeError(invalid_key_input_default(key2, ...types));
      }
      checkEncCryptoKey(key2, alg2, "decrypt", "unwrapKey");
      check_key_length_default(alg2, key2);
      if (key2.usages.includes("decrypt")) {
        return new Uint8Array(await webcrypto_default.subtle.decrypt(subtleRsaEs(alg2), key2, encryptedKey));
      }
      if (key2.usages.includes("unwrapKey")) {
        const cryptoKeyCek = await webcrypto_default.subtle.unwrapKey("raw", encryptedKey, key2, subtleRsaEs(alg2), ...bogus_default);
        return new Uint8Array(await webcrypto_default.subtle.exportKey("raw", cryptoKeyCek));
      }
      throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation');
    };
  }
});

// node_modules/jose/dist/browser/lib/cek.js
function bitLength2(alg2) {
  switch (alg2) {
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
    case "A128CBC-HS256":
      return 256;
    case "A192CBC-HS384":
      return 384;
    case "A256CBC-HS512":
      return 512;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg2}`);
  }
}
var cek_default;
var init_cek = __esm({
  "node_modules/jose/dist/browser/lib/cek.js"() {
    init_errors2();
    init_random();
    cek_default = (alg2) => random_default(new Uint8Array(bitLength2(alg2) >> 3));
  }
});

// node_modules/jose/dist/browser/lib/format_pem.js
var init_format_pem = __esm({
  "node_modules/jose/dist/browser/lib/format_pem.js"() {
  }
});

// node_modules/jose/dist/browser/runtime/asn1.js
var init_asn1 = __esm({
  "node_modules/jose/dist/browser/runtime/asn1.js"() {
    init_webcrypto();
    init_invalid_key_input();
    init_base64url();
    init_format_pem();
    init_errors2();
    init_is_key_like();
  }
});

// node_modules/jose/dist/browser/runtime/jwk_to_key.js
function subtleMapping(jwk) {
  let algorithm;
  let keyUsages;
  switch (jwk.kty) {
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512":
          algorithm = { name: "RSA-PSS", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RS256":
        case "RS384":
        case "RS512":
          algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`
          };
          keyUsages = jwk.d ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256":
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES384":
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES512":
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: "ECDH", namedCurve: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "EdDSA":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
  }
  return { algorithm, keyUsages };
}
var parse, jwk_to_key_default;
var init_jwk_to_key = __esm({
  "node_modules/jose/dist/browser/runtime/jwk_to_key.js"() {
    init_webcrypto();
    init_errors2();
    parse = async (jwk) => {
      if (!jwk.alg) {
        throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
      }
      const { algorithm, keyUsages } = subtleMapping(jwk);
      const rest = [
        algorithm,
        jwk.ext ?? false,
        jwk.key_ops ?? keyUsages
      ];
      const keyData = { ...jwk };
      delete keyData.alg;
      delete keyData.use;
      return webcrypto_default.subtle.importKey("jwk", keyData, ...rest);
    };
    jwk_to_key_default = parse;
  }
});

// node_modules/jose/dist/browser/key/import.js
async function importJWK(jwk, alg2) {
  if (!isObject(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  alg2 || (alg2 = jwk.alg);
  switch (jwk.kty) {
    case "oct":
      if (typeof jwk.k !== "string" || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }
      return decode(jwk.k);
    case "RSA":
      if (jwk.oth !== void 0) {
        throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
      }
    case "EC":
    case "OKP":
      return jwk_to_key_default({ ...jwk, alg: alg2 });
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}
var init_import = __esm({
  "node_modules/jose/dist/browser/key/import.js"() {
    init_base64url();
    init_asn1();
    init_jwk_to_key();
    init_errors2();
    init_is_object();
  }
});

// node_modules/jose/dist/browser/lib/check_key_type.js
var symmetricTypeCheck, asymmetricTypeCheck, checkKeyType, check_key_type_default;
var init_check_key_type = __esm({
  "node_modules/jose/dist/browser/lib/check_key_type.js"() {
    init_invalid_key_input();
    init_is_key_like();
    symmetricTypeCheck = (alg2, key2) => {
      if (key2 instanceof Uint8Array)
        return;
      if (!is_key_like_default(key2)) {
        throw new TypeError(withAlg(alg2, key2, ...types, "Uint8Array"));
      }
      if (key2.type !== "secret") {
        throw new TypeError(`${types.join(" or ")} instances for symmetric algorithms must be of type "secret"`);
      }
    };
    asymmetricTypeCheck = (alg2, key2, usage) => {
      if (!is_key_like_default(key2)) {
        throw new TypeError(withAlg(alg2, key2, ...types));
      }
      if (key2.type === "secret") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithms must not be of type "secret"`);
      }
      if (usage === "sign" && key2.type === "public") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm signing must be of type "private"`);
      }
      if (usage === "decrypt" && key2.type === "public") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm decryption must be of type "private"`);
      }
      if (key2.algorithm && usage === "verify" && key2.type === "private") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm verifying must be of type "public"`);
      }
      if (key2.algorithm && usage === "encrypt" && key2.type === "private") {
        throw new TypeError(`${types.join(" or ")} instances for asymmetric algorithm encryption must be of type "public"`);
      }
    };
    checkKeyType = (alg2, key2, usage) => {
      const symmetric = alg2.startsWith("HS") || alg2 === "dir" || alg2.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(alg2);
      if (symmetric) {
        symmetricTypeCheck(alg2, key2);
      } else {
        asymmetricTypeCheck(alg2, key2, usage);
      }
    };
    check_key_type_default = checkKeyType;
  }
});

// node_modules/jose/dist/browser/runtime/encrypt.js
async function cbcEncrypt(enc2, plaintext, cek, iv, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(invalid_key_input_default(cek, "Uint8Array"));
  }
  const keySize = parseInt(enc2.slice(1, 4), 10);
  const encKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, ["encrypt"]);
  const macKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  const ciphertext = new Uint8Array(await webcrypto_default.subtle.encrypt({
    iv,
    name: "AES-CBC"
  }, encKey, plaintext));
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const tag = new Uint8Array((await webcrypto_default.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
  return { ciphertext, tag, iv };
}
async function gcmEncrypt(enc2, plaintext, cek, iv, aad) {
  let encKey;
  if (cek instanceof Uint8Array) {
    encKey = await webcrypto_default.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  } else {
    checkEncCryptoKey(cek, enc2, "encrypt");
    encKey = cek;
  }
  const encrypted = new Uint8Array(await webcrypto_default.subtle.encrypt({
    additionalData: aad,
    iv,
    name: "AES-GCM",
    tagLength: 128
  }, encKey, plaintext));
  const tag = encrypted.slice(-16);
  const ciphertext = encrypted.slice(0, -16);
  return { ciphertext, tag, iv };
}
var encrypt3, encrypt_default;
var init_encrypt = __esm({
  "node_modules/jose/dist/browser/runtime/encrypt.js"() {
    init_buffer_utils();
    init_check_iv_length();
    init_check_cek_length();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_iv();
    init_errors2();
    init_is_key_like();
    encrypt3 = async (enc2, plaintext, cek, iv, aad) => {
      if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalid_key_input_default(cek, ...types, "Uint8Array"));
      }
      if (iv) {
        check_iv_length_default(enc2, iv);
      } else {
        iv = iv_default(enc2);
      }
      switch (enc2) {
        case "A128CBC-HS256":
        case "A192CBC-HS384":
        case "A256CBC-HS512":
          if (cek instanceof Uint8Array) {
            check_cek_length_default(cek, parseInt(enc2.slice(-3), 10));
          }
          return cbcEncrypt(enc2, plaintext, cek, iv, aad);
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
          if (cek instanceof Uint8Array) {
            check_cek_length_default(cek, parseInt(enc2.slice(1, 4), 10));
          }
          return gcmEncrypt(enc2, plaintext, cek, iv, aad);
        default:
          throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
      }
    };
    encrypt_default = encrypt3;
  }
});

// node_modules/jose/dist/browser/lib/aesgcmkw.js
async function wrap2(alg2, key2, cek, iv) {
  const jweAlgorithm = alg2.slice(0, 7);
  const wrapped = await encrypt_default(jweAlgorithm, cek, key2, iv, new Uint8Array(0));
  return {
    encryptedKey: wrapped.ciphertext,
    iv: encode(wrapped.iv),
    tag: encode(wrapped.tag)
  };
}
async function unwrap2(alg2, key2, encryptedKey, iv, tag) {
  const jweAlgorithm = alg2.slice(0, 7);
  return decrypt_default(jweAlgorithm, key2, encryptedKey, iv, tag, new Uint8Array(0));
}
var init_aesgcmkw = __esm({
  "node_modules/jose/dist/browser/lib/aesgcmkw.js"() {
    init_encrypt();
    init_decrypt();
    init_base64url();
  }
});

// node_modules/jose/dist/browser/lib/decrypt_key_management.js
async function decryptKeyManagement(alg2, key2, encryptedKey, joseHeader, options2) {
  check_key_type_default(alg2, key2, "decrypt");
  switch (alg2) {
    case "dir": {
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
      return key2;
    }
    case "ECDH-ES":
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!isObject(joseHeader.epk))
        throw new JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
      if (!ecdhAllowed(key2))
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      const epk = await importJWK(joseHeader.epk, alg2);
      let partyUInfo;
      let partyVInfo;
      if (joseHeader.apu !== void 0) {
        if (typeof joseHeader.apu !== "string")
          throw new JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
        try {
          partyUInfo = decode(joseHeader.apu);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the apu");
        }
      }
      if (joseHeader.apv !== void 0) {
        if (typeof joseHeader.apv !== "string")
          throw new JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
        try {
          partyVInfo = decode(joseHeader.apv);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the apv");
        }
      }
      const sharedSecret = await deriveKey(epk, key2, alg2 === "ECDH-ES" ? joseHeader.enc : alg2, alg2 === "ECDH-ES" ? bitLength2(joseHeader.enc) : parseInt(alg2.slice(-5, -2), 10), partyUInfo, partyVInfo);
      if (alg2 === "ECDH-ES")
        return sharedSecret;
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap(alg2.slice(-6), sharedSecret, encryptedKey);
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return decrypt3(alg2, key2, encryptedKey);
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.p2c !== "number")
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
      const p2cLimit = options2?.maxPBES2Count || 1e4;
      if (joseHeader.p2c > p2cLimit)
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds`);
      if (typeof joseHeader.p2s !== "string")
        throw new JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
      let p2s2;
      try {
        p2s2 = decode(joseHeader.p2s);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the p2s");
      }
      return decrypt2(alg2, key2, encryptedKey, joseHeader.p2c, p2s2);
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap(alg2, key2, encryptedKey);
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.iv !== "string")
        throw new JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
      if (typeof joseHeader.tag !== "string")
        throw new JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
      let iv;
      try {
        iv = decode(joseHeader.iv);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the iv");
      }
      let tag;
      try {
        tag = decode(joseHeader.tag);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the tag");
      }
      return unwrap2(alg2, key2, encryptedKey, iv, tag);
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
}
var decrypt_key_management_default;
var init_decrypt_key_management = __esm({
  "node_modules/jose/dist/browser/lib/decrypt_key_management.js"() {
    init_aeskw();
    init_ecdhes();
    init_pbes2kw();
    init_rsaes();
    init_base64url();
    init_errors2();
    init_cek();
    init_import();
    init_check_key_type();
    init_is_object();
    init_aesgcmkw();
    decrypt_key_management_default = decryptKeyManagement;
  }
});

// node_modules/jose/dist/browser/lib/validate_crit.js
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }
    if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}
var validate_crit_default;
var init_validate_crit = __esm({
  "node_modules/jose/dist/browser/lib/validate_crit.js"() {
    init_errors2();
    validate_crit_default = validateCrit;
  }
});

// node_modules/jose/dist/browser/lib/validate_algorithms.js
var validateAlgorithms, validate_algorithms_default;
var init_validate_algorithms = __esm({
  "node_modules/jose/dist/browser/lib/validate_algorithms.js"() {
    validateAlgorithms = (option, algorithms) => {
      if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s4) => typeof s4 !== "string"))) {
        throw new TypeError(`"${option}" option must be an array of strings`);
      }
      if (!algorithms) {
        return void 0;
      }
      return new Set(algorithms);
    };
    validate_algorithms_default = validateAlgorithms;
  }
});

// node_modules/jose/dist/browser/jwe/flattened/decrypt.js
async function flattenedDecrypt(jwe, key2, options2) {
  if (!isObject(jwe)) {
    throw new JWEInvalid("Flattened JWE must be an object");
  }
  if (jwe.protected === void 0 && jwe.header === void 0 && jwe.unprotected === void 0) {
    throw new JWEInvalid("JOSE Header missing");
  }
  if (jwe.iv !== void 0 && typeof jwe.iv !== "string") {
    throw new JWEInvalid("JWE Initialization Vector incorrect type");
  }
  if (typeof jwe.ciphertext !== "string") {
    throw new JWEInvalid("JWE Ciphertext missing or incorrect type");
  }
  if (jwe.tag !== void 0 && typeof jwe.tag !== "string") {
    throw new JWEInvalid("JWE Authentication Tag incorrect type");
  }
  if (jwe.protected !== void 0 && typeof jwe.protected !== "string") {
    throw new JWEInvalid("JWE Protected Header incorrect type");
  }
  if (jwe.encrypted_key !== void 0 && typeof jwe.encrypted_key !== "string") {
    throw new JWEInvalid("JWE Encrypted Key incorrect type");
  }
  if (jwe.aad !== void 0 && typeof jwe.aad !== "string") {
    throw new JWEInvalid("JWE AAD incorrect type");
  }
  if (jwe.header !== void 0 && !isObject(jwe.header)) {
    throw new JWEInvalid("JWE Shared Unprotected Header incorrect type");
  }
  if (jwe.unprotected !== void 0 && !isObject(jwe.unprotected)) {
    throw new JWEInvalid("JWE Per-Recipient Unprotected Header incorrect type");
  }
  let parsedProt;
  if (jwe.protected) {
    try {
      const protectedHeader2 = decode(jwe.protected);
      parsedProt = JSON.parse(decoder.decode(protectedHeader2));
    } catch {
      throw new JWEInvalid("JWE Protected Header is invalid");
    }
  }
  if (!is_disjoint_default(parsedProt, jwe.header, jwe.unprotected)) {
    throw new JWEInvalid("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jwe.header,
    ...jwe.unprotected
  };
  validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options2?.crit, parsedProt, joseHeader);
  if (joseHeader.zip !== void 0) {
    throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
  }
  const { alg: alg2, enc: enc2 } = joseHeader;
  if (typeof alg2 !== "string" || !alg2) {
    throw new JWEInvalid("missing JWE Algorithm (alg) in JWE Header");
  }
  if (typeof enc2 !== "string" || !enc2) {
    throw new JWEInvalid("missing JWE Encryption Algorithm (enc) in JWE Header");
  }
  const keyManagementAlgorithms = options2 && validate_algorithms_default("keyManagementAlgorithms", options2.keyManagementAlgorithms);
  const contentEncryptionAlgorithms = options2 && validate_algorithms_default("contentEncryptionAlgorithms", options2.contentEncryptionAlgorithms);
  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg2) || !keyManagementAlgorithms && alg2.startsWith("PBES2")) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  }
  if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc2)) {
    throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter value not allowed');
  }
  let encryptedKey;
  if (jwe.encrypted_key !== void 0) {
    try {
      encryptedKey = decode(jwe.encrypted_key);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the encrypted_key");
    }
  }
  let resolvedKey = false;
  if (typeof key2 === "function") {
    key2 = await key2(parsedProt, jwe);
    resolvedKey = true;
  }
  let cek;
  try {
    cek = await decrypt_key_management_default(alg2, key2, encryptedKey, joseHeader, options2);
  } catch (err) {
    if (err instanceof TypeError || err instanceof JWEInvalid || err instanceof JOSENotSupported) {
      throw err;
    }
    cek = cek_default(enc2);
  }
  let iv;
  let tag;
  if (jwe.iv !== void 0) {
    try {
      iv = decode(jwe.iv);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the iv");
    }
  }
  if (jwe.tag !== void 0) {
    try {
      tag = decode(jwe.tag);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the tag");
    }
  }
  const protectedHeader = encoder.encode(jwe.protected ?? "");
  let additionalData;
  if (jwe.aad !== void 0) {
    additionalData = concat(protectedHeader, encoder.encode("."), encoder.encode(jwe.aad));
  } else {
    additionalData = protectedHeader;
  }
  let ciphertext;
  try {
    ciphertext = decode(jwe.ciphertext);
  } catch {
    throw new JWEInvalid("Failed to base64url decode the ciphertext");
  }
  const plaintext = await decrypt_default(enc2, cek, ciphertext, iv, tag, additionalData);
  const result = { plaintext };
  if (jwe.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jwe.aad !== void 0) {
    try {
      result.additionalAuthenticatedData = decode(jwe.aad);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the aad");
    }
  }
  if (jwe.unprotected !== void 0) {
    result.sharedUnprotectedHeader = jwe.unprotected;
  }
  if (jwe.header !== void 0) {
    result.unprotectedHeader = jwe.header;
  }
  if (resolvedKey) {
    return { ...result, key: key2 };
  }
  return result;
}
var init_decrypt2 = __esm({
  "node_modules/jose/dist/browser/jwe/flattened/decrypt.js"() {
    init_base64url();
    init_decrypt();
    init_errors2();
    init_is_disjoint();
    init_is_object();
    init_decrypt_key_management();
    init_buffer_utils();
    init_cek();
    init_validate_crit();
    init_validate_algorithms();
  }
});

// node_modules/jose/dist/browser/jwe/compact/decrypt.js
async function compactDecrypt(jwe, key2, options2) {
  if (jwe instanceof Uint8Array) {
    jwe = decoder.decode(jwe);
  }
  if (typeof jwe !== "string") {
    throw new JWEInvalid("Compact JWE must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag, length } = jwe.split(".");
  if (length !== 5) {
    throw new JWEInvalid("Invalid Compact JWE");
  }
  const decrypted = await flattenedDecrypt({
    ciphertext,
    iv: iv || void 0,
    protected: protectedHeader,
    tag: tag || void 0,
    encrypted_key: encryptedKey || void 0
  }, key2, options2);
  const result = { plaintext: decrypted.plaintext, protectedHeader: decrypted.protectedHeader };
  if (typeof key2 === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}
var init_decrypt3 = __esm({
  "node_modules/jose/dist/browser/jwe/compact/decrypt.js"() {
    init_decrypt2();
    init_errors2();
    init_buffer_utils();
  }
});

// node_modules/jose/dist/browser/jwe/general/decrypt.js
var init_decrypt4 = __esm({
  "node_modules/jose/dist/browser/jwe/general/decrypt.js"() {
    init_decrypt2();
    init_errors2();
    init_is_object();
  }
});

// node_modules/jose/dist/browser/runtime/key_to_jwk.js
var keyToJWK, key_to_jwk_default;
var init_key_to_jwk = __esm({
  "node_modules/jose/dist/browser/runtime/key_to_jwk.js"() {
    init_webcrypto();
    init_invalid_key_input();
    init_base64url();
    init_is_key_like();
    keyToJWK = async (key2) => {
      if (key2 instanceof Uint8Array) {
        return {
          kty: "oct",
          k: encode(key2)
        };
      }
      if (!isCryptoKey(key2)) {
        throw new TypeError(invalid_key_input_default(key2, ...types, "Uint8Array"));
      }
      if (!key2.extractable) {
        throw new TypeError("non-extractable CryptoKey cannot be exported as a JWK");
      }
      const { ext, key_ops, alg: alg2, use, ...jwk } = await webcrypto_default.subtle.exportKey("jwk", key2);
      return jwk;
    };
    key_to_jwk_default = keyToJWK;
  }
});

// node_modules/jose/dist/browser/key/export.js
async function exportJWK(key2) {
  return key_to_jwk_default(key2);
}
var init_export = __esm({
  "node_modules/jose/dist/browser/key/export.js"() {
    init_asn1();
    init_asn1();
    init_key_to_jwk();
  }
});

// node_modules/jose/dist/browser/lib/encrypt_key_management.js
async function encryptKeyManagement(alg2, enc2, key2, providedCek, providedParameters = {}) {
  let encryptedKey;
  let parameters;
  let cek;
  check_key_type_default(alg2, key2, "encrypt");
  switch (alg2) {
    case "dir": {
      cek = key2;
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!ecdhAllowed(key2)) {
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      }
      const { apu, apv } = providedParameters;
      let { epk: ephemeralKey } = providedParameters;
      ephemeralKey || (ephemeralKey = (await generateEpk(key2)).privateKey);
      const { x: x2, y: y2, crv, kty } = await exportJWK(ephemeralKey);
      const sharedSecret = await deriveKey(key2, ephemeralKey, alg2 === "ECDH-ES" ? enc2 : alg2, alg2 === "ECDH-ES" ? bitLength2(enc2) : parseInt(alg2.slice(-5, -2), 10), apu, apv);
      parameters = { epk: { x: x2, crv, kty } };
      if (kty === "EC")
        parameters.epk.y = y2;
      if (apu)
        parameters.apu = encode(apu);
      if (apv)
        parameters.apv = encode(apv);
      if (alg2 === "ECDH-ES") {
        cek = sharedSecret;
        break;
      }
      cek = providedCek || cek_default(enc2);
      const kwAlg = alg2.slice(-6);
      encryptedKey = await wrap(kwAlg, sharedSecret, cek);
      break;
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      cek = providedCek || cek_default(enc2);
      encryptedKey = await encrypt2(alg2, key2, cek);
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      cek = providedCek || cek_default(enc2);
      const { p2c, p2s: p2s2 } = providedParameters;
      ({ encryptedKey, ...parameters } = await encrypt(alg2, key2, cek, p2c, p2s2));
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      cek = providedCek || cek_default(enc2);
      encryptedKey = await wrap(alg2, key2, cek);
      break;
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      cek = providedCek || cek_default(enc2);
      const { iv } = providedParameters;
      ({ encryptedKey, ...parameters } = await wrap2(alg2, key2, cek, iv));
      break;
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
  return { cek, encryptedKey, parameters };
}
var encrypt_key_management_default;
var init_encrypt_key_management = __esm({
  "node_modules/jose/dist/browser/lib/encrypt_key_management.js"() {
    init_aeskw();
    init_ecdhes();
    init_pbes2kw();
    init_rsaes();
    init_base64url();
    init_cek();
    init_errors2();
    init_export();
    init_check_key_type();
    init_aesgcmkw();
    encrypt_key_management_default = encryptKeyManagement;
  }
});

// node_modules/jose/dist/browser/jwe/flattened/encrypt.js
var unprotected, FlattenedEncrypt;
var init_encrypt2 = __esm({
  "node_modules/jose/dist/browser/jwe/flattened/encrypt.js"() {
    init_base64url();
    init_encrypt();
    init_encrypt_key_management();
    init_errors2();
    init_is_disjoint();
    init_buffer_utils();
    init_validate_crit();
    unprotected = Symbol();
    FlattenedEncrypt = class {
      constructor(plaintext) {
        if (!(plaintext instanceof Uint8Array)) {
          throw new TypeError("plaintext must be an instance of Uint8Array");
        }
        this._plaintext = plaintext;
      }
      setKeyManagementParameters(parameters) {
        if (this._keyManagementParameters) {
          throw new TypeError("setKeyManagementParameters can only be called once");
        }
        this._keyManagementParameters = parameters;
        return this;
      }
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setSharedUnprotectedHeader(sharedUnprotectedHeader) {
        if (this._sharedUnprotectedHeader) {
          throw new TypeError("setSharedUnprotectedHeader can only be called once");
        }
        this._sharedUnprotectedHeader = sharedUnprotectedHeader;
        return this;
      }
      setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
          throw new TypeError("setUnprotectedHeader can only be called once");
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
      }
      setAdditionalAuthenticatedData(aad) {
        this._aad = aad;
        return this;
      }
      setContentEncryptionKey(cek) {
        if (this._cek) {
          throw new TypeError("setContentEncryptionKey can only be called once");
        }
        this._cek = cek;
        return this;
      }
      setInitializationVector(iv) {
        if (this._iv) {
          throw new TypeError("setInitializationVector can only be called once");
        }
        this._iv = iv;
        return this;
      }
      async encrypt(key2, options2) {
        if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader) {
          throw new JWEInvalid("either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()");
        }
        if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader)) {
          throw new JWEInvalid("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
        }
        const joseHeader = {
          ...this._protectedHeader,
          ...this._unprotectedHeader,
          ...this._sharedUnprotectedHeader
        };
        validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options2?.crit, this._protectedHeader, joseHeader);
        if (joseHeader.zip !== void 0) {
          throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
        }
        const { alg: alg2, enc: enc2 } = joseHeader;
        if (typeof alg2 !== "string" || !alg2) {
          throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if (typeof enc2 !== "string" || !enc2) {
          throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
        }
        let encryptedKey;
        if (this._cek && (alg2 === "dir" || alg2 === "ECDH-ES")) {
          throw new TypeError(`setContentEncryptionKey cannot be called with JWE "alg" (Algorithm) Header ${alg2}`);
        }
        let cek;
        {
          let parameters;
          ({ cek, encryptedKey, parameters } = await encrypt_key_management_default(alg2, enc2, key2, this._cek, this._keyManagementParameters));
          if (parameters) {
            if (options2 && unprotected in options2) {
              if (!this._unprotectedHeader) {
                this.setUnprotectedHeader(parameters);
              } else {
                this._unprotectedHeader = { ...this._unprotectedHeader, ...parameters };
              }
            } else {
              if (!this._protectedHeader) {
                this.setProtectedHeader(parameters);
              } else {
                this._protectedHeader = { ...this._protectedHeader, ...parameters };
              }
            }
          }
        }
        let additionalData;
        let protectedHeader;
        let aadMember;
        if (this._protectedHeader) {
          protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
        } else {
          protectedHeader = encoder.encode("");
        }
        if (this._aad) {
          aadMember = encode(this._aad);
          additionalData = concat(protectedHeader, encoder.encode("."), encoder.encode(aadMember));
        } else {
          additionalData = protectedHeader;
        }
        const { ciphertext, tag, iv } = await encrypt_default(enc2, this._plaintext, cek, this._iv, additionalData);
        const jwe = {
          ciphertext: encode(ciphertext)
        };
        if (iv) {
          jwe.iv = encode(iv);
        }
        if (tag) {
          jwe.tag = encode(tag);
        }
        if (encryptedKey) {
          jwe.encrypted_key = encode(encryptedKey);
        }
        if (aadMember) {
          jwe.aad = aadMember;
        }
        if (this._protectedHeader) {
          jwe.protected = decoder.decode(protectedHeader);
        }
        if (this._sharedUnprotectedHeader) {
          jwe.unprotected = this._sharedUnprotectedHeader;
        }
        if (this._unprotectedHeader) {
          jwe.header = this._unprotectedHeader;
        }
        return jwe;
      }
    };
  }
});

// node_modules/jose/dist/browser/jwe/general/encrypt.js
var init_encrypt3 = __esm({
  "node_modules/jose/dist/browser/jwe/general/encrypt.js"() {
    init_encrypt2();
    init_errors2();
    init_cek();
    init_is_disjoint();
    init_encrypt_key_management();
    init_base64url();
    init_validate_crit();
  }
});

// node_modules/jose/dist/browser/runtime/subtle_dsa.js
var init_subtle_dsa = __esm({
  "node_modules/jose/dist/browser/runtime/subtle_dsa.js"() {
    init_errors2();
  }
});

// node_modules/jose/dist/browser/runtime/get_sign_verify_key.js
var init_get_sign_verify_key = __esm({
  "node_modules/jose/dist/browser/runtime/get_sign_verify_key.js"() {
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
  }
});

// node_modules/jose/dist/browser/runtime/verify.js
var init_verify = __esm({
  "node_modules/jose/dist/browser/runtime/verify.js"() {
    init_subtle_dsa();
    init_webcrypto();
    init_check_key_length();
    init_get_sign_verify_key();
  }
});

// node_modules/jose/dist/browser/jws/flattened/verify.js
var init_verify2 = __esm({
  "node_modules/jose/dist/browser/jws/flattened/verify.js"() {
    init_base64url();
    init_verify();
    init_errors2();
    init_buffer_utils();
    init_is_disjoint();
    init_is_object();
    init_check_key_type();
    init_validate_crit();
    init_validate_algorithms();
  }
});

// node_modules/jose/dist/browser/jws/compact/verify.js
var init_verify3 = __esm({
  "node_modules/jose/dist/browser/jws/compact/verify.js"() {
    init_verify2();
    init_errors2();
    init_buffer_utils();
  }
});

// node_modules/jose/dist/browser/jws/general/verify.js
var init_verify4 = __esm({
  "node_modules/jose/dist/browser/jws/general/verify.js"() {
    init_verify2();
    init_errors2();
    init_is_object();
  }
});

// node_modules/jose/dist/browser/lib/epoch.js
var epoch_default;
var init_epoch = __esm({
  "node_modules/jose/dist/browser/lib/epoch.js"() {
    epoch_default = (date) => Math.floor(date.getTime() / 1e3);
  }
});

// node_modules/jose/dist/browser/lib/secs.js
var minute, hour, day, week, year, REGEX, secs_default;
var init_secs = __esm({
  "node_modules/jose/dist/browser/lib/secs.js"() {
    minute = 60;
    hour = minute * 60;
    day = hour * 24;
    week = day * 7;
    year = day * 365.25;
    REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
    secs_default = (str) => {
      const matched = REGEX.exec(str);
      if (!matched || matched[4] && matched[1]) {
        throw new TypeError("Invalid time period format");
      }
      const value = parseFloat(matched[2]);
      const unit = matched[3].toLowerCase();
      let numericDate;
      switch (unit) {
        case "sec":
        case "secs":
        case "second":
        case "seconds":
        case "s":
          numericDate = Math.round(value);
          break;
        case "minute":
        case "minutes":
        case "min":
        case "mins":
        case "m":
          numericDate = Math.round(value * minute);
          break;
        case "hour":
        case "hours":
        case "hr":
        case "hrs":
        case "h":
          numericDate = Math.round(value * hour);
          break;
        case "day":
        case "days":
        case "d":
          numericDate = Math.round(value * day);
          break;
        case "week":
        case "weeks":
        case "w":
          numericDate = Math.round(value * week);
          break;
        default:
          numericDate = Math.round(value * year);
          break;
      }
      if (matched[1] === "-" || matched[4] === "ago") {
        return -numericDate;
      }
      return numericDate;
    };
  }
});

// node_modules/jose/dist/browser/lib/jwt_claims_set.js
var normalizeTyp, checkAudiencePresence, jwt_claims_set_default;
var init_jwt_claims_set = __esm({
  "node_modules/jose/dist/browser/lib/jwt_claims_set.js"() {
    init_errors2();
    init_buffer_utils();
    init_epoch();
    init_secs();
    init_is_object();
    normalizeTyp = (value) => value.toLowerCase().replace(/^application\//, "");
    checkAudiencePresence = (audPayload, audOption) => {
      if (typeof audPayload === "string") {
        return audOption.includes(audPayload);
      }
      if (Array.isArray(audPayload)) {
        return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
      }
      return false;
    };
    jwt_claims_set_default = (protectedHeader, encodedPayload, options2 = {}) => {
      const { typ } = options2;
      if (typ && (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
        throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', "typ", "check_failed");
      }
      let payload;
      try {
        payload = JSON.parse(decoder.decode(encodedPayload));
      } catch {
      }
      if (!isObject(payload)) {
        throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
      }
      const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options2;
      const presenceCheck = [...requiredClaims];
      if (maxTokenAge !== void 0)
        presenceCheck.push("iat");
      if (audience !== void 0)
        presenceCheck.push("aud");
      if (subject !== void 0)
        presenceCheck.push("sub");
      if (issuer !== void 0)
        presenceCheck.push("iss");
      for (const claim of new Set(presenceCheck.reverse())) {
        if (!(claim in payload)) {
          throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, claim, "missing");
        }
      }
      if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
        throw new JWTClaimValidationFailed('unexpected "iss" claim value', "iss", "check_failed");
      }
      if (subject && payload.sub !== subject) {
        throw new JWTClaimValidationFailed('unexpected "sub" claim value', "sub", "check_failed");
      }
      if (audience && !checkAudiencePresence(payload.aud, typeof audience === "string" ? [audience] : audience)) {
        throw new JWTClaimValidationFailed('unexpected "aud" claim value', "aud", "check_failed");
      }
      let tolerance;
      switch (typeof options2.clockTolerance) {
        case "string":
          tolerance = secs_default(options2.clockTolerance);
          break;
        case "number":
          tolerance = options2.clockTolerance;
          break;
        case "undefined":
          tolerance = 0;
          break;
        default:
          throw new TypeError("Invalid clockTolerance option type");
      }
      const { currentDate } = options2;
      const now2 = epoch_default(currentDate || /* @__PURE__ */ new Date());
      if ((payload.iat !== void 0 || maxTokenAge) && typeof payload.iat !== "number") {
        throw new JWTClaimValidationFailed('"iat" claim must be a number', "iat", "invalid");
      }
      if (payload.nbf !== void 0) {
        if (typeof payload.nbf !== "number") {
          throw new JWTClaimValidationFailed('"nbf" claim must be a number', "nbf", "invalid");
        }
        if (payload.nbf > now2 + tolerance) {
          throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', "nbf", "check_failed");
        }
      }
      if (payload.exp !== void 0) {
        if (typeof payload.exp !== "number") {
          throw new JWTClaimValidationFailed('"exp" claim must be a number', "exp", "invalid");
        }
        if (payload.exp <= now2 - tolerance) {
          throw new JWTExpired('"exp" claim timestamp check failed', "exp", "check_failed");
        }
      }
      if (maxTokenAge) {
        const age = now2 - payload.iat;
        const max = typeof maxTokenAge === "number" ? maxTokenAge : secs_default(maxTokenAge);
        if (age - tolerance > max) {
          throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', "iat", "check_failed");
        }
        if (age < 0 - tolerance) {
          throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', "iat", "check_failed");
        }
      }
      return payload;
    };
  }
});

// node_modules/jose/dist/browser/jwt/verify.js
var init_verify5 = __esm({
  "node_modules/jose/dist/browser/jwt/verify.js"() {
    init_verify3();
    init_jwt_claims_set();
    init_errors2();
  }
});

// node_modules/jose/dist/browser/jwt/decrypt.js
async function jwtDecrypt(jwt2, key2, options2) {
  const decrypted = await compactDecrypt(jwt2, key2, options2);
  const payload = jwt_claims_set_default(decrypted.protectedHeader, decrypted.plaintext, options2);
  const { protectedHeader } = decrypted;
  if (protectedHeader.iss !== void 0 && protectedHeader.iss !== payload.iss) {
    throw new JWTClaimValidationFailed('replicated "iss" claim header parameter mismatch', "iss", "mismatch");
  }
  if (protectedHeader.sub !== void 0 && protectedHeader.sub !== payload.sub) {
    throw new JWTClaimValidationFailed('replicated "sub" claim header parameter mismatch', "sub", "mismatch");
  }
  if (protectedHeader.aud !== void 0 && JSON.stringify(protectedHeader.aud) !== JSON.stringify(payload.aud)) {
    throw new JWTClaimValidationFailed('replicated "aud" claim header parameter mismatch', "aud", "mismatch");
  }
  const result = { payload, protectedHeader };
  if (typeof key2 === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}
var init_decrypt5 = __esm({
  "node_modules/jose/dist/browser/jwt/decrypt.js"() {
    init_decrypt3();
    init_jwt_claims_set();
    init_errors2();
  }
});

// node_modules/jose/dist/browser/jwe/compact/encrypt.js
var CompactEncrypt;
var init_encrypt4 = __esm({
  "node_modules/jose/dist/browser/jwe/compact/encrypt.js"() {
    init_encrypt2();
    CompactEncrypt = class {
      constructor(plaintext) {
        this._flattened = new FlattenedEncrypt(plaintext);
      }
      setContentEncryptionKey(cek) {
        this._flattened.setContentEncryptionKey(cek);
        return this;
      }
      setInitializationVector(iv) {
        this._flattened.setInitializationVector(iv);
        return this;
      }
      setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
      }
      setKeyManagementParameters(parameters) {
        this._flattened.setKeyManagementParameters(parameters);
        return this;
      }
      async encrypt(key2, options2) {
        const jwe = await this._flattened.encrypt(key2, options2);
        return [jwe.protected, jwe.encrypted_key, jwe.iv, jwe.ciphertext, jwe.tag].join(".");
      }
    };
  }
});

// node_modules/jose/dist/browser/runtime/sign.js
var init_sign = __esm({
  "node_modules/jose/dist/browser/runtime/sign.js"() {
    init_subtle_dsa();
    init_webcrypto();
    init_check_key_length();
    init_get_sign_verify_key();
  }
});

// node_modules/jose/dist/browser/jws/flattened/sign.js
var init_sign2 = __esm({
  "node_modules/jose/dist/browser/jws/flattened/sign.js"() {
    init_base64url();
    init_sign();
    init_is_disjoint();
    init_errors2();
    init_buffer_utils();
    init_check_key_type();
    init_validate_crit();
  }
});

// node_modules/jose/dist/browser/jws/compact/sign.js
var init_sign3 = __esm({
  "node_modules/jose/dist/browser/jws/compact/sign.js"() {
    init_sign2();
  }
});

// node_modules/jose/dist/browser/jws/general/sign.js
var init_sign4 = __esm({
  "node_modules/jose/dist/browser/jws/general/sign.js"() {
    init_sign2();
    init_errors2();
  }
});

// node_modules/jose/dist/browser/jwt/produce.js
function validateInput(label, input) {
  if (!Number.isFinite(input)) {
    throw new TypeError(`Invalid ${label} input`);
  }
  return input;
}
var ProduceJWT;
var init_produce = __esm({
  "node_modules/jose/dist/browser/jwt/produce.js"() {
    init_epoch();
    init_is_object();
    init_secs();
    ProduceJWT = class {
      constructor(payload = {}) {
        if (!isObject(payload)) {
          throw new TypeError("JWT Claims Set MUST be an object");
        }
        this._payload = payload;
      }
      setIssuer(issuer) {
        this._payload = { ...this._payload, iss: issuer };
        return this;
      }
      setSubject(subject) {
        this._payload = { ...this._payload, sub: subject };
        return this;
      }
      setAudience(audience) {
        this._payload = { ...this._payload, aud: audience };
        return this;
      }
      setJti(jwtId) {
        this._payload = { ...this._payload, jti: jwtId };
        return this;
      }
      setNotBefore(input) {
        if (typeof input === "number") {
          this._payload = { ...this._payload, nbf: validateInput("setNotBefore", input) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, nbf: validateInput("setNotBefore", epoch_default(input)) };
        } else {
          this._payload = { ...this._payload, nbf: epoch_default(/* @__PURE__ */ new Date()) + secs_default(input) };
        }
        return this;
      }
      setExpirationTime(input) {
        if (typeof input === "number") {
          this._payload = { ...this._payload, exp: validateInput("setExpirationTime", input) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, exp: validateInput("setExpirationTime", epoch_default(input)) };
        } else {
          this._payload = { ...this._payload, exp: epoch_default(/* @__PURE__ */ new Date()) + secs_default(input) };
        }
        return this;
      }
      setIssuedAt(input) {
        if (typeof input === "undefined") {
          this._payload = { ...this._payload, iat: epoch_default(/* @__PURE__ */ new Date()) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, iat: validateInput("setIssuedAt", epoch_default(input)) };
        } else if (typeof input === "string") {
          this._payload = {
            ...this._payload,
            iat: validateInput("setIssuedAt", epoch_default(/* @__PURE__ */ new Date()) + secs_default(input))
          };
        } else {
          this._payload = { ...this._payload, iat: validateInput("setIssuedAt", input) };
        }
        return this;
      }
    };
  }
});

// node_modules/jose/dist/browser/jwt/sign.js
var init_sign5 = __esm({
  "node_modules/jose/dist/browser/jwt/sign.js"() {
    init_sign3();
    init_errors2();
    init_buffer_utils();
    init_produce();
  }
});

// node_modules/jose/dist/browser/jwt/encrypt.js
var EncryptJWT;
var init_encrypt5 = __esm({
  "node_modules/jose/dist/browser/jwt/encrypt.js"() {
    init_encrypt4();
    init_buffer_utils();
    init_produce();
    EncryptJWT = class extends ProduceJWT {
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setKeyManagementParameters(parameters) {
        if (this._keyManagementParameters) {
          throw new TypeError("setKeyManagementParameters can only be called once");
        }
        this._keyManagementParameters = parameters;
        return this;
      }
      setContentEncryptionKey(cek) {
        if (this._cek) {
          throw new TypeError("setContentEncryptionKey can only be called once");
        }
        this._cek = cek;
        return this;
      }
      setInitializationVector(iv) {
        if (this._iv) {
          throw new TypeError("setInitializationVector can only be called once");
        }
        this._iv = iv;
        return this;
      }
      replicateIssuerAsHeader() {
        this._replicateIssuerAsHeader = true;
        return this;
      }
      replicateSubjectAsHeader() {
        this._replicateSubjectAsHeader = true;
        return this;
      }
      replicateAudienceAsHeader() {
        this._replicateAudienceAsHeader = true;
        return this;
      }
      async encrypt(key2, options2) {
        const enc2 = new CompactEncrypt(encoder.encode(JSON.stringify(this._payload)));
        if (this._replicateIssuerAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, iss: this._payload.iss };
        }
        if (this._replicateSubjectAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, sub: this._payload.sub };
        }
        if (this._replicateAudienceAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, aud: this._payload.aud };
        }
        enc2.setProtectedHeader(this._protectedHeader);
        if (this._iv) {
          enc2.setInitializationVector(this._iv);
        }
        if (this._cek) {
          enc2.setContentEncryptionKey(this._cek);
        }
        if (this._keyManagementParameters) {
          enc2.setKeyManagementParameters(this._keyManagementParameters);
        }
        return enc2.encrypt(key2, options2);
      }
    };
  }
});

// node_modules/jose/dist/browser/jwk/thumbprint.js
async function calculateJwkThumbprint(jwk, digestAlgorithm) {
  if (!isObject(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  digestAlgorithm ?? (digestAlgorithm = "sha256");
  if (digestAlgorithm !== "sha256" && digestAlgorithm !== "sha384" && digestAlgorithm !== "sha512") {
    throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
  }
  let components;
  switch (jwk.kty) {
    case "EC":
      check(jwk.crv, '"crv" (Curve) Parameter');
      check(jwk.x, '"x" (X Coordinate) Parameter');
      check(jwk.y, '"y" (Y Coordinate) Parameter');
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
      break;
    case "OKP":
      check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
      check(jwk.x, '"x" (Public Key) Parameter');
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
      break;
    case "RSA":
      check(jwk.e, '"e" (Exponent) Parameter');
      check(jwk.n, '"n" (Modulus) Parameter');
      components = { e: jwk.e, kty: jwk.kty, n: jwk.n };
      break;
    case "oct":
      check(jwk.k, '"k" (Key Value) Parameter');
      components = { k: jwk.k, kty: jwk.kty };
      break;
    default:
      throw new JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
  }
  const data = encoder.encode(JSON.stringify(components));
  return encode(await digest_default(digestAlgorithm, data));
}
var check;
var init_thumbprint = __esm({
  "node_modules/jose/dist/browser/jwk/thumbprint.js"() {
    init_digest();
    init_base64url();
    init_errors2();
    init_buffer_utils();
    init_is_object();
    check = (value, description) => {
      if (typeof value !== "string" || !value) {
        throw new JWKInvalid(`${description} missing or invalid`);
      }
    };
  }
});

// node_modules/jose/dist/browser/jwk/embedded.js
var init_embedded = __esm({
  "node_modules/jose/dist/browser/jwk/embedded.js"() {
    init_import();
    init_is_object();
    init_errors2();
  }
});

// node_modules/jose/dist/browser/jwks/local.js
var init_local = __esm({
  "node_modules/jose/dist/browser/jwks/local.js"() {
    init_import();
    init_errors2();
    init_is_object();
  }
});

// node_modules/jose/dist/browser/runtime/fetch_jwks.js
var init_fetch_jwks = __esm({
  "node_modules/jose/dist/browser/runtime/fetch_jwks.js"() {
    init_errors2();
  }
});

// node_modules/jose/dist/browser/jwks/remote.js
var USER_AGENT;
var init_remote = __esm({
  "node_modules/jose/dist/browser/jwks/remote.js"() {
    init_fetch_jwks();
    init_errors2();
    init_local();
    if (typeof navigator === "undefined" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) {
      const NAME = "jose";
      const VERSION = "v5.2.3";
      USER_AGENT = `${NAME}/${VERSION}`;
    }
  }
});

// node_modules/jose/dist/browser/jwt/unsecured.js
var init_unsecured = __esm({
  "node_modules/jose/dist/browser/jwt/unsecured.js"() {
    init_base64url();
    init_buffer_utils();
    init_errors2();
    init_jwt_claims_set();
    init_produce();
  }
});

// node_modules/jose/dist/browser/util/base64url.js
var base64url_exports2 = {};
__export(base64url_exports2, {
  decode: () => decode2,
  encode: () => encode2
});
var encode2, decode2;
var init_base64url2 = __esm({
  "node_modules/jose/dist/browser/util/base64url.js"() {
    init_base64url();
    encode2 = encode;
    decode2 = decode;
  }
});

// node_modules/jose/dist/browser/util/decode_protected_header.js
var init_decode_protected_header = __esm({
  "node_modules/jose/dist/browser/util/decode_protected_header.js"() {
    init_base64url2();
    init_buffer_utils();
    init_is_object();
  }
});

// node_modules/jose/dist/browser/util/decode_jwt.js
var init_decode_jwt = __esm({
  "node_modules/jose/dist/browser/util/decode_jwt.js"() {
    init_base64url2();
    init_buffer_utils();
    init_is_object();
    init_errors2();
  }
});

// node_modules/jose/dist/browser/runtime/generate.js
var init_generate = __esm({
  "node_modules/jose/dist/browser/runtime/generate.js"() {
    init_webcrypto();
    init_errors2();
    init_random();
  }
});

// node_modules/jose/dist/browser/key/generate_key_pair.js
var init_generate_key_pair = __esm({
  "node_modules/jose/dist/browser/key/generate_key_pair.js"() {
    init_generate();
  }
});

// node_modules/jose/dist/browser/key/generate_secret.js
var init_generate_secret = __esm({
  "node_modules/jose/dist/browser/key/generate_secret.js"() {
    init_generate();
  }
});

// node_modules/jose/dist/browser/runtime/runtime.js
var init_runtime = __esm({
  "node_modules/jose/dist/browser/runtime/runtime.js"() {
  }
});

// node_modules/jose/dist/browser/util/runtime.js
var init_runtime2 = __esm({
  "node_modules/jose/dist/browser/util/runtime.js"() {
    init_runtime();
  }
});

// node_modules/jose/dist/browser/index.js
var init_browser = __esm({
  "node_modules/jose/dist/browser/index.js"() {
    init_decrypt3();
    init_decrypt2();
    init_decrypt4();
    init_encrypt3();
    init_verify3();
    init_verify2();
    init_verify4();
    init_verify5();
    init_decrypt5();
    init_encrypt4();
    init_encrypt2();
    init_sign3();
    init_sign2();
    init_sign4();
    init_sign5();
    init_encrypt5();
    init_thumbprint();
    init_embedded();
    init_local();
    init_remote();
    init_unsecured();
    init_export();
    init_import();
    init_decode_protected_header();
    init_decode_jwt();
    init_errors2();
    init_generate_key_pair();
    init_generate_secret();
    init_base64url2();
    init_runtime2();
  }
});

// node_modules/cookie/index.js
var require_cookie = __commonJS({
  "node_modules/cookie/index.js"(exports) {
    "use strict";
    exports.parse = parse6;
    exports.serialize = serialize3;
    var __toString = Object.prototype.toString;
    var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
    function parse6(str, options2) {
      if (typeof str !== "string") {
        throw new TypeError("argument str must be a string");
      }
      var obj = {};
      var opt = options2 || {};
      var dec = opt.decode || decode4;
      var index5 = 0;
      while (index5 < str.length) {
        var eqIdx = str.indexOf("=", index5);
        if (eqIdx === -1) {
          break;
        }
        var endIdx = str.indexOf(";", index5);
        if (endIdx === -1) {
          endIdx = str.length;
        } else if (endIdx < eqIdx) {
          index5 = str.lastIndexOf(";", eqIdx - 1) + 1;
          continue;
        }
        var key2 = str.slice(index5, eqIdx).trim();
        if (void 0 === obj[key2]) {
          var val = str.slice(eqIdx + 1, endIdx).trim();
          if (val.charCodeAt(0) === 34) {
            val = val.slice(1, -1);
          }
          obj[key2] = tryDecode(val, dec);
        }
        index5 = endIdx + 1;
      }
      return obj;
    }
    function serialize3(name, val, options2) {
      var opt = options2 || {};
      var enc2 = opt.encode || encode5;
      if (typeof enc2 !== "function") {
        throw new TypeError("option encode is invalid");
      }
      if (!fieldContentRegExp.test(name)) {
        throw new TypeError("argument name is invalid");
      }
      var value = enc2(val);
      if (value && !fieldContentRegExp.test(value)) {
        throw new TypeError("argument val is invalid");
      }
      var str = name + "=" + value;
      if (null != opt.maxAge) {
        var maxAge = opt.maxAge - 0;
        if (isNaN(maxAge) || !isFinite(maxAge)) {
          throw new TypeError("option maxAge is invalid");
        }
        str += "; Max-Age=" + Math.floor(maxAge);
      }
      if (opt.domain) {
        if (!fieldContentRegExp.test(opt.domain)) {
          throw new TypeError("option domain is invalid");
        }
        str += "; Domain=" + opt.domain;
      }
      if (opt.path) {
        if (!fieldContentRegExp.test(opt.path)) {
          throw new TypeError("option path is invalid");
        }
        str += "; Path=" + opt.path;
      }
      if (opt.expires) {
        var expires = opt.expires;
        if (!isDate(expires) || isNaN(expires.valueOf())) {
          throw new TypeError("option expires is invalid");
        }
        str += "; Expires=" + expires.toUTCString();
      }
      if (opt.httpOnly) {
        str += "; HttpOnly";
      }
      if (opt.secure) {
        str += "; Secure";
      }
      if (opt.partitioned) {
        str += "; Partitioned";
      }
      if (opt.priority) {
        var priority = typeof opt.priority === "string" ? opt.priority.toLowerCase() : opt.priority;
        switch (priority) {
          case "low":
            str += "; Priority=Low";
            break;
          case "medium":
            str += "; Priority=Medium";
            break;
          case "high":
            str += "; Priority=High";
            break;
          default:
            throw new TypeError("option priority is invalid");
        }
      }
      if (opt.sameSite) {
        var sameSite = typeof opt.sameSite === "string" ? opt.sameSite.toLowerCase() : opt.sameSite;
        switch (sameSite) {
          case true:
            str += "; SameSite=Strict";
            break;
          case "lax":
            str += "; SameSite=Lax";
            break;
          case "strict":
            str += "; SameSite=Strict";
            break;
          case "none":
            str += "; SameSite=None";
            break;
          default:
            throw new TypeError("option sameSite is invalid");
        }
      }
      return str;
    }
    function decode4(str) {
      return str.indexOf("%") !== -1 ? decodeURIComponent(str) : str;
    }
    function encode5(val) {
      return encodeURIComponent(val);
    }
    function isDate(val) {
      return __toString.call(val) === "[object Date]" || val instanceof Date;
    }
    function tryDecode(str, decode5) {
      try {
        return decode5(str);
      } catch (e2) {
        return str;
      }
    }
  }
});

// node_modules/@auth/core/jwt.js
async function encode3(params) {
  const { token = {}, secret, maxAge = DEFAULT_MAX_AGE, salt } = params;
  const secrets = Array.isArray(secret) ? secret : [secret];
  const encryptionSecret = await getDerivedEncryptionKey(enc, secrets[0], salt);
  const thumbprint = await calculateJwkThumbprint({ kty: "oct", k: base64url_exports2.encode(encryptionSecret) }, `sha${encryptionSecret.byteLength << 3}`);
  return await new EncryptJWT(token).setProtectedHeader({ alg, enc, kid: thumbprint }).setIssuedAt().setExpirationTime(now() + maxAge).setJti(crypto.randomUUID()).encrypt(encryptionSecret);
}
async function decode3(params) {
  const { token, secret, salt } = params;
  const secrets = Array.isArray(secret) ? secret : [secret];
  if (!token)
    return null;
  const { payload } = await jwtDecrypt(token, async ({ kid, enc: enc2 }) => {
    for (const secret2 of secrets) {
      const encryptionSecret = await getDerivedEncryptionKey(enc2, secret2, salt);
      if (kid === void 0)
        return encryptionSecret;
      const thumbprint = await calculateJwkThumbprint({ kty: "oct", k: base64url_exports2.encode(encryptionSecret) }, `sha${encryptionSecret.byteLength << 3}`);
      if (kid === thumbprint)
        return encryptionSecret;
    }
    throw new Error("no matching decryption secret");
  }, {
    clockTolerance: 15,
    keyManagementAlgorithms: [alg],
    contentEncryptionAlgorithms: [enc, "A256GCM"]
  });
  return payload;
}
async function getDerivedEncryptionKey(enc2, keyMaterial, salt) {
  let length;
  switch (enc2) {
    case "A256CBC-HS512":
      length = 64;
      break;
    case "A256GCM":
      length = 32;
      break;
    default:
      throw new Error("Unsupported JWT Content Encryption Algorithm");
  }
  return await hkdf("sha256", keyMaterial, salt, `Auth.js Generated Encryption Key (${salt})`, length);
}
var import_cookie3, DEFAULT_MAX_AGE, now, alg, enc;
var init_jwt = __esm({
  "node_modules/@auth/core/jwt.js"() {
    init_web();
    init_browser();
    init_cookie();
    init_errors();
    import_cookie3 = __toESM(require_cookie(), 1);
    DEFAULT_MAX_AGE = 30 * 24 * 60 * 60;
    now = () => Date.now() / 1e3 | 0;
    alg = "dir";
    enc = "A256CBC-HS512";
  }
});

// node_modules/@auth/core/lib/utils/callback-url.js
async function createCallbackUrl({ options: options2, paramValue, cookieValue }) {
  const { url, callbacks } = options2;
  let callbackUrl = url.origin;
  if (paramValue) {
    callbackUrl = await callbacks.redirect({
      url: paramValue,
      baseUrl: url.origin
    });
  } else if (cookieValue) {
    callbackUrl = await callbacks.redirect({
      url: cookieValue,
      baseUrl: url.origin
    });
  }
  return {
    callbackUrl,
    // Save callback URL in a cookie so that it can be used for subsequent requests in signin/signout/callback flow
    callbackUrlCookie: callbackUrl !== cookieValue ? callbackUrl : void 0
  };
}
var init_callback_url = __esm({
  "node_modules/@auth/core/lib/utils/callback-url.js"() {
  }
});

// node_modules/@auth/core/lib/utils/logger.js
function setLogger(newLogger = {}, debug) {
  if (!debug)
    logger.debug = () => {
    };
  if (newLogger.error)
    logger.error = newLogger.error;
  if (newLogger.warn)
    logger.warn = newLogger.warn;
  if (newLogger.debug)
    logger.debug = newLogger.debug;
}
var red, yellow, grey, reset, logger;
var init_logger = __esm({
  "node_modules/@auth/core/lib/utils/logger.js"() {
    init_errors();
    red = "\x1B[31m";
    yellow = "\x1B[33m";
    grey = "\x1B[90m";
    reset = "\x1B[0m";
    logger = {
      error(error) {
        const name = error instanceof AuthError ? error.type : error.name;
        console.error(`${red}[auth][error]${reset} ${name}: ${error.message}`);
        if (error.cause && typeof error.cause === "object" && "err" in error.cause && error.cause.err instanceof Error) {
          const { err, ...data } = error.cause;
          console.error(`${red}[auth][cause]${reset}:`, err.stack);
          if (data)
            console.error(`${red}[auth][details]${reset}:`, JSON.stringify(data, null, 2));
        } else if (error.stack) {
          console.error(error.stack.replace(/.*/, "").substring(1));
        }
      },
      warn(code) {
        const url = `https://warnings.authjs.dev#${code}`;
        console.warn(`${yellow}[auth][warn][${code}]${reset}`, `Read more: ${url}`);
      },
      debug(message2, metadata) {
        console.log(`${grey}[auth][debug]:${reset} ${message2}`, JSON.stringify(metadata, null, 2));
      }
    };
  }
});

// node_modules/@auth/core/lib/utils/actions.js
function isAuthAction(action) {
  return actions.includes(action);
}
var actions;
var init_actions = __esm({
  "node_modules/@auth/core/lib/utils/actions.js"() {
    actions = [
      "providers",
      "session",
      "csrf",
      "signin",
      "signout",
      "callback",
      "verify-request",
      "error",
      "webauthn-options"
    ];
  }
});

// node_modules/@auth/core/lib/utils/web.js
async function getBody(req) {
  if (!("body" in req) || !req.body || req.method !== "POST")
    return;
  const contentType = req.headers.get("content-type");
  if (contentType?.includes("application/json")) {
    return await req.json();
  } else if (contentType?.includes("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(await req.text());
    return Object.fromEntries(params);
  }
}
async function toInternalRequest(req, config4) {
  try {
    if (req.method !== "GET" && req.method !== "POST")
      throw new UnknownAction("Only GET and POST requests are supported.");
    config4.basePath ?? (config4.basePath = "/auth");
    const url = new URL(req.url);
    const { action, providerId } = parseActionAndProviderId(url.pathname, config4.basePath);
    return {
      url,
      action,
      providerId,
      method: req.method,
      headers: Object.fromEntries(req.headers),
      body: req.body ? await getBody(req) : void 0,
      cookies: (0, import_cookie4.parse)(req.headers.get("cookie") ?? "") ?? {},
      error: url.searchParams.get("error") ?? void 0,
      query: Object.fromEntries(url.searchParams)
    };
  } catch (e2) {
    logger.error(e2);
    logger.debug("request", req);
  }
}
function toRequest(request) {
  return new Request(request.url, {
    headers: request.headers,
    method: request.method,
    body: request.method === "POST" ? JSON.stringify(request.body ?? {}) : void 0
  });
}
function toResponse(res) {
  const headers2 = new Headers(res.headers);
  res.cookies?.forEach((cookie) => {
    const { name, value, options: options2 } = cookie;
    const cookieHeader = (0, import_cookie4.serialize)(name, value, options2);
    if (headers2.has("Set-Cookie"))
      headers2.append("Set-Cookie", cookieHeader);
    else
      headers2.set("Set-Cookie", cookieHeader);
  });
  let body2 = res.body;
  if (headers2.get("content-type") === "application/json")
    body2 = JSON.stringify(res.body);
  else if (headers2.get("content-type") === "application/x-www-form-urlencoded")
    body2 = new URLSearchParams(res.body).toString();
  const status = res.redirect ? 302 : res.status ?? 200;
  const response = new Response(body2, { headers: headers2, status });
  if (res.redirect)
    response.headers.set("Location", res.redirect);
  return response;
}
async function createHash(message2) {
  const data = new TextEncoder().encode(message2);
  const hash2 = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash2)).map((b3) => b3.toString(16).padStart(2, "0")).join("").toString();
}
function randomString(size) {
  const i2hex = (i3) => ("0" + i3.toString(16)).slice(-2);
  const r3 = (a3, i3) => a3 + i2hex(i3);
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  return Array.from(bytes).reduce(r3, "");
}
function parseActionAndProviderId(pathname, base2) {
  const a3 = pathname.match(new RegExp(`^${base2}(.+)`));
  if (a3 === null)
    throw new UnknownAction(`Cannot parse action at ${pathname}`);
  const [_4, actionAndProviderId] = a3;
  const b3 = actionAndProviderId.replace(/^\//, "").split("/");
  if (b3.length !== 1 && b3.length !== 2)
    throw new UnknownAction(`Cannot parse action at ${pathname}`);
  const [action, providerId] = b3;
  if (!isAuthAction(action))
    throw new UnknownAction(`Cannot parse action at ${pathname}`);
  if (providerId && !["signin", "callback", "webauthn-options"].includes(action))
    throw new UnknownAction(`Cannot parse action at ${pathname}`);
  return { action, providerId };
}
var import_cookie4;
var init_web2 = __esm({
  "node_modules/@auth/core/lib/utils/web.js"() {
    import_cookie4 = __toESM(require_cookie(), 1);
    init_errors();
    init_logger();
    init_actions();
  }
});

// node_modules/@auth/core/lib/actions/callback/oauth/csrf-token.js
async function createCSRFToken({ options: options2, cookieValue, isPost, bodyValue }) {
  if (cookieValue) {
    const [csrfToken2, csrfTokenHash2] = cookieValue.split("|");
    const expectedCsrfTokenHash = await createHash(`${csrfToken2}${options2.secret}`);
    if (csrfTokenHash2 === expectedCsrfTokenHash) {
      const csrfTokenVerified = isPost && csrfToken2 === bodyValue;
      return { csrfTokenVerified, csrfToken: csrfToken2 };
    }
  }
  const csrfToken = randomString(32);
  const csrfTokenHash = await createHash(`${csrfToken}${options2.secret}`);
  const cookie = `${csrfToken}|${csrfTokenHash}`;
  return { cookie, csrfToken };
}
function validateCSRF(action, verified) {
  if (verified)
    return;
  throw new MissingCSRF(`CSRF token was missing during an action ${action}.`);
}
var init_csrf_token = __esm({
  "node_modules/@auth/core/lib/actions/callback/oauth/csrf-token.js"() {
    init_web2();
    init_errors();
  }
});

// node_modules/@auth/core/lib/utils/merge.js
function isObject2(item) {
  return item && typeof item === "object" && !Array.isArray(item);
}
function merge(target, ...sources) {
  if (!sources.length)
    return target;
  const source = sources.shift();
  if (isObject2(target) && isObject2(source)) {
    for (const key2 in source) {
      if (isObject2(source[key2])) {
        if (!target[key2])
          Object.assign(target, { [key2]: {} });
        merge(target[key2], source[key2]);
      } else {
        Object.assign(target, { [key2]: source[key2] });
      }
    }
  }
  return merge(target, ...sources);
}
var init_merge = __esm({
  "node_modules/@auth/core/lib/utils/merge.js"() {
  }
});

// node_modules/@auth/core/lib/utils/providers.js
function parseProviders(params) {
  const { providerId, options: options2 } = params;
  const url = new URL(options2.basePath ?? "/auth", params.url.origin);
  const providers = params.providers.map((p3) => {
    const provider = typeof p3 === "function" ? p3() : p3;
    const { options: userOptions, ...defaults } = provider;
    const id = userOptions?.id ?? defaults.id;
    const merged = merge(defaults, userOptions, {
      signinUrl: `${url}/signin/${id}`,
      callbackUrl: `${url}/callback/${id}`
    });
    if (provider.type === "oauth" || provider.type === "oidc") {
      merged.redirectProxyUrl ?? (merged.redirectProxyUrl = options2.redirectProxyUrl);
      return normalizeOAuth(merged);
    }
    return merged;
  });
  return {
    providers,
    provider: providers.find(({ id }) => id === providerId)
  };
}
function normalizeOAuth(c3) {
  if (c3.issuer)
    c3.wellKnown ?? (c3.wellKnown = `${c3.issuer}/.well-known/openid-configuration`);
  const authorization = normalizeEndpoint(c3.authorization, c3.issuer);
  if (authorization && !authorization.url?.searchParams.has("scope")) {
    authorization.url.searchParams.set("scope", "openid profile email");
  }
  const token = normalizeEndpoint(c3.token, c3.issuer);
  const userinfo = normalizeEndpoint(c3.userinfo, c3.issuer);
  const checks = c3.checks ?? ["pkce"];
  if (c3.redirectProxyUrl) {
    if (!checks.includes("state"))
      checks.push("state");
    c3.redirectProxyUrl = `${c3.redirectProxyUrl}/callback/${c3.id}`;
  }
  return {
    ...c3,
    authorization,
    token,
    checks,
    userinfo,
    profile: c3.profile ?? defaultProfile,
    account: c3.account ?? defaultAccount
  };
}
function stripUndefined(o4) {
  const result = {};
  for (let [k3, v3] of Object.entries(o4))
    v3 !== void 0 && (result[k3] = v3);
  return result;
}
function normalizeEndpoint(e2, issuer) {
  if (!e2 && issuer)
    return;
  if (typeof e2 === "string") {
    return { url: new URL(e2) };
  }
  const url = new URL(e2?.url ?? "https://authjs.dev");
  if (e2?.params != null) {
    for (let [key2, value] of Object.entries(e2.params)) {
      if (key2 === "claims")
        value = JSON.stringify(value);
      url.searchParams.set(key2, String(value));
    }
  }
  return { url, request: e2?.request, conform: e2?.conform };
}
var defaultProfile, defaultAccount;
var init_providers = __esm({
  "node_modules/@auth/core/lib/utils/providers.js"() {
    init_merge();
    defaultProfile = (profile) => {
      return stripUndefined({
        id: profile.sub ?? profile.id ?? crypto.randomUUID(),
        name: profile.name ?? profile.nickname ?? profile.preferred_username,
        email: profile.email,
        image: profile.picture
      });
    };
    defaultAccount = (account) => {
      return stripUndefined({
        access_token: account.access_token,
        id_token: account.id_token,
        refresh_token: account.refresh_token,
        expires_at: account.expires_at,
        scope: account.scope,
        token_type: account.token_type,
        session_state: account.session_state
      });
    };
  }
});

// node_modules/@auth/core/lib/init.js
async function init({ authOptions, providerId, action, url, cookies: reqCookies, callbackUrl: reqCallbackUrl, csrfToken: reqCsrfToken, csrfDisabled, isPost }) {
  const { providers, provider } = parseProviders({
    providers: authOptions.providers,
    url,
    providerId,
    options: authOptions
  });
  const maxAge = 30 * 24 * 60 * 60;
  let isOnRedirectProxy = false;
  if ((provider?.type === "oauth" || provider?.type === "oidc") && provider.redirectProxyUrl) {
    try {
      isOnRedirectProxy = new URL(provider.redirectProxyUrl).origin === url.origin;
    } catch {
      throw new TypeError(`redirectProxyUrl must be a valid URL. Received: ${provider.redirectProxyUrl}`);
    }
  }
  const options2 = {
    debug: false,
    pages: {},
    theme: {
      colorScheme: "auto",
      logo: "",
      brandColor: "",
      buttonText: ""
    },
    // Custom options override defaults
    ...authOptions,
    // These computed settings can have values in userOptions but we override them
    // and are request-specific.
    url,
    action,
    // @ts-expect-errors
    provider,
    cookies: merge(defaultCookies(authOptions.useSecureCookies ?? url.protocol === "https:"), authOptions.cookies),
    providers,
    // Session options
    session: {
      // If no adapter specified, force use of JSON Web Tokens (stateless)
      strategy: authOptions.adapter ? "database" : "jwt",
      maxAge,
      updateAge: 24 * 60 * 60,
      generateSessionToken: () => crypto.randomUUID(),
      ...authOptions.session
    },
    // JWT options
    jwt: {
      secret: authOptions.secret,
      // Asserted in assert.ts
      maxAge: authOptions.session?.maxAge ?? maxAge,
      // default to same as `session.maxAge`
      encode: encode3,
      decode: decode3,
      ...authOptions.jwt
    },
    // Event messages
    events: eventsErrorHandler(authOptions.events ?? {}, logger),
    adapter: adapterErrorHandler(authOptions.adapter, logger),
    // Callback functions
    callbacks: { ...defaultCallbacks, ...authOptions.callbacks },
    logger,
    callbackUrl: url.origin,
    isOnRedirectProxy,
    experimental: {
      ...authOptions.experimental
    }
  };
  const cookies = [];
  if (csrfDisabled) {
    options2.csrfTokenVerified = true;
  } else {
    const { csrfToken, cookie: csrfCookie, csrfTokenVerified } = await createCSRFToken({
      options: options2,
      cookieValue: reqCookies?.[options2.cookies.csrfToken.name],
      isPost,
      bodyValue: reqCsrfToken
    });
    options2.csrfToken = csrfToken;
    options2.csrfTokenVerified = csrfTokenVerified;
    if (csrfCookie) {
      cookies.push({
        name: options2.cookies.csrfToken.name,
        value: csrfCookie,
        options: options2.cookies.csrfToken.options
      });
    }
  }
  const { callbackUrl, callbackUrlCookie } = await createCallbackUrl({
    options: options2,
    cookieValue: reqCookies?.[options2.cookies.callbackUrl.name],
    paramValue: reqCallbackUrl
  });
  options2.callbackUrl = callbackUrl;
  if (callbackUrlCookie) {
    cookies.push({
      name: options2.cookies.callbackUrl.name,
      value: callbackUrlCookie,
      options: options2.cookies.callbackUrl.options
    });
  }
  return { options: options2, cookies };
}
function eventsErrorHandler(methods, logger2) {
  return Object.keys(methods).reduce((acc, name) => {
    acc[name] = async (...args) => {
      try {
        const method = methods[name];
        return await method(...args);
      } catch (e2) {
        logger2.error(new EventError(e2));
      }
    };
    return acc;
  }, {});
}
function adapterErrorHandler(adapter, logger2) {
  if (!adapter)
    return;
  return Object.keys(adapter).reduce((acc, name) => {
    acc[name] = async (...args) => {
      try {
        logger2.debug(`adapter_${name}`, { args });
        const method = adapter[name];
        return await method(...args);
      } catch (e2) {
        const error = new AdapterError(e2);
        logger2.error(error);
        throw error;
      }
    };
    return acc;
  }, {});
}
var defaultCallbacks;
var init_init = __esm({
  "node_modules/@auth/core/lib/init.js"() {
    init_jwt();
    init_callback_url();
    init_cookie();
    init_csrf_token();
    init_errors();
    init_providers();
    init_logger();
    init_merge();
    defaultCallbacks = {
      signIn() {
        return true;
      },
      redirect({ url, baseUrl }) {
        if (url.startsWith("/"))
          return `${baseUrl}${url}`;
        else if (new URL(url).origin === baseUrl)
          return url;
        return baseUrl;
      },
      session({ session: session2 }) {
        return {
          user: {
            name: session2.user?.name,
            email: session2.user?.email,
            image: session2.user?.image
          },
          expires: session2.expires?.toISOString?.() ?? session2.expires
        };
      },
      jwt({ token }) {
        return token;
      }
    };
  }
});

// node_modules/preact/dist/preact.module.js
function s(n3, l3) {
  for (var u3 in l3)
    n3[u3] = l3[u3];
  return n3;
}
function a(n3) {
  var l3 = n3.parentNode;
  l3 && l3.removeChild(n3);
}
function v(n3, i3, t2, o4, r3) {
  var f3 = { type: n3, props: i3, key: t2, ref: o4, __k: null, __: null, __b: 0, __e: null, __d: void 0, __c: null, __h: null, constructor: void 0, __v: null == r3 ? ++u : r3 };
  return null == r3 && null != l.vnode && l.vnode(f3), f3;
}
function p(n3) {
  return n3.children;
}
function d(n3, l3) {
  this.props = n3, this.context = l3;
}
function _(n3, l3) {
  if (null == l3)
    return n3.__ ? _(n3.__, n3.__.__k.indexOf(n3) + 1) : null;
  for (var u3; l3 < n3.__k.length; l3++)
    if (null != (u3 = n3.__k[l3]) && null != u3.__e)
      return u3.__e;
  return "function" == typeof n3.type ? _(n3) : null;
}
function k(n3) {
  var l3, u3;
  if (null != (n3 = n3.__) && null != n3.__c) {
    for (n3.__e = n3.__c.base = null, l3 = 0; l3 < n3.__k.length; l3++)
      if (null != (u3 = n3.__k[l3]) && null != u3.__e) {
        n3.__e = n3.__c.base = u3.__e;
        break;
      }
    return k(n3);
  }
}
function b(n3) {
  (!n3.__d && (n3.__d = true) && t.push(n3) && !g.__r++ || o !== l.debounceRendering) && ((o = l.debounceRendering) || setTimeout)(g);
}
function g() {
  for (var n3; g.__r = t.length; )
    n3 = t.sort(function(n4, l3) {
      return n4.__v.__b - l3.__v.__b;
    }), t = [], n3.some(function(n4) {
      var l3, u3, i3, t2, o4, r3;
      n4.__d && (o4 = (t2 = (l3 = n4).__v).__e, (r3 = l3.__P) && (u3 = [], (i3 = s({}, t2)).__v = t2.__v + 1, j(r3, t2, i3, l3.__n, void 0 !== r3.ownerSVGElement, null != t2.__h ? [o4] : null, u3, null == o4 ? _(t2) : o4, t2.__h), z(u3, t2), t2.__e != o4 && k(t2)));
    });
}
function w(n3, l3, u3, i3, t2, o4, r3, c3, s4, a3) {
  var h2, y2, d3, k3, b3, g3, w3, x2 = i3 && i3.__k || e, C3 = x2.length;
  for (u3.__k = [], h2 = 0; h2 < l3.length; h2++)
    if (null != (k3 = u3.__k[h2] = null == (k3 = l3[h2]) || "boolean" == typeof k3 ? null : "string" == typeof k3 || "number" == typeof k3 || "bigint" == typeof k3 ? v(null, k3, null, null, k3) : Array.isArray(k3) ? v(p, { children: k3 }, null, null, null) : k3.__b > 0 ? v(k3.type, k3.props, k3.key, k3.ref ? k3.ref : null, k3.__v) : k3)) {
      if (k3.__ = u3, k3.__b = u3.__b + 1, null === (d3 = x2[h2]) || d3 && k3.key == d3.key && k3.type === d3.type)
        x2[h2] = void 0;
      else
        for (y2 = 0; y2 < C3; y2++) {
          if ((d3 = x2[y2]) && k3.key == d3.key && k3.type === d3.type) {
            x2[y2] = void 0;
            break;
          }
          d3 = null;
        }
      j(n3, k3, d3 = d3 || f, t2, o4, r3, c3, s4, a3), b3 = k3.__e, (y2 = k3.ref) && d3.ref != y2 && (w3 || (w3 = []), d3.ref && w3.push(d3.ref, null, k3), w3.push(y2, k3.__c || b3, k3)), null != b3 ? (null == g3 && (g3 = b3), "function" == typeof k3.type && k3.__k === d3.__k ? k3.__d = s4 = m(k3, s4, n3) : s4 = A(n3, k3, d3, x2, b3, s4), "function" == typeof u3.type && (u3.__d = s4)) : s4 && d3.__e == s4 && s4.parentNode != n3 && (s4 = _(d3));
    }
  for (u3.__e = g3, h2 = C3; h2--; )
    null != x2[h2] && N(x2[h2], x2[h2]);
  if (w3)
    for (h2 = 0; h2 < w3.length; h2++)
      M(w3[h2], w3[++h2], w3[++h2]);
}
function m(n3, l3, u3) {
  for (var i3, t2 = n3.__k, o4 = 0; t2 && o4 < t2.length; o4++)
    (i3 = t2[o4]) && (i3.__ = n3, l3 = "function" == typeof i3.type ? m(i3, l3, u3) : A(u3, i3, i3, t2, i3.__e, l3));
  return l3;
}
function A(n3, l3, u3, i3, t2, o4) {
  var r3, f3, e2;
  if (void 0 !== l3.__d)
    r3 = l3.__d, l3.__d = void 0;
  else if (null == u3 || t2 != o4 || null == t2.parentNode)
    n:
      if (null == o4 || o4.parentNode !== n3)
        n3.appendChild(t2), r3 = null;
      else {
        for (f3 = o4, e2 = 0; (f3 = f3.nextSibling) && e2 < i3.length; e2 += 1)
          if (f3 == t2)
            break n;
        n3.insertBefore(t2, o4), r3 = o4;
      }
  return void 0 !== r3 ? r3 : t2.nextSibling;
}
function C(n3, l3, u3, i3, t2) {
  var o4;
  for (o4 in u3)
    "children" === o4 || "key" === o4 || o4 in l3 || H(n3, o4, null, u3[o4], i3);
  for (o4 in l3)
    t2 && "function" != typeof l3[o4] || "children" === o4 || "key" === o4 || "value" === o4 || "checked" === o4 || u3[o4] === l3[o4] || H(n3, o4, l3[o4], u3[o4], i3);
}
function $(n3, l3, u3) {
  "-" === l3[0] ? n3.setProperty(l3, u3) : n3[l3] = null == u3 ? "" : "number" != typeof u3 || c.test(l3) ? u3 : u3 + "px";
}
function H(n3, l3, u3, i3, t2) {
  var o4;
  n:
    if ("style" === l3)
      if ("string" == typeof u3)
        n3.style.cssText = u3;
      else {
        if ("string" == typeof i3 && (n3.style.cssText = i3 = ""), i3)
          for (l3 in i3)
            u3 && l3 in u3 || $(n3.style, l3, "");
        if (u3)
          for (l3 in u3)
            i3 && u3[l3] === i3[l3] || $(n3.style, l3, u3[l3]);
      }
    else if ("o" === l3[0] && "n" === l3[1])
      o4 = l3 !== (l3 = l3.replace(/Capture$/, "")), l3 = l3.toLowerCase() in n3 ? l3.toLowerCase().slice(2) : l3.slice(2), n3.l || (n3.l = {}), n3.l[l3 + o4] = u3, u3 ? i3 || n3.addEventListener(l3, o4 ? T : I, o4) : n3.removeEventListener(l3, o4 ? T : I, o4);
    else if ("dangerouslySetInnerHTML" !== l3) {
      if (t2)
        l3 = l3.replace(/xlink(H|:h)/, "h").replace(/sName$/, "s");
      else if ("href" !== l3 && "list" !== l3 && "form" !== l3 && "tabIndex" !== l3 && "download" !== l3 && l3 in n3)
        try {
          n3[l3] = null == u3 ? "" : u3;
          break n;
        } catch (n4) {
        }
      "function" == typeof u3 || (null == u3 || false === u3 && -1 == l3.indexOf("-") ? n3.removeAttribute(l3) : n3.setAttribute(l3, u3));
    }
}
function I(n3) {
  this.l[n3.type + false](l.event ? l.event(n3) : n3);
}
function T(n3) {
  this.l[n3.type + true](l.event ? l.event(n3) : n3);
}
function j(n3, u3, i3, t2, o4, r3, f3, e2, c3) {
  var a3, h2, v3, y2, _4, k3, b3, g3, m3, x2, A2, C3, $2, H2, I2, T2 = u3.type;
  if (void 0 !== u3.constructor)
    return null;
  null != i3.__h && (c3 = i3.__h, e2 = u3.__e = i3.__e, u3.__h = null, r3 = [e2]), (a3 = l.__b) && a3(u3);
  try {
    n:
      if ("function" == typeof T2) {
        if (g3 = u3.props, m3 = (a3 = T2.contextType) && t2[a3.__c], x2 = a3 ? m3 ? m3.props.value : a3.__ : t2, i3.__c ? b3 = (h2 = u3.__c = i3.__c).__ = h2.__E : ("prototype" in T2 && T2.prototype.render ? u3.__c = h2 = new T2(g3, x2) : (u3.__c = h2 = new d(g3, x2), h2.constructor = T2, h2.render = O), m3 && m3.sub(h2), h2.props = g3, h2.state || (h2.state = {}), h2.context = x2, h2.__n = t2, v3 = h2.__d = true, h2.__h = [], h2._sb = []), null == h2.__s && (h2.__s = h2.state), null != T2.getDerivedStateFromProps && (h2.__s == h2.state && (h2.__s = s({}, h2.__s)), s(h2.__s, T2.getDerivedStateFromProps(g3, h2.__s))), y2 = h2.props, _4 = h2.state, v3)
          null == T2.getDerivedStateFromProps && null != h2.componentWillMount && h2.componentWillMount(), null != h2.componentDidMount && h2.__h.push(h2.componentDidMount);
        else {
          if (null == T2.getDerivedStateFromProps && g3 !== y2 && null != h2.componentWillReceiveProps && h2.componentWillReceiveProps(g3, x2), !h2.__e && null != h2.shouldComponentUpdate && false === h2.shouldComponentUpdate(g3, h2.__s, x2) || u3.__v === i3.__v) {
            for (h2.props = g3, h2.state = h2.__s, u3.__v !== i3.__v && (h2.__d = false), h2.__v = u3, u3.__e = i3.__e, u3.__k = i3.__k, u3.__k.forEach(function(n4) {
              n4 && (n4.__ = u3);
            }), A2 = 0; A2 < h2._sb.length; A2++)
              h2.__h.push(h2._sb[A2]);
            h2._sb = [], h2.__h.length && f3.push(h2);
            break n;
          }
          null != h2.componentWillUpdate && h2.componentWillUpdate(g3, h2.__s, x2), null != h2.componentDidUpdate && h2.__h.push(function() {
            h2.componentDidUpdate(y2, _4, k3);
          });
        }
        if (h2.context = x2, h2.props = g3, h2.__v = u3, h2.__P = n3, C3 = l.__r, $2 = 0, "prototype" in T2 && T2.prototype.render) {
          for (h2.state = h2.__s, h2.__d = false, C3 && C3(u3), a3 = h2.render(h2.props, h2.state, h2.context), H2 = 0; H2 < h2._sb.length; H2++)
            h2.__h.push(h2._sb[H2]);
          h2._sb = [];
        } else
          do {
            h2.__d = false, C3 && C3(u3), a3 = h2.render(h2.props, h2.state, h2.context), h2.state = h2.__s;
          } while (h2.__d && ++$2 < 25);
        h2.state = h2.__s, null != h2.getChildContext && (t2 = s(s({}, t2), h2.getChildContext())), v3 || null == h2.getSnapshotBeforeUpdate || (k3 = h2.getSnapshotBeforeUpdate(y2, _4)), I2 = null != a3 && a3.type === p && null == a3.key ? a3.props.children : a3, w(n3, Array.isArray(I2) ? I2 : [I2], u3, i3, t2, o4, r3, f3, e2, c3), h2.base = u3.__e, u3.__h = null, h2.__h.length && f3.push(h2), b3 && (h2.__E = h2.__ = null), h2.__e = false;
      } else
        null == r3 && u3.__v === i3.__v ? (u3.__k = i3.__k, u3.__e = i3.__e) : u3.__e = L(i3.__e, u3, i3, t2, o4, r3, f3, c3);
    (a3 = l.diffed) && a3(u3);
  } catch (n4) {
    u3.__v = null, (c3 || null != r3) && (u3.__e = e2, u3.__h = !!c3, r3[r3.indexOf(e2)] = null), l.__e(n4, u3, i3);
  }
}
function z(n3, u3) {
  l.__c && l.__c(u3, n3), n3.some(function(u4) {
    try {
      n3 = u4.__h, u4.__h = [], n3.some(function(n4) {
        n4.call(u4);
      });
    } catch (n4) {
      l.__e(n4, u4.__v);
    }
  });
}
function L(l3, u3, i3, t2, o4, r3, e2, c3) {
  var s4, h2, v3, y2 = i3.props, p3 = u3.props, d3 = u3.type, k3 = 0;
  if ("svg" === d3 && (o4 = true), null != r3) {
    for (; k3 < r3.length; k3++)
      if ((s4 = r3[k3]) && "setAttribute" in s4 == !!d3 && (d3 ? s4.localName === d3 : 3 === s4.nodeType)) {
        l3 = s4, r3[k3] = null;
        break;
      }
  }
  if (null == l3) {
    if (null === d3)
      return document.createTextNode(p3);
    l3 = o4 ? document.createElementNS("http://www.w3.org/2000/svg", d3) : document.createElement(d3, p3.is && p3), r3 = null, c3 = false;
  }
  if (null === d3)
    y2 === p3 || c3 && l3.data === p3 || (l3.data = p3);
  else {
    if (r3 = r3 && n.call(l3.childNodes), h2 = (y2 = i3.props || f).dangerouslySetInnerHTML, v3 = p3.dangerouslySetInnerHTML, !c3) {
      if (null != r3)
        for (y2 = {}, k3 = 0; k3 < l3.attributes.length; k3++)
          y2[l3.attributes[k3].name] = l3.attributes[k3].value;
      (v3 || h2) && (v3 && (h2 && v3.__html == h2.__html || v3.__html === l3.innerHTML) || (l3.innerHTML = v3 && v3.__html || ""));
    }
    if (C(l3, p3, y2, o4, c3), v3)
      u3.__k = [];
    else if (k3 = u3.props.children, w(l3, Array.isArray(k3) ? k3 : [k3], u3, i3, t2, o4 && "foreignObject" !== d3, r3, e2, r3 ? r3[0] : i3.__k && _(i3, 0), c3), null != r3)
      for (k3 = r3.length; k3--; )
        null != r3[k3] && a(r3[k3]);
    c3 || ("value" in p3 && void 0 !== (k3 = p3.value) && (k3 !== l3.value || "progress" === d3 && !k3 || "option" === d3 && k3 !== y2.value) && H(l3, "value", k3, y2.value, false), "checked" in p3 && void 0 !== (k3 = p3.checked) && k3 !== l3.checked && H(l3, "checked", k3, y2.checked, false));
  }
  return l3;
}
function M(n3, u3, i3) {
  try {
    "function" == typeof n3 ? n3(u3) : n3.current = u3;
  } catch (n4) {
    l.__e(n4, i3);
  }
}
function N(n3, u3, i3) {
  var t2, o4;
  if (l.unmount && l.unmount(n3), (t2 = n3.ref) && (t2.current && t2.current !== n3.__e || M(t2, null, u3)), null != (t2 = n3.__c)) {
    if (t2.componentWillUnmount)
      try {
        t2.componentWillUnmount();
      } catch (n4) {
        l.__e(n4, u3);
      }
    t2.base = t2.__P = null, n3.__c = void 0;
  }
  if (t2 = n3.__k)
    for (o4 = 0; o4 < t2.length; o4++)
      t2[o4] && N(t2[o4], u3, i3 || "function" != typeof n3.type);
  i3 || null == n3.__e || a(n3.__e), n3.__ = n3.__e = n3.__d = void 0;
}
function O(n3, l3, u3) {
  return this.constructor(n3, u3);
}
var n, l, u, i, t, o, r, f, e, c;
var init_preact_module = __esm({
  "node_modules/preact/dist/preact.module.js"() {
    f = {};
    e = [];
    c = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i;
    n = e.slice, l = { __e: function(n3, l3, u3, i3) {
      for (var t2, o4, r3; l3 = l3.__; )
        if ((t2 = l3.__c) && !t2.__)
          try {
            if ((o4 = t2.constructor) && null != o4.getDerivedStateFromError && (t2.setState(o4.getDerivedStateFromError(n3)), r3 = t2.__d), null != t2.componentDidCatch && (t2.componentDidCatch(n3, i3 || {}), r3 = t2.__d), r3)
              return t2.__E = t2;
          } catch (l4) {
            n3 = l4;
          }
      throw n3;
    } }, u = 0, i = function(n3) {
      return null != n3 && void 0 === n3.constructor;
    }, d.prototype.setState = function(n3, l3) {
      var u3;
      u3 = null != this.__s && this.__s !== this.state ? this.__s : this.__s = s({}, this.state), "function" == typeof n3 && (n3 = n3(s({}, u3), this.props)), n3 && s(u3, n3), null != n3 && this.__v && (l3 && this._sb.push(l3), b(this));
    }, d.prototype.forceUpdate = function(n3) {
      this.__v && (this.__e = true, n3 && this.__h.push(n3), b(this));
    }, d.prototype.render = p, t = [], g.__r = 0, r = 0;
  }
});

// node_modules/preact-render-to-string/dist/index.mjs
function l2(e2) {
  if (false === a2.test(e2 += ""))
    return e2;
  for (var t2 = 0, r3 = 0, n3 = "", o4 = ""; r3 < e2.length; r3++) {
    switch (e2.charCodeAt(r3)) {
      case 34:
        o4 = "&quot;";
        break;
      case 38:
        o4 = "&amp;";
        break;
      case 60:
        o4 = "&lt;";
        break;
      default:
        continue;
    }
    r3 !== t2 && (n3 += e2.slice(t2, r3)), n3 += o4, t2 = r3 + 1;
  }
  return r3 !== t2 && (n3 += e2.slice(t2, r3)), n3;
}
function p2(e2) {
  var t2 = "";
  for (var n3 in e2) {
    var o4 = e2[n3];
    null != o4 && "" !== o4 && (t2 && (t2 += " "), t2 += "-" == n3[0] ? n3 : c2[n3] || (c2[n3] = n3.replace(u2, "-$1").toLowerCase()), t2 = "number" == typeof o4 && false === r2.test(n3) ? t2 + ": " + o4 + "px;" : t2 + ": " + o4 + ";");
  }
  return t2 || void 0;
}
function _2(e2, t2) {
  return Array.isArray(t2) ? t2.reduce(_2, e2) : null != t2 && false !== t2 && e2.push(t2), e2;
}
function d2() {
  this.__d = true;
}
function v2(e2, t2) {
  return { __v: e2, context: t2, props: e2.props, setState: d2, forceUpdate: d2, __d: true, __h: [] };
}
function h(e2, t2) {
  var r3 = e2.contextType, n3 = r3 && t2[r3.__c];
  return null != r3 ? n3 ? n3.props.value : r3.__ : t2;
}
function y(r3, a3, c3, u3, d3, m3) {
  if (null == r3 || "boolean" == typeof r3)
    return "";
  if ("object" != typeof r3)
    return l2(r3);
  var b3 = c3.pretty, x2 = b3 && "string" == typeof b3 ? b3 : "	";
  if (Array.isArray(r3)) {
    for (var k3 = "", S2 = 0; S2 < r3.length; S2++)
      b3 && S2 > 0 && (k3 += "\n"), k3 += y(r3[S2], a3, c3, u3, d3, m3);
    return k3;
  }
  var w3, C3 = r3.type, O3 = r3.props, j3 = false;
  if ("function" == typeof C3) {
    if (j3 = true, !c3.shallow || !u3 && false !== c3.renderRootComponent) {
      if (C3 === p) {
        var A2 = [];
        return _2(A2, r3.props.children), y(A2, a3, c3, false !== c3.shallowHighOrder, d3, m3);
      }
      var F, H2 = r3.__c = v2(r3, a3);
      l.__b && l.__b(r3);
      var M2 = l.__r;
      if (C3.prototype && "function" == typeof C3.prototype.render) {
        var L2 = h(C3, a3);
        (H2 = r3.__c = new C3(O3, L2)).__v = r3, H2._dirty = H2.__d = true, H2.props = O3, null == H2.state && (H2.state = {}), null == H2._nextState && null == H2.__s && (H2._nextState = H2.__s = H2.state), H2.context = L2, C3.getDerivedStateFromProps ? H2.state = Object.assign({}, H2.state, C3.getDerivedStateFromProps(H2.props, H2.state)) : H2.componentWillMount && (H2.componentWillMount(), H2.state = H2._nextState !== H2.state ? H2._nextState : H2.__s !== H2.state ? H2.__s : H2.state), M2 && M2(r3), F = H2.render(H2.props, H2.state, H2.context);
      } else
        for (var T2 = h(C3, a3), E = 0; H2.__d && E++ < 25; )
          H2.__d = false, M2 && M2(r3), F = C3.call(r3.__c, O3, T2);
      return H2.getChildContext && (a3 = Object.assign({}, a3, H2.getChildContext())), l.diffed && l.diffed(r3), y(F, a3, c3, false !== c3.shallowHighOrder, d3, m3);
    }
    C3 = (w3 = C3).displayName || w3 !== Function && w3.name || function(e2) {
      var t2 = (Function.prototype.toString.call(e2).match(/^\s*function\s+([^( ]+)/) || "")[1];
      if (!t2) {
        for (var r4 = -1, n3 = g2.length; n3--; )
          if (g2[n3] === e2) {
            r4 = n3;
            break;
          }
        r4 < 0 && (r4 = g2.push(e2) - 1), t2 = "UnnamedComponent" + r4;
      }
      return t2;
    }(w3);
  }
  var $2, D, N2 = "<" + C3;
  if (O3) {
    var P = Object.keys(O3);
    c3 && true === c3.sortAttributes && P.sort();
    for (var W = 0; W < P.length; W++) {
      var I2 = P[W], R = O3[I2];
      if ("children" !== I2) {
        if (!o2.test(I2) && (c3 && c3.allAttributes || "key" !== I2 && "ref" !== I2 && "__self" !== I2 && "__source" !== I2)) {
          if ("defaultValue" === I2)
            I2 = "value";
          else if ("defaultChecked" === I2)
            I2 = "checked";
          else if ("defaultSelected" === I2)
            I2 = "selected";
          else if ("className" === I2) {
            if (void 0 !== O3.class)
              continue;
            I2 = "class";
          } else
            d3 && i2.test(I2) && (I2 = I2.toLowerCase().replace(/^xlink:?/, "xlink:"));
          if ("htmlFor" === I2) {
            if (O3.for)
              continue;
            I2 = "for";
          }
          "style" === I2 && R && "object" == typeof R && (R = p2(R)), "a" === I2[0] && "r" === I2[1] && "boolean" == typeof R && (R = String(R));
          var U = c3.attributeHook && c3.attributeHook(I2, R, a3, c3, j3);
          if (U || "" === U)
            N2 += U;
          else if ("dangerouslySetInnerHTML" === I2)
            D = R && R.__html;
          else if ("textarea" === C3 && "value" === I2)
            $2 = R;
          else if ((R || 0 === R || "" === R) && "function" != typeof R) {
            if (!(true !== R && "" !== R || (R = I2, c3 && c3.xml))) {
              N2 = N2 + " " + I2;
              continue;
            }
            if ("value" === I2) {
              if ("select" === C3) {
                m3 = R;
                continue;
              }
              "option" === C3 && m3 == R && void 0 === O3.selected && (N2 += " selected");
            }
            N2 = N2 + " " + I2 + '="' + l2(R) + '"';
          }
        }
      } else
        $2 = R;
    }
  }
  if (b3) {
    var V = N2.replace(/\n\s*/, " ");
    V === N2 || ~V.indexOf("\n") ? b3 && ~N2.indexOf("\n") && (N2 += "\n") : N2 = V;
  }
  if (N2 += ">", o2.test(C3))
    throw new Error(C3 + " is not a valid HTML tag name in " + N2);
  var q, z2 = n2.test(C3) || c3.voidElements && c3.voidElements.test(C3), Z = [];
  if (D)
    b3 && f2(D) && (D = "\n" + x2 + s2(D, x2)), N2 += D;
  else if (null != $2 && _2(q = [], $2).length) {
    for (var B = b3 && ~N2.indexOf("\n"), G = false, J = 0; J < q.length; J++) {
      var K = q[J];
      if (null != K && false !== K) {
        var Q = y(K, a3, c3, true, "svg" === C3 || "foreignObject" !== C3 && d3, m3);
        if (b3 && !B && f2(Q) && (B = true), Q)
          if (b3) {
            var X = Q.length > 0 && "<" != Q[0];
            G && X ? Z[Z.length - 1] += Q : Z.push(Q), G = X;
          } else
            Z.push(Q);
      }
    }
    if (b3 && B)
      for (var Y = Z.length; Y--; )
        Z[Y] = "\n" + x2 + s2(Z[Y], x2);
  }
  if (Z.length || D)
    N2 += Z.join("");
  else if (c3 && c3.xml)
    return N2.substring(0, N2.length - 1) + " />";
  return !z2 || q || D ? (b3 && ~N2.indexOf("\n") && (N2 += "\n"), N2 = N2 + "</" + C3 + ">") : N2 = N2.replace(/>$/, " />"), N2;
}
function k2(e2, r3, n3) {
  r3 = r3 || {};
  var o4, i3 = l.__s;
  return l.__s = true, o4 = n3 && (n3.pretty || n3.voidElements || n3.sortAttributes || n3.shallow || n3.allAttributes || n3.xml || n3.attributeHook) ? y(e2, r3, n3) : j2(e2, r3, false, void 0), l.__c && l.__c(e2, x), l.__s = i3, x.length = 0, o4;
}
function S(e2, t2) {
  return "className" === e2 ? "class" : "htmlFor" === e2 ? "for" : "defaultValue" === e2 ? "value" : "defaultChecked" === e2 ? "checked" : "defaultSelected" === e2 ? "selected" : t2 && i2.test(e2) ? e2.toLowerCase().replace(/^xlink:?/, "xlink:") : e2;
}
function w2(e2, t2) {
  return "style" === e2 && null != t2 && "object" == typeof t2 ? p2(t2) : "a" === e2[0] && "r" === e2[1] && "boolean" == typeof t2 ? String(t2) : t2;
}
function j2(r3, i3, a3, s4) {
  if (null == r3 || true === r3 || false === r3 || "" === r3)
    return "";
  if ("object" != typeof r3)
    return l2(r3);
  if (C2(r3)) {
    for (var f3 = "", c3 = 0; c3 < r3.length; c3++)
      f3 += j2(r3[c3], i3, a3, s4);
    return f3;
  }
  l.__b && l.__b(r3);
  var u3 = r3.type, p3 = r3.props;
  if ("function" == typeof u3) {
    if (u3 === p)
      return j2(r3.props.children, i3, a3, s4);
    var _4;
    _4 = u3.prototype && "function" == typeof u3.prototype.render ? function(e2, r4) {
      var n3 = e2.type, o4 = h(n3, r4), i4 = new n3(e2.props, o4);
      e2.__c = i4, i4.__v = e2, i4.__d = true, i4.props = e2.props, null == i4.state && (i4.state = {}), null == i4.__s && (i4.__s = i4.state), i4.context = o4, n3.getDerivedStateFromProps ? i4.state = O2({}, i4.state, n3.getDerivedStateFromProps(i4.props, i4.state)) : i4.componentWillMount && (i4.componentWillMount(), i4.state = i4.__s !== i4.state ? i4.__s : i4.state);
      var a4 = l.__r;
      return a4 && a4(e2), i4.render(i4.props, i4.state, i4.context);
    }(r3, i3) : function(e2, r4) {
      var n3, o4 = v2(e2, r4), i4 = h(e2.type, r4);
      e2.__c = o4;
      for (var a4 = l.__r, l3 = 0; o4.__d && l3++ < 25; )
        o4.__d = false, a4 && a4(e2), n3 = e2.type.call(o4, e2.props, i4);
      return n3;
    }(r3, i3);
    var d3 = r3.__c;
    d3.getChildContext && (i3 = O2({}, i3, d3.getChildContext()));
    var g3 = j2(_4, i3, a3, s4);
    return l.diffed && l.diffed(r3), g3;
  }
  var y2, m3, b3 = "<";
  if (b3 += u3, p3)
    for (var x2 in y2 = p3.children, p3) {
      var k3 = p3[x2];
      if (!("key" === x2 || "ref" === x2 || "__self" === x2 || "__source" === x2 || "children" === x2 || "className" === x2 && "class" in p3 || "htmlFor" === x2 && "for" in p3 || o2.test(x2))) {
        if (k3 = w2(x2 = S(x2, a3), k3), "dangerouslySetInnerHTML" === x2)
          m3 = k3 && k3.__html;
        else if ("textarea" === u3 && "value" === x2)
          y2 = k3;
        else if ((k3 || 0 === k3 || "" === k3) && "function" != typeof k3) {
          if (true === k3 || "" === k3) {
            k3 = x2, b3 = b3 + " " + x2;
            continue;
          }
          if ("value" === x2) {
            if ("select" === u3) {
              s4 = k3;
              continue;
            }
            "option" !== u3 || s4 != k3 || "selected" in p3 || (b3 += " selected");
          }
          b3 = b3 + " " + x2 + '="' + l2(k3) + '"';
        }
      }
    }
  var A2 = b3;
  if (b3 += ">", o2.test(u3))
    throw new Error(u3 + " is not a valid HTML tag name in " + b3);
  var F = "", H2 = false;
  if (m3)
    F += m3, H2 = true;
  else if ("string" == typeof y2)
    F += l2(y2), H2 = true;
  else if (C2(y2))
    for (var M2 = 0; M2 < y2.length; M2++) {
      var L2 = y2[M2];
      if (null != L2 && false !== L2) {
        var T2 = j2(L2, i3, "svg" === u3 || "foreignObject" !== u3 && a3, s4);
        T2 && (F += T2, H2 = true);
      }
    }
  else if (null != y2 && false !== y2 && true !== y2) {
    var E = j2(y2, i3, "svg" === u3 || "foreignObject" !== u3 && a3, s4);
    E && (F += E, H2 = true);
  }
  if (l.diffed && l.diffed(r3), H2)
    b3 += F;
  else if (n2.test(u3))
    return A2 + " />";
  return b3 + "</" + u3 + ">";
}
var r2, n2, o2, i2, a2, s2, f2, c2, u2, g2, m2, b2, x, C2, O2;
var init_dist = __esm({
  "node_modules/preact-render-to-string/dist/index.mjs"() {
    init_preact_module();
    r2 = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|^--/i;
    n2 = /^(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)$/;
    o2 = /[\s\n\\/='"\0<>]/;
    i2 = /^xlink:?./;
    a2 = /["&<]/;
    s2 = function(e2, t2) {
      return String(e2).replace(/(\n+)/g, "$1" + (t2 || "	"));
    };
    f2 = function(e2, t2, r3) {
      return String(e2).length > (t2 || 40) || !r3 && -1 !== String(e2).indexOf("\n") || -1 !== String(e2).indexOf("<");
    };
    c2 = {};
    u2 = /([A-Z])/g;
    g2 = [];
    m2 = { shallow: true };
    k2.render = k2;
    b2 = function(e2, t2) {
      return k2(e2, t2, m2);
    };
    x = [];
    C2 = Array.isArray;
    O2 = Object.assign;
    k2.shallowRender = b2;
  }
});

// node_modules/preact/jsx-runtime/dist/jsxRuntime.module.js
function o3(o4, e2, n3, t2, f3) {
  var l3, s4, u3 = {};
  for (s4 in e2)
    "ref" == s4 ? l3 = e2[s4] : u3[s4] = e2[s4];
  var a3 = { type: o4, props: u3, key: n3, ref: l3, __k: null, __: null, __b: 0, __e: null, __d: void 0, __c: null, __h: null, constructor: void 0, __v: --_3, __source: f3, __self: t2 };
  if ("function" == typeof o4 && (l3 = o4.defaultProps))
    for (s4 in l3)
      void 0 === u3[s4] && (u3[s4] = l3[s4]);
  return l.vnode && l.vnode(a3), a3;
}
var _3;
var init_jsxRuntime_module = __esm({
  "node_modules/preact/jsx-runtime/dist/jsxRuntime.module.js"() {
    init_preact_module();
    init_preact_module();
    _3 = 0;
  }
});

// node_modules/@auth/core/lib/pages/error.js
function ErrorPage(props) {
  const { url, error = "default", theme } = props;
  const signinPageUrl = `${url}/signin`;
  const errors = {
    default: {
      status: 200,
      heading: "Error",
      message: o3("p", { children: o3("a", { className: "site", href: url?.origin, children: url?.host }) })
    },
    Configuration: {
      status: 500,
      heading: "Server error",
      message: o3("div", { children: [o3("p", { children: "There is a problem with the server configuration." }), o3("p", { children: "Check the server logs for more information." })] })
    },
    AccessDenied: {
      status: 403,
      heading: "Access Denied",
      message: o3("div", { children: [o3("p", { children: "You do not have permission to sign in." }), o3("p", { children: o3("a", { className: "button", href: signinPageUrl, children: "Sign in" }) })] })
    },
    Verification: {
      status: 403,
      heading: "Unable to sign in",
      message: o3("div", { children: [o3("p", { children: "The sign in link is no longer valid." }), o3("p", { children: "It may have been used already or it may have expired." })] }),
      signin: o3("a", { className: "button", href: signinPageUrl, children: "Sign in" })
    }
  };
  const { status, heading, message: message2, signin } = errors[error] ?? errors.default;
  return {
    status,
    html: o3("div", { className: "error", children: [theme?.brandColor && o3("style", { dangerouslySetInnerHTML: {
      __html: `
        :root {
          --brand-color: ${theme?.brandColor}
        }
      `
    } }), o3("div", { className: "card", children: [theme?.logo && o3("img", { src: theme?.logo, alt: "Logo", className: "logo" }), o3("h1", { children: heading }), o3("div", { className: "message", children: message2 }), signin] })] })
  };
}
var init_error = __esm({
  "node_modules/@auth/core/lib/pages/error.js"() {
    init_jsxRuntime_module();
  }
});

// node_modules/@auth/core/lib/utils/webauthn-client.js
async function webauthnScript(authURL, providerID) {
  const WebAuthnBrowser = window.SimpleWebAuthnBrowser;
  async function fetchOptions(action) {
    const url = new URL(`${authURL}/webauthn-options/${providerID}`);
    if (action)
      url.searchParams.append("action", action);
    const formFields = getFormFields();
    formFields.forEach((field) => {
      url.searchParams.append(field.name, field.value);
    });
    const res = await fetch(url);
    if (!res.ok) {
      console.error("Failed to fetch options", res);
      return;
    }
    return res.json();
  }
  function getForm() {
    const formID = `#${providerID}-form`;
    const form = document.querySelector(formID);
    if (!form)
      throw new Error(`Form '${formID}' not found`);
    return form;
  }
  function getFormFields() {
    const form = getForm();
    const formFields = Array.from(form.querySelectorAll("input[data-form-field]"));
    return formFields;
  }
  async function submitForm(action, data) {
    const form = getForm();
    if (action) {
      const actionInput = document.createElement("input");
      actionInput.type = "hidden";
      actionInput.name = "action";
      actionInput.value = action;
      form.appendChild(actionInput);
    }
    if (data) {
      const dataInput = document.createElement("input");
      dataInput.type = "hidden";
      dataInput.name = "data";
      dataInput.value = JSON.stringify(data);
      form.appendChild(dataInput);
    }
    return form.submit();
  }
  async function authenticationFlow(options2, autofill) {
    const authResp = await WebAuthnBrowser.startAuthentication(options2, autofill);
    return await submitForm("authenticate", authResp);
  }
  async function registrationFlow(options2) {
    const formFields = getFormFields();
    formFields.forEach((field) => {
      if (field.required && !field.value) {
        throw new Error(`Missing required field: ${field.name}`);
      }
    });
    const regResp = await WebAuthnBrowser.startRegistration(options2);
    return await submitForm("register", regResp);
  }
  async function autofillAuthentication() {
    if (!WebAuthnBrowser.browserSupportsWebAuthnAutofill())
      return;
    const res = await fetchOptions("authenticate");
    if (!res) {
      console.error("Failed to fetch option for autofill authentication");
      return;
    }
    try {
      await authenticationFlow(res.options, true);
    } catch (e2) {
      console.error(e2);
    }
  }
  async function setupForm() {
    const form = getForm();
    if (!WebAuthnBrowser.browserSupportsWebAuthn()) {
      form.style.display = "none";
      return;
    }
    if (form) {
      form.addEventListener("submit", async (e2) => {
        e2.preventDefault();
        const res = await fetchOptions(void 0);
        if (!res) {
          console.error("Failed to fetch options for form submission");
          return;
        }
        if (res.action === "authenticate") {
          try {
            await authenticationFlow(res.options, false);
          } catch (e3) {
            console.error(e3);
          }
        } else if (res.action === "register") {
          try {
            await registrationFlow(res.options);
          } catch (e3) {
            console.error(e3);
          }
        }
      });
    }
  }
  setupForm();
  autofillAuthentication();
}
var init_webauthn_client = __esm({
  "node_modules/@auth/core/lib/utils/webauthn-client.js"() {
  }
});

// node_modules/@auth/core/lib/pages/signin.js
function hexToRgba(hex, alpha = 1) {
  if (!hex) {
    return;
  }
  hex = hex.replace(/^#/, "");
  if (hex.length === 3) {
    hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2];
  }
  const bigint = parseInt(hex, 16);
  const r3 = bigint >> 16 & 255;
  const g3 = bigint >> 8 & 255;
  const b3 = bigint & 255;
  alpha = Math.min(Math.max(alpha, 0), 1);
  const rgba = `rgba(${r3}, ${g3}, ${b3}, ${alpha})`;
  return rgba;
}
function ConditionalUIScript(providerID) {
  const startConditionalUIScript = `
const currentURL = window.location.href;
const authURL = currentURL.substring(0, currentURL.lastIndexOf('/'));
(${webauthnScript})(authURL, "${providerID}");
`;
  return o3(p, { children: o3("script", { dangerouslySetInnerHTML: { __html: startConditionalUIScript } }) });
}
function SigninPage(props) {
  const { csrfToken, providers = [], callbackUrl, theme, email, error: errorType } = props;
  if (typeof document !== "undefined" && theme?.brandColor) {
    document.documentElement.style.setProperty("--brand-color", theme.brandColor);
  }
  if (typeof document !== "undefined" && theme?.buttonText) {
    document.documentElement.style.setProperty("--button-text-color", theme.buttonText);
  }
  const error = errorType && (signinErrors[errorType] ?? signinErrors.default);
  const providerLogoPath = "https://authjs.dev/img/providers";
  const conditionalUIProviderID = providers.find((provider) => provider.type === "webauthn" && provider.enableConditionalUI)?.id;
  return o3("div", { className: "signin", children: [theme?.brandColor && o3("style", { dangerouslySetInnerHTML: {
    __html: `:root {--brand-color: ${theme.brandColor}}`
  } }), theme?.buttonText && o3("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --button-text-color: ${theme.buttonText}
        }
      `
  } }), o3("div", { className: "card", children: [error && o3("div", { className: "error", children: o3("p", { children: error }) }), theme?.logo && o3("img", { src: theme.logo, alt: "Logo", className: "logo" }), providers.map((provider, i3) => {
    let bg, text2, logo, logoDark, bgDark, textDark;
    if (provider.type === "oauth" || provider.type === "oidc") {
      ;
      ({
        bg = "",
        text: text2 = "",
        logo = "",
        bgDark = bg,
        textDark = text2,
        logoDark = ""
      } = provider.style ?? {});
      logo = logo.startsWith("/") ? providerLogoPath + logo : logo;
      logoDark = logoDark.startsWith("/") ? providerLogoPath + logoDark : logoDark || logo;
      logoDark || (logoDark = logo);
    }
    return o3("div", { className: "provider", children: [provider.type === "oauth" || provider.type === "oidc" ? o3("form", { action: provider.signinUrl, method: "POST", children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), callbackUrl && o3("input", { type: "hidden", name: "callbackUrl", value: callbackUrl }), o3("button", { type: "submit", className: "button", style: {
      "--provider-bg": bg,
      "--provider-dark-bg": bgDark,
      "--provider-color": text2,
      "--provider-dark-color": textDark,
      "--provider-bg-hover": hexToRgba(bg, 0.8),
      "--provider-dark-bg-hover": hexToRgba(bgDark, 0.8)
    }, tabIndex: 0, children: [logo && o3("img", { loading: "lazy", height: 24, width: 24, id: "provider-logo", src: logo }), logoDark && o3("img", { loading: "lazy", height: 24, width: 24, id: "provider-logo-dark", src: logoDark }), o3("span", { children: ["Sign in with ", provider.name] })] })] }) : null, (provider.type === "email" || provider.type === "credentials" || provider.type === "webauthn") && i3 > 0 && providers[i3 - 1].type !== "email" && providers[i3 - 1].type !== "credentials" && providers[i3 - 1].type !== "webauthn" && o3("hr", {}), provider.type === "email" && o3("form", { action: provider.signinUrl, method: "POST", children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), o3("label", { className: "section-header", htmlFor: `input-email-for-${provider.id}-provider`, children: "Email" }), o3("input", { id: `input-email-for-${provider.id}-provider`, autoFocus: true, type: "email", name: "email", value: email, placeholder: "email@example.com", required: true }), o3("button", { id: "submitButton", type: "submit", tabIndex: 0, children: ["Sign in with ", provider.name] })] }), provider.type === "credentials" && o3("form", { action: provider.callbackUrl, method: "POST", children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), Object.keys(provider.credentials).map((credential) => {
      return o3("div", { children: [o3("label", { className: "section-header", htmlFor: `input-${credential}-for-${provider.id}-provider`, children: provider.credentials[credential].label ?? credential }), o3("input", { name: credential, id: `input-${credential}-for-${provider.id}-provider`, type: provider.credentials[credential].type ?? "text", placeholder: provider.credentials[credential].placeholder ?? "", ...provider.credentials[credential] })] }, `input-group-${provider.id}`);
    }), o3("button", { id: "submitButton", type: "submit", tabIndex: 0, children: ["Sign in with ", provider.name] })] }), provider.type === "webauthn" && o3("form", { action: provider.callbackUrl, method: "POST", id: `${provider.id}-form`, children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), Object.keys(provider.formFields).map((field) => {
      return o3("div", { children: [o3("label", { className: "section-header", htmlFor: `input-${field}-for-${provider.id}-provider`, children: provider.formFields[field].label ?? field }), o3("input", { name: field, "data-form-field": true, id: `input-${field}-for-${provider.id}-provider`, type: provider.formFields[field].type ?? "text", placeholder: provider.formFields[field].placeholder ?? "", ...provider.formFields[field] })] }, `input-group-${provider.id}`);
    }), o3("button", { id: `submitButton-${provider.id}`, type: "submit", tabIndex: 0, children: ["Sign in with ", provider.name] })] }), (provider.type === "email" || provider.type === "credentials" || provider.type === "webauthn") && i3 + 1 < providers.length && o3("hr", {})] }, provider.id);
  })] }), conditionalUIProviderID && ConditionalUIScript(conditionalUIProviderID)] });
}
var signinErrors;
var init_signin = __esm({
  "node_modules/@auth/core/lib/pages/signin.js"() {
    init_jsxRuntime_module();
    init_webauthn_client();
    signinErrors = {
      default: "Unable to sign in.",
      Signin: "Try signing in with a different account.",
      OAuthSignin: "Try signing in with a different account.",
      OAuthCallbackError: "Try signing in with a different account.",
      OAuthCreateAccount: "Try signing in with a different account.",
      EmailCreateAccount: "Try signing in with a different account.",
      Callback: "Try signing in with a different account.",
      OAuthAccountNotLinked: "To confirm your identity, sign in with the same account you used originally.",
      EmailSignin: "The e-mail could not be sent.",
      CredentialsSignin: "Sign in failed. Check the details you provided are correct.",
      SessionRequired: "Please sign in to access this page."
    };
  }
});

// node_modules/@auth/core/lib/pages/signout.js
function SignoutPage(props) {
  const { url, csrfToken, theme } = props;
  return o3("div", { className: "signout", children: [theme?.brandColor && o3("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `
  } }), theme?.buttonText && o3("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --button-text-color: ${theme.buttonText}
        }
      `
  } }), o3("div", { className: "card", children: [theme?.logo && o3("img", { src: theme.logo, alt: "Logo", className: "logo" }), o3("h1", { children: "Signout" }), o3("p", { children: "Are you sure you want to sign out?" }), o3("form", { action: url?.toString(), method: "POST", children: [o3("input", { type: "hidden", name: "csrfToken", value: csrfToken }), o3("button", { id: "submitButton", type: "submit", children: "Sign out" })] })] })] });
}
var init_signout = __esm({
  "node_modules/@auth/core/lib/pages/signout.js"() {
    init_jsxRuntime_module();
  }
});

// node_modules/@auth/core/lib/pages/styles.js
var styles_default;
var init_styles = __esm({
  "node_modules/@auth/core/lib/pages/styles.js"() {
    styles_default = `:root {
  --border-width: 1px;
  --border-radius: 0.5rem;
  --color-error: #c94b4b;
  --color-info: #157efb;
  --color-info-hover: #0f6ddb;
  --color-info-text: #fff;
}

.__next-auth-theme-auto,
.__next-auth-theme-light {
  --color-background: #ececec;
  --color-background-hover: rgba(236, 236, 236, 0.8);
  --color-background-card: #fff;
  --color-text: #000;
  --color-primary: #444;
  --color-control-border: #bbb;
  --color-button-active-background: #f9f9f9;
  --color-button-active-border: #aaa;
  --color-separator: #ccc;
}

.__next-auth-theme-dark {
  --color-background: #161b22;
  --color-background-hover: rgba(22, 27, 34, 0.8);
  --color-background-card: #0d1117;
  --color-text: #fff;
  --color-primary: #ccc;
  --color-control-border: #555;
  --color-button-active-background: #060606;
  --color-button-active-border: #666;
  --color-separator: #444;
}

@media (prefers-color-scheme: dark) {
  .__next-auth-theme-auto {
    --color-background: #161b22;
    --color-background-hover: rgba(22, 27, 34, 0.8);
    --color-background-card: #0d1117;
    --color-text: #fff;
    --color-primary: #ccc;
    --color-control-border: #555;
    --color-button-active-background: #060606;
    --color-button-active-border: #666;
    --color-separator: #444;
  }

  button,
  a.button {
    color: var(--provider-dark-color, var(--color-primary));
    background-color: var(--provider-dark-bg, var(--color-background));
  }
    :is(button,a.button):hover {
      background-color: var(
        --provider-dark-bg-hover,
        var(--color-background-hover)
      ) !important;
    }
  #provider-logo {
    display: none !important;
  }
  #provider-logo-dark {
    width: 25px;
    display: block !important;
  }
}
html {
  box-sizing: border-box;
}
*,
*:before,
*:after {
  box-sizing: inherit;
  margin: 0;
  padding: 0;
}

body {
  background-color: var(--color-background);
  margin: 0;
  padding: 0;
  font-family:
    ui-sans-serif,
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    Roboto,
    "Helvetica Neue",
    Arial,
    "Noto Sans",
    sans-serif,
    "Apple Color Emoji",
    "Segoe UI Emoji",
    "Segoe UI Symbol",
    "Noto Color Emoji";
}

h1 {
  margin-bottom: 1.5rem;
  padding: 0 1rem;
  font-weight: 400;
  color: var(--color-text);
}

p {
  margin-bottom: 1.5rem;
  padding: 0 1rem;
  color: var(--color-text);
}

form {
  margin: 0;
  padding: 0;
}

label {
  font-weight: 500;
  text-align: left;
  margin-bottom: 0.25rem;
  display: block;
  color: var(--color-text);
}

input[type] {
  box-sizing: border-box;
  display: block;
  width: 100%;
  padding: 0.5rem 1rem;
  border: var(--border-width) solid var(--color-control-border);
  background: var(--color-background-card);
  font-size: 1rem;
  border-radius: var(--border-radius);
  color: var(--color-text);
}

input[type]:focus {
    box-shadow: none;
  }

p {
  font-size: 1.1rem;
  line-height: 2rem;
}

a.button {
  text-decoration: none;
  line-height: 1rem;
}

a.button:link,
  a.button:visited {
    background-color: var(--color-background);
    color: var(--color-primary);
  }

button span {
  flex-grow: 1;
}

button,
a.button {
  padding: 0.75rem 1rem;
  color: var(--provider-color, var(--color-primary));
  background-color: var(--provider-bg);
  font-size: 1.1rem;
  min-height: 62px;
  border-color: rgba(0, 0, 0, 0.1);
  border-radius: var(--border-radius);
  transition: all 0.1s ease-in-out;
  font-weight: 500;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

:is(button,a.button):hover {
    background-color: var(--provider-bg-hover, var(--color-background-hover));
    cursor: pointer;
  }

:is(button,a.button):active {
    cursor: pointer;
  }

:is(button,a.button) #provider-logo {
    width: 25px;
    display: block;
  }

:is(button,a.button) #provider-logo-dark {
    display: none;
  }

#submitButton {
  color: var(--button-text-color, var(--color-info-text));
  background-color: var(--brand-color, var(--color-info));
  width: 100%;
}

#submitButton:hover {
    background-color: var(
      --button-hover-bg,
      var(--color-info-hover)
    ) !important;
  }

a.site {
  color: var(--color-primary);
  text-decoration: none;
  font-size: 1rem;
  line-height: 2rem;
}

a.site:hover {
    text-decoration: underline;
  }

.page {
  position: absolute;
  width: 100%;
  height: 100%;
  display: grid;
  place-items: center;
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

.page > div {
    text-align: center;
  }

.error a.button {
    padding-left: 2rem;
    padding-right: 2rem;
    margin-top: 0.5rem;
  }

.error .message {
    margin-bottom: 1.5rem;
  }

.signin input[type="text"] {
    margin-left: auto;
    margin-right: auto;
    display: block;
  }

.signin hr {
    display: block;
    border: 0;
    border-top: 1px solid var(--color-separator);
    margin: 2rem auto 1rem auto;
    overflow: visible;
  }

.signin hr::before {
      content: "or";
      background: var(--color-background-card);
      color: #888;
      padding: 0 0.4rem;
      position: relative;
      top: -0.7rem;
    }

.signin .error {
    background: #f5f5f5;
    font-weight: 500;
    border-radius: 0.3rem;
    background: var(--color-error);
  }

.signin .error p {
      text-align: left;
      padding: 0.5rem 1rem;
      font-size: 0.9rem;
      line-height: 1.2rem;
      color: var(--color-info-text);
    }

.signin > div,
  .signin form {
    display: block;
  }

.signin > div input[type], .signin form input[type] {
      margin-bottom: 0.5rem;
    }

.signin > div button, .signin form button {
      width: 100%;
    }

.signin .provider + .provider {
    margin-top: 1rem;
  }

.logo {
  display: inline-block;
  max-width: 150px;
  margin: 1.25rem 0;
  max-height: 70px;
}

.card {
  background-color: var(--color-background-card);
  border-radius: 2rem;
  padding: 1.25rem 2rem;
}

.card .header {
    color: var(--color-primary);
  }

.section-header {
  color: var(--color-text);
}

@media screen and (min-width: 450px) {
  .card {
    margin: 2rem 0;
    width: 368px;
  }
}
@media screen and (max-width: 450px) {
  .card {
    margin: 1rem 0;
    width: 343px;
  }
}
`;
  }
});

// node_modules/@auth/core/lib/pages/verify-request.js
function VerifyRequestPage(props) {
  const { url, theme } = props;
  return o3("div", { className: "verify-request", children: [theme.brandColor && o3("style", { dangerouslySetInnerHTML: {
    __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `
  } }), o3("div", { className: "card", children: [theme.logo && o3("img", { src: theme.logo, alt: "Logo", className: "logo" }), o3("h1", { children: "Check your email" }), o3("p", { children: "A sign in link has been sent to your email address." }), o3("p", { children: o3("a", { className: "site", href: url.origin, children: url.host }) })] })] });
}
var init_verify_request = __esm({
  "node_modules/@auth/core/lib/pages/verify-request.js"() {
    init_jsxRuntime_module();
  }
});

// node_modules/@auth/core/lib/pages/index.js
function send({ html, title, status, cookies, theme, headTags }) {
  return {
    cookies,
    status,
    headers: { "Content-Type": "text/html" },
    body: `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>${styles_default}</style><title>${title}</title>${headTags ?? ""}</head><body class="__next-auth-theme-${theme?.colorScheme ?? "auto"}"><div class="page">${k2(html)}</div></body></html>`
  };
}
function renderPage(params) {
  const { url, theme, query, cookies, pages, providers } = params;
  return {
    csrf(skip, options2, cookies2) {
      if (!skip) {
        return {
          headers: { "Content-Type": "application/json" },
          body: { csrfToken: options2.csrfToken },
          cookies: cookies2
        };
      }
      options2.logger.warn("csrf-disabled");
      cookies2.push({
        name: options2.cookies.csrfToken.name,
        value: "",
        options: { ...options2.cookies.csrfToken.options, maxAge: 0 }
      });
      return { status: 404, cookies: cookies2 };
    },
    providers(providers2) {
      return {
        headers: { "Content-Type": "application/json" },
        body: providers2.reduce((acc, { id, name, type, signinUrl, callbackUrl }) => {
          acc[id] = { id, name, type, signinUrl, callbackUrl };
          return acc;
        }, {})
      };
    },
    signin(providerId, error) {
      if (providerId)
        throw new UnknownAction("Unsupported action");
      if (pages?.signIn) {
        let signinUrl = `${pages.signIn}${pages.signIn.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl: params.callbackUrl ?? "/" })}`;
        if (error)
          signinUrl = `${signinUrl}&${new URLSearchParams({ error })}`;
        return { redirect: signinUrl, cookies };
      }
      const webauthnProvider = providers?.find((p3) => p3.type === "webauthn" && p3.enableConditionalUI && !!p3.simpleWebAuthnBrowserVersion);
      let simpleWebAuthnBrowserScript = "";
      if (webauthnProvider) {
        const { simpleWebAuthnBrowserVersion } = webauthnProvider;
        simpleWebAuthnBrowserScript = `<script src="https://unpkg.com/@simplewebauthn/browser@${simpleWebAuthnBrowserVersion}/dist/bundle/index.umd.min.js" crossorigin="anonymous"><\/script>`;
      }
      return send({
        cookies,
        theme,
        html: SigninPage({
          csrfToken: params.csrfToken,
          // We only want to render providers
          providers: params.providers?.filter((provider) => (
            // Always render oauth and email type providers
            ["email", "oauth", "oidc"].includes(provider.type) || // Only render credentials type provider if credentials are defined
            provider.type === "credentials" && provider.credentials || // Only render webauthn type provider if formFields are defined
            provider.type === "webauthn" && provider.formFields || // Don't render other provider types
            false
          )),
          callbackUrl: params.callbackUrl,
          theme: params.theme,
          error,
          ...query
        }),
        title: "Sign In",
        headTags: simpleWebAuthnBrowserScript
      });
    },
    signout() {
      if (pages?.signOut)
        return { redirect: pages.signOut, cookies };
      return send({
        cookies,
        theme,
        html: SignoutPage({ csrfToken: params.csrfToken, url, theme }),
        title: "Sign Out"
      });
    },
    verifyRequest(props) {
      if (pages?.verifyRequest)
        return { redirect: pages.verifyRequest, cookies };
      return send({
        cookies,
        theme,
        html: VerifyRequestPage({ url, theme, ...props }),
        title: "Verify Request"
      });
    },
    error(error) {
      if (pages?.error) {
        return {
          redirect: `${pages.error}${pages.error.includes("?") ? "&" : "?"}error=${error}`,
          cookies
        };
      }
      return send({
        cookies,
        theme,
        // @ts-expect-error fix error type
        ...ErrorPage({ url, theme, error }),
        title: "Error"
      });
    }
  };
}
var init_pages = __esm({
  "node_modules/@auth/core/lib/pages/index.js"() {
    init_dist();
    init_error();
    init_signin();
    init_signout();
    init_styles();
    init_verify_request();
    init_errors();
  }
});

// node_modules/@auth/core/lib/utils/date.js
function fromDate(time, date = Date.now()) {
  return new Date(date + time * 1e3);
}
var init_date = __esm({
  "node_modules/@auth/core/lib/utils/date.js"() {
  }
});

// node_modules/@auth/core/lib/actions/callback/handle-login.js
async function handleLoginOrRegister(sessionToken, _profile, _account, options2) {
  if (!_account?.providerAccountId || !_account.type)
    throw new Error("Missing or invalid provider account");
  if (!["email", "oauth", "oidc", "webauthn"].includes(_account.type))
    throw new Error("Provider not supported");
  const { adapter, jwt: jwt2, events, session: { strategy: sessionStrategy, generateSessionToken } } = options2;
  if (!adapter) {
    return { user: _profile, account: _account };
  }
  const profile = _profile;
  let account = _account;
  const { createUser, updateUser, getUser, getUserByAccount, getUserByEmail, linkAccount, createSession, getSessionAndUser, deleteSession } = adapter;
  let session2 = null;
  let user = null;
  let isNewUser = false;
  const useJwtSession = sessionStrategy === "jwt";
  if (sessionToken) {
    if (useJwtSession) {
      try {
        const salt = options2.cookies.sessionToken.name;
        session2 = await jwt2.decode({ ...jwt2, token: sessionToken, salt });
        if (session2 && "sub" in session2 && session2.sub) {
          user = await getUser(session2.sub);
        }
      } catch {
      }
    } else {
      const userAndSession = await getSessionAndUser(sessionToken);
      if (userAndSession) {
        session2 = userAndSession.session;
        user = userAndSession.user;
      }
    }
  }
  if (account.type === "email") {
    const userByEmail = await getUserByEmail(profile.email);
    if (userByEmail) {
      if (user?.id !== userByEmail.id && !useJwtSession && sessionToken) {
        await deleteSession(sessionToken);
      }
      user = await updateUser({
        id: userByEmail.id,
        emailVerified: /* @__PURE__ */ new Date()
      });
      await events.updateUser?.({ user });
    } else {
      user = await createUser({ ...profile, emailVerified: /* @__PURE__ */ new Date() });
      await events.createUser?.({ user });
      isNewUser = true;
    }
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: user.id,
      expires: fromDate(options2.session.maxAge)
    });
    return { session: session2, user, isNewUser };
  } else if (account.type === "webauthn") {
    const userByAccount2 = await getUserByAccount({
      providerAccountId: account.providerAccountId,
      provider: account.provider
    });
    if (userByAccount2) {
      if (user) {
        if (userByAccount2.id === user.id) {
          const currentAccount2 = { ...account, userId: user.id };
          return { session: session2, user, isNewUser, account: currentAccount2 };
        }
        throw new AccountNotLinked("The account is already associated with another user", { provider: account.provider });
      }
      session2 = useJwtSession ? {} : await createSession({
        sessionToken: generateSessionToken(),
        userId: userByAccount2.id,
        expires: fromDate(options2.session.maxAge)
      });
      const currentAccount = { ...account, userId: userByAccount2.id };
      return { session: session2, user: userByAccount2, isNewUser, account: currentAccount };
    } else {
      if (user) {
        await linkAccount({ ...account, userId: user.id });
        await events.linkAccount?.({ user, account, profile });
        const currentAccount2 = { ...account, userId: user.id };
        return { session: session2, user, isNewUser, account: currentAccount2 };
      }
      const userByEmail = profile.email ? await getUserByEmail(profile.email) : null;
      if (userByEmail) {
        throw new AccountNotLinked("Another account already exists with the same e-mail address", { provider: account.provider });
      } else {
        user = await createUser({ ...profile });
      }
      await events.createUser?.({ user });
      await linkAccount({ ...account, userId: user.id });
      await events.linkAccount?.({ user, account, profile });
      session2 = useJwtSession ? {} : await createSession({
        sessionToken: generateSessionToken(),
        userId: user.id,
        expires: fromDate(options2.session.maxAge)
      });
      const currentAccount = { ...account, userId: user.id };
      return { session: session2, user, isNewUser: true, account: currentAccount };
    }
  }
  const userByAccount = await getUserByAccount({
    providerAccountId: account.providerAccountId,
    provider: account.provider
  });
  if (userByAccount) {
    if (user) {
      if (userByAccount.id === user.id) {
        return { session: session2, user, isNewUser };
      }
      throw new OAuthAccountNotLinked("The account is already associated with another user", { provider: account.provider });
    }
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: userByAccount.id,
      expires: fromDate(options2.session.maxAge)
    });
    return { session: session2, user: userByAccount, isNewUser };
  } else {
    const { provider: p3 } = options2;
    const { type, provider, providerAccountId, userId, ...tokenSet } = account;
    const defaults = { providerAccountId, provider, type, userId };
    account = Object.assign(p3.account(tokenSet) ?? {}, defaults);
    if (user) {
      await linkAccount({ ...account, userId: user.id });
      await events.linkAccount?.({ user, account, profile });
      return { session: session2, user, isNewUser };
    }
    const userByEmail = profile.email ? await getUserByEmail(profile.email) : null;
    if (userByEmail) {
      const provider2 = options2.provider;
      if (provider2?.allowDangerousEmailAccountLinking) {
        user = userByEmail;
      } else {
        throw new OAuthAccountNotLinked("Another account already exists with the same e-mail address", { provider: account.provider });
      }
    } else {
      user = await createUser({ ...profile, emailVerified: null });
    }
    await events.createUser?.({ user });
    await linkAccount({ ...account, userId: user.id });
    await events.linkAccount?.({ user, account, profile });
    session2 = useJwtSession ? {} : await createSession({
      sessionToken: generateSessionToken(),
      userId: user.id,
      expires: fromDate(options2.session.maxAge)
    });
    return { session: session2, user, isNewUser: true };
  }
}
var init_handle_login = __esm({
  "node_modules/@auth/core/lib/actions/callback/handle-login.js"() {
    init_errors();
    init_date();
  }
});

// node_modules/oauth4webapi/build/index.js
function looseInstanceOf(input, expected) {
  if (input == null) {
    return false;
  }
  try {
    return input instanceof expected || Object.getPrototypeOf(input)[Symbol.toStringTag] === expected.prototype[Symbol.toStringTag];
  } catch {
    return false;
  }
}
function buf(input) {
  if (typeof input === "string") {
    return encoder2.encode(input);
  }
  return decoder2.decode(input);
}
function encodeBase64Url(input) {
  if (input instanceof ArrayBuffer) {
    input = new Uint8Array(input);
  }
  const arr = [];
  for (let i3 = 0; i3 < input.byteLength; i3 += CHUNK_SIZE2) {
    arr.push(String.fromCharCode.apply(null, input.subarray(i3, i3 + CHUNK_SIZE2)));
  }
  return btoa(arr.join("")).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function decodeBase64Url(input) {
  try {
    const binary = atob(input.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""));
    const bytes = new Uint8Array(binary.length);
    for (let i3 = 0; i3 < binary.length; i3++) {
      bytes[i3] = binary.charCodeAt(i3);
    }
    return bytes;
  } catch (cause) {
    throw new OPE("The input to be decoded is not correctly encoded.", { cause });
  }
}
function b64u(input) {
  if (typeof input === "string") {
    return decodeBase64Url(input);
  }
  return encodeBase64Url(input);
}
function isCryptoKey2(key2) {
  return key2 instanceof CryptoKey;
}
function isPrivateKey(key2) {
  return isCryptoKey2(key2) && key2.type === "private";
}
function isPublicKey(key2) {
  return isCryptoKey2(key2) && key2.type === "public";
}
function processDpopNonce(response) {
  try {
    const nonce2 = response.headers.get("dpop-nonce");
    if (nonce2) {
      dpopNonces.set(new URL(response.url).origin, nonce2);
    }
  } catch {
  }
  return response;
}
function isJsonObject(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }
  return true;
}
function prepareHeaders(input) {
  if (looseInstanceOf(input, Headers)) {
    input = Object.fromEntries(input.entries());
  }
  const headers2 = new Headers(input);
  if (USER_AGENT2 && !headers2.has("user-agent")) {
    headers2.set("user-agent", USER_AGENT2);
  }
  if (headers2.has("authorization")) {
    throw new TypeError('"options.headers" must not include the "authorization" header name');
  }
  if (headers2.has("dpop")) {
    throw new TypeError('"options.headers" must not include the "dpop" header name');
  }
  return headers2;
}
function signal(value) {
  if (typeof value === "function") {
    value = value();
  }
  if (!(value instanceof AbortSignal)) {
    throw new TypeError('"options.signal" must return or be an instance of AbortSignal');
  }
  return value;
}
async function discoveryRequest(issuerIdentifier, options2) {
  if (!(issuerIdentifier instanceof URL)) {
    throw new TypeError('"issuerIdentifier" must be an instance of URL');
  }
  if (issuerIdentifier.protocol !== "https:" && issuerIdentifier.protocol !== "http:") {
    throw new TypeError('"issuer.protocol" must be "https:" or "http:"');
  }
  const url = new URL(issuerIdentifier.href);
  switch (options2?.algorithm) {
    case void 0:
    case "oidc":
      url.pathname = `${url.pathname}/.well-known/openid-configuration`.replace("//", "/");
      break;
    case "oauth2":
      if (url.pathname === "/") {
        url.pathname = ".well-known/oauth-authorization-server";
      } else {
        url.pathname = `.well-known/oauth-authorization-server/${url.pathname}`.replace("//", "/");
      }
      break;
    default:
      throw new TypeError('"options.algorithm" must be "oidc" (default), or "oauth2"');
  }
  const headers2 = prepareHeaders(options2?.headers);
  headers2.set("accept", "application/json");
  return (options2?.[customFetch] || fetch)(url.href, {
    headers: Object.fromEntries(headers2.entries()),
    method: "GET",
    redirect: "manual",
    signal: options2?.signal ? signal(options2.signal) : null
  }).then(processDpopNonce);
}
function validateString(input) {
  return typeof input === "string" && input.length !== 0;
}
async function processDiscoveryResponse(expectedIssuerIdentifier, response) {
  if (!(expectedIssuerIdentifier instanceof URL)) {
    throw new TypeError('"expectedIssuer" must be an instance of URL');
  }
  if (!looseInstanceOf(response, Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  if (response.status !== 200) {
    throw new OPE('"response" is not a conform Authorization Server Metadata response');
  }
  assertReadableResponse(response);
  let json2;
  try {
    json2 = await response.json();
  } catch (cause) {
    throw new OPE('failed to parse "response" body as JSON', { cause });
  }
  if (!isJsonObject(json2)) {
    throw new OPE('"response" body must be a top level object');
  }
  if (!validateString(json2.issuer)) {
    throw new OPE('"response" body "issuer" property must be a non-empty string');
  }
  if (new URL(json2.issuer).href !== expectedIssuerIdentifier.href) {
    throw new OPE('"response" body "issuer" does not match "expectedIssuer"');
  }
  return json2;
}
function randomBytes() {
  return b64u(crypto.getRandomValues(new Uint8Array(32)));
}
function generateRandomCodeVerifier() {
  return randomBytes();
}
function generateRandomState() {
  return randomBytes();
}
function generateRandomNonce() {
  return randomBytes();
}
async function calculatePKCECodeChallenge(codeVerifier) {
  if (!validateString(codeVerifier)) {
    throw new TypeError('"codeVerifier" must be a non-empty string');
  }
  return b64u(await crypto.subtle.digest("SHA-256", buf(codeVerifier)));
}
function getKeyAndKid(input) {
  if (input instanceof CryptoKey) {
    return { key: input };
  }
  if (!(input?.key instanceof CryptoKey)) {
    return {};
  }
  if (input.kid !== void 0 && !validateString(input.kid)) {
    throw new TypeError('"kid" must be a non-empty string');
  }
  return { key: input.key, kid: input.kid };
}
function formUrlEncode(token) {
  return encodeURIComponent(token).replace(/%20/g, "+");
}
function clientSecretBasic(clientId, clientSecret) {
  const username = formUrlEncode(clientId);
  const password = formUrlEncode(clientSecret);
  const credentials = btoa(`${username}:${password}`);
  return `Basic ${credentials}`;
}
function psAlg(key2) {
  switch (key2.algorithm.hash.name) {
    case "SHA-256":
      return "PS256";
    case "SHA-384":
      return "PS384";
    case "SHA-512":
      return "PS512";
    default:
      throw new UnsupportedOperationError("unsupported RsaHashedKeyAlgorithm hash name");
  }
}
function rsAlg(key2) {
  switch (key2.algorithm.hash.name) {
    case "SHA-256":
      return "RS256";
    case "SHA-384":
      return "RS384";
    case "SHA-512":
      return "RS512";
    default:
      throw new UnsupportedOperationError("unsupported RsaHashedKeyAlgorithm hash name");
  }
}
function esAlg(key2) {
  switch (key2.algorithm.namedCurve) {
    case "P-256":
      return "ES256";
    case "P-384":
      return "ES384";
    case "P-521":
      return "ES512";
    default:
      throw new UnsupportedOperationError("unsupported EcKeyAlgorithm namedCurve");
  }
}
function keyToJws(key2) {
  switch (key2.algorithm.name) {
    case "RSA-PSS":
      return psAlg(key2);
    case "RSASSA-PKCS1-v1_5":
      return rsAlg(key2);
    case "ECDSA":
      return esAlg(key2);
    case "Ed25519":
    case "Ed448":
      return "EdDSA";
    default:
      throw new UnsupportedOperationError("unsupported CryptoKey algorithm name");
  }
}
function getClockSkew(client) {
  const skew = client?.[clockSkew];
  return typeof skew === "number" && Number.isFinite(skew) ? skew : 0;
}
function getClockTolerance(client) {
  const tolerance = client?.[clockTolerance];
  return typeof tolerance === "number" && Number.isFinite(tolerance) && Math.sign(tolerance) !== -1 ? tolerance : 30;
}
function epochTime() {
  return Math.floor(Date.now() / 1e3);
}
function clientAssertion(as, client) {
  const now2 = epochTime() + getClockSkew(client);
  return {
    jti: randomBytes(),
    aud: [as.issuer, as.token_endpoint],
    exp: now2 + 60,
    iat: now2,
    nbf: now2,
    iss: client.client_id,
    sub: client.client_id
  };
}
async function privateKeyJwt(as, client, key2, kid) {
  return jwt({
    alg: keyToJws(key2),
    kid
  }, clientAssertion(as, client), key2);
}
function assertAs(as) {
  if (typeof as !== "object" || as === null) {
    throw new TypeError('"as" must be an object');
  }
  if (!validateString(as.issuer)) {
    throw new TypeError('"as.issuer" property must be a non-empty string');
  }
  return true;
}
function assertClient(client) {
  if (typeof client !== "object" || client === null) {
    throw new TypeError('"client" must be an object');
  }
  if (!validateString(client.client_id)) {
    throw new TypeError('"client.client_id" property must be a non-empty string');
  }
  return true;
}
function assertClientSecret(clientSecret) {
  if (!validateString(clientSecret)) {
    throw new TypeError('"client.client_secret" property must be a non-empty string');
  }
  return clientSecret;
}
function assertNoClientPrivateKey(clientAuthMethod, clientPrivateKey) {
  if (clientPrivateKey !== void 0) {
    throw new TypeError(`"options.clientPrivateKey" property must not be provided when ${clientAuthMethod} client authentication method is used.`);
  }
}
function assertNoClientSecret(clientAuthMethod, clientSecret) {
  if (clientSecret !== void 0) {
    throw new TypeError(`"client.client_secret" property must not be provided when ${clientAuthMethod} client authentication method is used.`);
  }
}
async function clientAuthentication(as, client, body2, headers2, clientPrivateKey) {
  body2.delete("client_secret");
  body2.delete("client_assertion_type");
  body2.delete("client_assertion");
  switch (client.token_endpoint_auth_method) {
    case void 0:
    case "client_secret_basic": {
      assertNoClientPrivateKey("client_secret_basic", clientPrivateKey);
      headers2.set("authorization", clientSecretBasic(client.client_id, assertClientSecret(client.client_secret)));
      break;
    }
    case "client_secret_post": {
      assertNoClientPrivateKey("client_secret_post", clientPrivateKey);
      body2.set("client_id", client.client_id);
      body2.set("client_secret", assertClientSecret(client.client_secret));
      break;
    }
    case "private_key_jwt": {
      assertNoClientSecret("private_key_jwt", client.client_secret);
      if (clientPrivateKey === void 0) {
        throw new TypeError('"options.clientPrivateKey" must be provided when "client.token_endpoint_auth_method" is "private_key_jwt"');
      }
      const { key: key2, kid } = getKeyAndKid(clientPrivateKey);
      if (!isPrivateKey(key2)) {
        throw new TypeError('"options.clientPrivateKey.key" must be a private CryptoKey');
      }
      body2.set("client_id", client.client_id);
      body2.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body2.set("client_assertion", await privateKeyJwt(as, client, key2, kid));
      break;
    }
    case "tls_client_auth":
    case "self_signed_tls_client_auth":
    case "none": {
      assertNoClientSecret(client.token_endpoint_auth_method, client.client_secret);
      assertNoClientPrivateKey(client.token_endpoint_auth_method, clientPrivateKey);
      body2.set("client_id", client.client_id);
      break;
    }
    default:
      throw new UnsupportedOperationError("unsupported client token_endpoint_auth_method");
  }
}
async function jwt(header, claimsSet, key2) {
  if (!key2.usages.includes("sign")) {
    throw new TypeError('CryptoKey instances used for signing assertions must include "sign" in their "usages"');
  }
  const input = `${b64u(buf(JSON.stringify(header)))}.${b64u(buf(JSON.stringify(claimsSet)))}`;
  const signature = b64u(await crypto.subtle.sign(keyToSubtle(key2), key2, buf(input)));
  return `${input}.${signature}`;
}
async function dpopProofJwt(headers2, options2, url, htm, clockSkew2, accessToken) {
  const { privateKey, publicKey, nonce: nonce2 = dpopNonces.get(url.origin) } = options2;
  if (!isPrivateKey(privateKey)) {
    throw new TypeError('"DPoP.privateKey" must be a private CryptoKey');
  }
  if (!isPublicKey(publicKey)) {
    throw new TypeError('"DPoP.publicKey" must be a public CryptoKey');
  }
  if (nonce2 !== void 0 && !validateString(nonce2)) {
    throw new TypeError('"DPoP.nonce" must be a non-empty string or undefined');
  }
  if (!publicKey.extractable) {
    throw new TypeError('"DPoP.publicKey.extractable" must be true');
  }
  const now2 = epochTime() + clockSkew2;
  const proof = await jwt({
    alg: keyToJws(privateKey),
    typ: "dpop+jwt",
    jwk: await publicJwk(publicKey)
  }, {
    iat: now2,
    jti: randomBytes(),
    htm,
    nonce: nonce2,
    htu: `${url.origin}${url.pathname}`,
    ath: accessToken ? b64u(await crypto.subtle.digest("SHA-256", buf(accessToken))) : void 0
  }, privateKey);
  headers2.set("dpop", proof);
}
async function getSetPublicJwkCache(key2) {
  const { kty, e: e2, n: n3, x: x2, y: y2, crv } = await crypto.subtle.exportKey("jwk", key2);
  const jwk = { kty, e: e2, n: n3, x: x2, y: y2, crv };
  jwkCache.set(key2, jwk);
  return jwk;
}
async function publicJwk(key2) {
  jwkCache || (jwkCache = /* @__PURE__ */ new WeakMap());
  return jwkCache.get(key2) || getSetPublicJwkCache(key2);
}
function validateEndpoint(value, endpoint, options2) {
  if (typeof value !== "string") {
    if (options2?.[useMtlsAlias]) {
      throw new TypeError(`"as.mtls_endpoint_aliases.${endpoint}" must be a string`);
    }
    throw new TypeError(`"as.${endpoint}" must be a string`);
  }
  return new URL(value);
}
function resolveEndpoint(as, endpoint, options2) {
  if (options2?.[useMtlsAlias] && as.mtls_endpoint_aliases && endpoint in as.mtls_endpoint_aliases) {
    return validateEndpoint(as.mtls_endpoint_aliases[endpoint], endpoint, options2);
  }
  return validateEndpoint(as[endpoint], endpoint);
}
function isOAuth2Error(input) {
  const value = input;
  if (typeof value !== "object" || Array.isArray(value) || value === null) {
    return false;
  }
  return value.error !== void 0;
}
function unquote(value) {
  if (value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"') {
    return value.slice(1, -1);
  }
  return value;
}
function wwwAuth(scheme, params) {
  const arr = params.split(SPLIT_REGEXP).slice(1);
  if (!arr.length) {
    return { scheme: scheme.toLowerCase(), parameters: {} };
  }
  arr[arr.length - 1] = arr[arr.length - 1].replace(/,$/, "");
  const parameters = {};
  for (let i3 = 1; i3 < arr.length; i3 += 2) {
    const idx = i3;
    if (arr[idx][0] === '"') {
      while (arr[idx].slice(-1) !== '"' && ++i3 < arr.length) {
        arr[idx] += arr[i3];
      }
    }
    const key2 = arr[idx - 1].replace(/^(?:, ?)|=$/g, "").toLowerCase();
    parameters[key2] = unquote(arr[idx]);
  }
  return {
    scheme: scheme.toLowerCase(),
    parameters
  };
}
function parseWwwAuthenticateChallenges(response) {
  if (!looseInstanceOf(response, Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  const header = response.headers.get("www-authenticate");
  if (header === null) {
    return void 0;
  }
  const result = [];
  for (const { 1: scheme, index: index5 } of header.matchAll(SCHEMES_REGEXP)) {
    result.push([scheme, index5]);
  }
  if (!result.length) {
    return void 0;
  }
  const challenges = result.map(([scheme, indexOf], i3, others) => {
    const next = others[i3 + 1];
    let parameters;
    if (next) {
      parameters = header.slice(indexOf, next[1]);
    } else {
      parameters = header.slice(indexOf);
    }
    return wwwAuth(scheme, parameters);
  });
  return challenges;
}
async function protectedResourceRequest(accessToken, method, url, headers2, body2, options2) {
  if (!validateString(accessToken)) {
    throw new TypeError('"accessToken" must be a non-empty string');
  }
  if (!(url instanceof URL)) {
    throw new TypeError('"url" must be an instance of URL');
  }
  headers2 = prepareHeaders(headers2);
  if (options2?.DPoP === void 0) {
    headers2.set("authorization", `Bearer ${accessToken}`);
  } else {
    await dpopProofJwt(headers2, options2.DPoP, url, "GET", getClockSkew({ [clockSkew]: options2?.[clockSkew] }), accessToken);
    headers2.set("authorization", `DPoP ${accessToken}`);
  }
  return (options2?.[customFetch] || fetch)(url.href, {
    body: body2,
    headers: Object.fromEntries(headers2.entries()),
    method,
    redirect: "manual",
    signal: options2?.signal ? signal(options2.signal) : null
  }).then(processDpopNonce);
}
async function userInfoRequest(as, client, accessToken, options2) {
  assertAs(as);
  assertClient(client);
  const url = resolveEndpoint(as, "userinfo_endpoint", options2);
  const headers2 = prepareHeaders(options2?.headers);
  if (client.userinfo_signed_response_alg) {
    headers2.set("accept", "application/jwt");
  } else {
    headers2.set("accept", "application/json");
    headers2.append("accept", "application/jwt");
  }
  return protectedResourceRequest(accessToken, "GET", url, headers2, null, {
    ...options2,
    [clockSkew]: getClockSkew(client)
  });
}
async function authenticatedRequest(as, client, method, url, body2, headers2, options2) {
  await clientAuthentication(as, client, body2, headers2, options2?.clientPrivateKey);
  headers2.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
  return (options2?.[customFetch] || fetch)(url.href, {
    body: body2,
    headers: Object.fromEntries(headers2.entries()),
    method,
    redirect: "manual",
    signal: options2?.signal ? signal(options2.signal) : null
  }).then(processDpopNonce);
}
async function tokenEndpointRequest(as, client, grantType, parameters, options2) {
  const url = resolveEndpoint(as, "token_endpoint", options2);
  parameters.set("grant_type", grantType);
  const headers2 = prepareHeaders(options2?.headers);
  headers2.set("accept", "application/json");
  if (options2?.DPoP !== void 0) {
    await dpopProofJwt(headers2, options2.DPoP, url, "POST", getClockSkew(client));
  }
  return authenticatedRequest(as, client, "POST", url, parameters, headers2, options2);
}
function getValidatedIdTokenClaims(ref) {
  if (!ref.id_token) {
    return void 0;
  }
  const claims = idTokenClaims.get(ref);
  if (!claims) {
    throw new TypeError('"ref" was already garbage collected or did not resolve from the proper sources');
  }
  return claims;
}
async function processGenericAccessTokenResponse(as, client, response, ignoreIdToken = false, ignoreRefreshToken = false) {
  assertAs(as);
  assertClient(client);
  if (!looseInstanceOf(response, Response)) {
    throw new TypeError('"response" must be an instance of Response');
  }
  if (response.status !== 200) {
    let err;
    if (err = await handleOAuthBodyError(response)) {
      return err;
    }
    throw new OPE('"response" is not a conform Token Endpoint response');
  }
  assertReadableResponse(response);
  let json2;
  try {
    json2 = await response.json();
  } catch (cause) {
    throw new OPE('failed to parse "response" body as JSON', { cause });
  }
  if (!isJsonObject(json2)) {
    throw new OPE('"response" body must be a top level object');
  }
  if (!validateString(json2.access_token)) {
    throw new OPE('"response" body "access_token" property must be a non-empty string');
  }
  if (!validateString(json2.token_type)) {
    throw new OPE('"response" body "token_type" property must be a non-empty string');
  }
  json2.token_type = json2.token_type.toLowerCase();
  if (json2.token_type !== "dpop" && json2.token_type !== "bearer") {
    throw new UnsupportedOperationError("unsupported `token_type` value");
  }
  if (json2.expires_in !== void 0 && (typeof json2.expires_in !== "number" || json2.expires_in <= 0)) {
    throw new OPE('"response" body "expires_in" property must be a positive number');
  }
  if (!ignoreRefreshToken && json2.refresh_token !== void 0 && !validateString(json2.refresh_token)) {
    throw new OPE('"response" body "refresh_token" property must be a non-empty string');
  }
  if (json2.scope !== void 0 && typeof json2.scope !== "string") {
    throw new OPE('"response" body "scope" property must be a string');
  }
  if (!ignoreIdToken) {
    if (json2.id_token !== void 0 && !validateString(json2.id_token)) {
      throw new OPE('"response" body "id_token" property must be a non-empty string');
    }
    if (json2.id_token) {
      const { claims } = await validateJwt(json2.id_token, checkSigningAlgorithm.bind(void 0, client.id_token_signed_response_alg, as.id_token_signing_alg_values_supported), noSignatureCheck, getClockSkew(client), getClockTolerance(client)).then(validatePresence.bind(void 0, ["aud", "exp", "iat", "iss", "sub"])).then(validateIssuer.bind(void 0, as.issuer)).then(validateAudience.bind(void 0, client.client_id));
      if (Array.isArray(claims.aud) && claims.aud.length !== 1 && claims.azp !== client.client_id) {
        throw new OPE('unexpected ID Token "azp" (authorized party) claim value');
      }
      if (client.require_auth_time && typeof claims.auth_time !== "number") {
        throw new OPE('unexpected ID Token "auth_time" (authentication time) claim value');
      }
      idTokenClaims.set(json2, claims);
    }
  }
  return json2;
}
function validateAudience(expected, result) {
  if (Array.isArray(result.claims.aud)) {
    if (!result.claims.aud.includes(expected)) {
      throw new OPE('unexpected JWT "aud" (audience) claim value');
    }
  } else if (result.claims.aud !== expected) {
    throw new OPE('unexpected JWT "aud" (audience) claim value');
  }
  return result;
}
function validateIssuer(expected, result) {
  if (result.claims.iss !== expected) {
    throw new OPE('unexpected JWT "iss" (issuer) claim value');
  }
  return result;
}
function brand(searchParams) {
  branded.add(searchParams);
  return searchParams;
}
async function authorizationCodeGrantRequest(as, client, callbackParameters, redirectUri, codeVerifier, options2) {
  assertAs(as);
  assertClient(client);
  if (!branded.has(callbackParameters)) {
    throw new TypeError('"callbackParameters" must be an instance of URLSearchParams obtained from "validateAuthResponse()", or "validateJwtAuthResponse()');
  }
  if (!validateString(redirectUri)) {
    throw new TypeError('"redirectUri" must be a non-empty string');
  }
  if (!validateString(codeVerifier)) {
    throw new TypeError('"codeVerifier" must be a non-empty string');
  }
  const code = getURLSearchParameter(callbackParameters, "code");
  if (!code) {
    throw new OPE('no authorization code in "callbackParameters"');
  }
  const parameters = new URLSearchParams(options2?.additionalParameters);
  parameters.set("redirect_uri", redirectUri);
  parameters.set("code_verifier", codeVerifier);
  parameters.set("code", code);
  return tokenEndpointRequest(as, client, "authorization_code", parameters, options2);
}
function validatePresence(required, result) {
  for (const claim of required) {
    if (result.claims[claim] === void 0) {
      throw new OPE(`JWT "${claim}" (${jwtClaimNames[claim]}) claim missing`);
    }
  }
  return result;
}
async function processAuthorizationCodeOpenIDResponse(as, client, response, expectedNonce, maxAge) {
  const result = await processGenericAccessTokenResponse(as, client, response);
  if (isOAuth2Error(result)) {
    return result;
  }
  if (!validateString(result.id_token)) {
    throw new OPE('"response" body "id_token" property must be a non-empty string');
  }
  maxAge ?? (maxAge = client.default_max_age ?? skipAuthTimeCheck);
  const claims = getValidatedIdTokenClaims(result);
  if ((client.require_auth_time || maxAge !== skipAuthTimeCheck) && claims.auth_time === void 0) {
    throw new OPE('ID Token "auth_time" (authentication time) claim missing');
  }
  if (maxAge !== skipAuthTimeCheck) {
    if (typeof maxAge !== "number" || maxAge < 0) {
      throw new TypeError('"options.max_age" must be a non-negative number');
    }
    const now2 = epochTime() + getClockSkew(client);
    const tolerance = getClockTolerance(client);
    if (claims.auth_time + maxAge < now2 - tolerance) {
      throw new OPE("too much time has elapsed since the last End-User authentication");
    }
  }
  switch (expectedNonce) {
    case void 0:
    case expectNoNonce:
      if (claims.nonce !== void 0) {
        throw new OPE('unexpected ID Token "nonce" claim value');
      }
      break;
    default:
      if (!validateString(expectedNonce)) {
        throw new TypeError('"expectedNonce" must be a non-empty string');
      }
      if (claims.nonce === void 0) {
        throw new OPE('ID Token "nonce" claim missing');
      }
      if (claims.nonce !== expectedNonce) {
        throw new OPE('unexpected ID Token "nonce" claim value');
      }
  }
  return result;
}
async function processAuthorizationCodeOAuth2Response(as, client, response) {
  const result = await processGenericAccessTokenResponse(as, client, response, true);
  if (isOAuth2Error(result)) {
    return result;
  }
  if (result.id_token !== void 0) {
    if (typeof result.id_token === "string" && result.id_token.length) {
      throw new OPE("Unexpected ID Token returned, use processAuthorizationCodeOpenIDResponse() for OpenID Connect callback processing");
    }
    delete result.id_token;
  }
  return result;
}
function assertReadableResponse(response) {
  if (response.bodyUsed) {
    throw new TypeError('"response" body has been used already');
  }
}
async function handleOAuthBodyError(response) {
  if (response.status > 399 && response.status < 500) {
    assertReadableResponse(response);
    try {
      const json2 = await response.json();
      if (isJsonObject(json2) && typeof json2.error === "string" && json2.error.length) {
        if (json2.error_description !== void 0 && typeof json2.error_description !== "string") {
          delete json2.error_description;
        }
        if (json2.error_uri !== void 0 && typeof json2.error_uri !== "string") {
          delete json2.error_uri;
        }
        if (json2.algs !== void 0 && typeof json2.algs !== "string") {
          delete json2.algs;
        }
        if (json2.scope !== void 0 && typeof json2.scope !== "string") {
          delete json2.scope;
        }
        return json2;
      }
    } catch {
    }
  }
  return void 0;
}
function checkRsaKeyAlgorithm(algorithm) {
  if (typeof algorithm.modulusLength !== "number" || algorithm.modulusLength < 2048) {
    throw new OPE(`${algorithm.name} modulusLength must be at least 2048 bits`);
  }
}
function ecdsaHashName(namedCurve) {
  switch (namedCurve) {
    case "P-256":
      return "SHA-256";
    case "P-384":
      return "SHA-384";
    case "P-521":
      return "SHA-512";
    default:
      throw new UnsupportedOperationError();
  }
}
function keyToSubtle(key2) {
  switch (key2.algorithm.name) {
    case "ECDSA":
      return {
        name: key2.algorithm.name,
        hash: ecdsaHashName(key2.algorithm.namedCurve)
      };
    case "RSA-PSS": {
      checkRsaKeyAlgorithm(key2.algorithm);
      switch (key2.algorithm.hash.name) {
        case "SHA-256":
        case "SHA-384":
        case "SHA-512":
          return {
            name: key2.algorithm.name,
            saltLength: parseInt(key2.algorithm.hash.name.slice(-3), 10) >> 3
          };
        default:
          throw new UnsupportedOperationError();
      }
    }
    case "RSASSA-PKCS1-v1_5":
      checkRsaKeyAlgorithm(key2.algorithm);
      return key2.algorithm.name;
    case "Ed448":
    case "Ed25519":
      return key2.algorithm.name;
  }
  throw new UnsupportedOperationError();
}
async function validateJwt(jws, checkAlg, getKey, clockSkew2, clockTolerance2) {
  const { 0: protectedHeader, 1: payload, 2: encodedSignature, length } = jws.split(".");
  if (length === 5) {
    throw new UnsupportedOperationError("JWE structure JWTs are not supported");
  }
  if (length !== 3) {
    throw new OPE("Invalid JWT");
  }
  let header;
  try {
    header = JSON.parse(buf(b64u(protectedHeader)));
  } catch (cause) {
    throw new OPE("failed to parse JWT Header body as base64url encoded JSON", { cause });
  }
  if (!isJsonObject(header)) {
    throw new OPE("JWT Header must be a top level object");
  }
  checkAlg(header);
  if (header.crit !== void 0) {
    throw new OPE('unexpected JWT "crit" header parameter');
  }
  const signature = b64u(encodedSignature);
  let key2;
  if (getKey !== noSignatureCheck) {
    key2 = await getKey(header);
    const input = `${protectedHeader}.${payload}`;
    const verified = await crypto.subtle.verify(keyToSubtle(key2), key2, signature, buf(input));
    if (!verified) {
      throw new OPE("JWT signature verification failed");
    }
  }
  let claims;
  try {
    claims = JSON.parse(buf(b64u(payload)));
  } catch (cause) {
    throw new OPE("failed to parse JWT Payload body as base64url encoded JSON", { cause });
  }
  if (!isJsonObject(claims)) {
    throw new OPE("JWT Payload must be a top level object");
  }
  const now2 = epochTime() + clockSkew2;
  if (claims.exp !== void 0) {
    if (typeof claims.exp !== "number") {
      throw new OPE('unexpected JWT "exp" (expiration time) claim type');
    }
    if (claims.exp <= now2 - clockTolerance2) {
      throw new OPE('unexpected JWT "exp" (expiration time) claim value, timestamp is <= now()');
    }
  }
  if (claims.iat !== void 0) {
    if (typeof claims.iat !== "number") {
      throw new OPE('unexpected JWT "iat" (issued at) claim type');
    }
  }
  if (claims.iss !== void 0) {
    if (typeof claims.iss !== "string") {
      throw new OPE('unexpected JWT "iss" (issuer) claim type');
    }
  }
  if (claims.nbf !== void 0) {
    if (typeof claims.nbf !== "number") {
      throw new OPE('unexpected JWT "nbf" (not before) claim type');
    }
    if (claims.nbf > now2 + clockTolerance2) {
      throw new OPE('unexpected JWT "nbf" (not before) claim value, timestamp is > now()');
    }
  }
  if (claims.aud !== void 0) {
    if (typeof claims.aud !== "string" && !Array.isArray(claims.aud)) {
      throw new OPE('unexpected JWT "aud" (audience) claim type');
    }
  }
  return { header, claims, signature, key: key2 };
}
function checkSigningAlgorithm(client, issuer, header) {
  if (client !== void 0) {
    if (header.alg !== client) {
      throw new OPE('unexpected JWT "alg" header parameter');
    }
    return;
  }
  if (Array.isArray(issuer)) {
    if (!issuer.includes(header.alg)) {
      throw new OPE('unexpected JWT "alg" header parameter');
    }
    return;
  }
  if (header.alg !== "RS256") {
    throw new OPE('unexpected JWT "alg" header parameter');
  }
}
function getURLSearchParameter(parameters, name) {
  const { 0: value, length } = parameters.getAll(name);
  if (length > 1) {
    throw new OPE(`"${name}" parameter must be provided only once`);
  }
  return value;
}
function validateAuthResponse(as, client, parameters, expectedState) {
  assertAs(as);
  assertClient(client);
  if (parameters instanceof URL) {
    parameters = parameters.searchParams;
  }
  if (!(parameters instanceof URLSearchParams)) {
    throw new TypeError('"parameters" must be an instance of URLSearchParams, or URL');
  }
  if (getURLSearchParameter(parameters, "response")) {
    throw new OPE('"parameters" contains a JARM response, use validateJwtAuthResponse() instead of validateAuthResponse()');
  }
  const iss = getURLSearchParameter(parameters, "iss");
  const state2 = getURLSearchParameter(parameters, "state");
  if (!iss && as.authorization_response_iss_parameter_supported) {
    throw new OPE('response parameter "iss" (issuer) missing');
  }
  if (iss && iss !== as.issuer) {
    throw new OPE('unexpected "iss" (issuer) response parameter value');
  }
  switch (expectedState) {
    case void 0:
    case expectNoState:
      if (state2 !== void 0) {
        throw new OPE('unexpected "state" response parameter encountered');
      }
      break;
    case skipStateCheck:
      break;
    default:
      if (!validateString(expectedState)) {
        throw new OPE('"expectedState" must be a non-empty string');
      }
      if (state2 === void 0) {
        throw new OPE('response parameter "state" missing');
      }
      if (state2 !== expectedState) {
        throw new OPE('unexpected "state" response parameter value');
      }
  }
  const error = getURLSearchParameter(parameters, "error");
  if (error) {
    return {
      error,
      error_description: getURLSearchParameter(parameters, "error_description"),
      error_uri: getURLSearchParameter(parameters, "error_uri")
    };
  }
  const id_token = getURLSearchParameter(parameters, "id_token");
  const token = getURLSearchParameter(parameters, "token");
  if (id_token !== void 0 || token !== void 0) {
    throw new UnsupportedOperationError("implicit and hybrid flows are not supported");
  }
  return brand(new URLSearchParams(parameters));
}
var USER_AGENT2, clockSkew, clockTolerance, customFetch, useMtlsAlias, encoder2, decoder2, CHUNK_SIZE2, LRU, UnsupportedOperationError, OperationProcessingError, OPE, dpopNonces, jwkCache, SPLIT_REGEXP, SCHEMES_REGEXP, skipSubjectCheck, idTokenClaims, branded, jwtClaimNames, expectNoNonce, skipAuthTimeCheck, noSignatureCheck, skipStateCheck, expectNoState;
var init_build = __esm({
  "node_modules/oauth4webapi/build/index.js"() {
    if (typeof navigator === "undefined" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) {
      const NAME = "oauth4webapi";
      const VERSION = "v2.10.3";
      USER_AGENT2 = `${NAME}/${VERSION}`;
    }
    clockSkew = Symbol();
    clockTolerance = Symbol();
    customFetch = Symbol();
    useMtlsAlias = Symbol();
    encoder2 = new TextEncoder();
    decoder2 = new TextDecoder();
    CHUNK_SIZE2 = 32768;
    LRU = class {
      constructor(maxSize) {
        this.cache = /* @__PURE__ */ new Map();
        this._cache = /* @__PURE__ */ new Map();
        this.maxSize = maxSize;
      }
      get(key2) {
        let v3 = this.cache.get(key2);
        if (v3) {
          return v3;
        }
        if (v3 = this._cache.get(key2)) {
          this.update(key2, v3);
          return v3;
        }
        return void 0;
      }
      has(key2) {
        return this.cache.has(key2) || this._cache.has(key2);
      }
      set(key2, value) {
        if (this.cache.has(key2)) {
          this.cache.set(key2, value);
        } else {
          this.update(key2, value);
        }
        return this;
      }
      delete(key2) {
        if (this.cache.has(key2)) {
          return this.cache.delete(key2);
        }
        if (this._cache.has(key2)) {
          return this._cache.delete(key2);
        }
        return false;
      }
      update(key2, value) {
        this.cache.set(key2, value);
        if (this.cache.size >= this.maxSize) {
          this._cache = this.cache;
          this.cache = /* @__PURE__ */ new Map();
        }
      }
    };
    UnsupportedOperationError = class extends Error {
      constructor(message2) {
        super(message2 ?? "operation not supported");
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
      }
    };
    OperationProcessingError = class extends Error {
      constructor(message2, options2) {
        super(message2, options2);
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
      }
    };
    OPE = OperationProcessingError;
    dpopNonces = new LRU(100);
    SPLIT_REGEXP = /((?:,|, )?[0-9a-zA-Z!#$%&'*+-.^_`|~]+=)/;
    SCHEMES_REGEXP = /(?:^|, ?)([0-9a-zA-Z!#$%&'*+\-.^_`|~]+)(?=$|[ ,])/g;
    skipSubjectCheck = Symbol();
    idTokenClaims = /* @__PURE__ */ new WeakMap();
    branded = /* @__PURE__ */ new WeakSet();
    jwtClaimNames = {
      aud: "audience",
      c_hash: "code hash",
      client_id: "client id",
      exp: "expiration time",
      iat: "issued at",
      iss: "issuer",
      jti: "jwt id",
      nonce: "nonce",
      s_hash: "state hash",
      sub: "subject",
      ath: "access token hash",
      htm: "http method",
      htu: "http uri",
      cnf: "confirmation"
    };
    expectNoNonce = Symbol();
    skipAuthTimeCheck = Symbol();
    noSignatureCheck = Symbol();
    skipStateCheck = Symbol();
    expectNoState = Symbol();
  }
});

// node_modules/@auth/core/lib/actions/callback/oauth/checks.js
async function signCookie(type, value, maxAge, options2, data) {
  const { cookies, logger: logger2 } = options2;
  logger2.debug(`CREATE_${type.toUpperCase()}`, { value, maxAge });
  const expires = /* @__PURE__ */ new Date();
  expires.setTime(expires.getTime() + maxAge * 1e3);
  const token = { value };
  if (type === "state" && data)
    token.data = data;
  const name = cookies[type].name;
  return {
    name,
    value: await encode3({ ...options2.jwt, maxAge, token, salt: name }),
    options: { ...cookies[type].options, expires }
  };
}
function decodeState(value) {
  try {
    const decoder3 = new TextDecoder();
    return JSON.parse(decoder3.decode(base64url_exports2.decode(value)));
  } catch {
  }
}
function handleState(query, provider, isOnRedirectProxy) {
  let randomState;
  let proxyRedirect;
  if (provider.redirectProxyUrl && !query?.state) {
    throw new InvalidCheck("Missing state in query, but required for redirect proxy");
  }
  const state2 = decodeState(query?.state);
  randomState = state2?.random;
  if (isOnRedirectProxy) {
    if (!state2?.origin)
      return { randomState };
    proxyRedirect = `${state2.origin}?${new URLSearchParams(query)}`;
  }
  return { randomState, proxyRedirect };
}
var PKCE_MAX_AGE, pkce, STATE_MAX_AGE, state, NONCE_MAX_AGE, nonce, WEBAUTHN_CHALLENGE_MAX_AGE, webauthnChallenge;
var init_checks = __esm({
  "node_modules/@auth/core/lib/actions/callback/oauth/checks.js"() {
    init_browser();
    init_build();
    init_errors();
    init_jwt();
    PKCE_MAX_AGE = 60 * 15;
    pkce = {
      async create(options2) {
        const code_verifier = generateRandomCodeVerifier();
        const value = await calculatePKCECodeChallenge(code_verifier);
        const maxAge = PKCE_MAX_AGE;
        const cookie = await signCookie("pkceCodeVerifier", code_verifier, maxAge, options2);
        return { cookie, value };
      },
      /**
       * Returns code_verifier if the provider is configured to use PKCE,
       * and clears the container cookie afterwards.
       * An error is thrown if the code_verifier is missing or invalid.
       * @see https://www.rfc-editor.org/rfc/rfc7636
       * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#pkce
       */
      async use(cookies, resCookies, options2) {
        const { provider } = options2;
        if (!provider?.checks?.includes("pkce"))
          return;
        const codeVerifier = cookies?.[options2.cookies.pkceCodeVerifier.name];
        if (!codeVerifier)
          throw new InvalidCheck("PKCE code_verifier cookie was missing.");
        const value = await decode3({
          ...options2.jwt,
          token: codeVerifier,
          salt: options2.cookies.pkceCodeVerifier.name
        });
        if (!value?.value)
          throw new InvalidCheck("PKCE code_verifier value could not be parsed.");
        resCookies.push({
          name: options2.cookies.pkceCodeVerifier.name,
          value: "",
          options: { ...options2.cookies.pkceCodeVerifier.options, maxAge: 0 }
        });
        return value.value;
      }
    };
    STATE_MAX_AGE = 60 * 15;
    state = {
      async create(options2, data) {
        const { provider } = options2;
        if (!provider.checks.includes("state")) {
          if (data) {
            throw new InvalidCheck("State data was provided but the provider is not configured to use state.");
          }
          return;
        }
        const encodedState = base64url_exports2.encode(JSON.stringify({ ...data, random: generateRandomState() }));
        const maxAge = STATE_MAX_AGE;
        const cookie = await signCookie("state", encodedState, maxAge, options2, data);
        return { cookie, value: encodedState };
      },
      /**
       * Returns state if the provider is configured to use state,
       * and clears the container cookie afterwards.
       * An error is thrown if the state is missing or invalid.
       * @see https://www.rfc-editor.org/rfc/rfc6749#section-10.12
       * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
       */
      async use(cookies, resCookies, options2, paramRandom) {
        const { provider } = options2;
        if (!provider.checks.includes("state"))
          return;
        const state2 = cookies?.[options2.cookies.state.name];
        if (!state2)
          throw new InvalidCheck("State cookie was missing.");
        const encodedState = await decode3({
          ...options2.jwt,
          token: state2,
          salt: options2.cookies.state.name
        });
        if (!encodedState?.value)
          throw new InvalidCheck("State (cookie) value could not be parsed.");
        const decodedState = decodeState(encodedState.value);
        if (!decodedState)
          throw new InvalidCheck("State (encoded) value could not be parsed.");
        if (decodedState.random !== paramRandom)
          throw new InvalidCheck(`Random state values did not match. Expected: ${decodedState.random}. Got: ${paramRandom}`);
        resCookies.push({
          name: options2.cookies.state.name,
          value: "",
          options: { ...options2.cookies.state.options, maxAge: 0 }
        });
        return encodedState.value;
      }
    };
    NONCE_MAX_AGE = 60 * 15;
    nonce = {
      async create(options2) {
        if (!options2.provider.checks.includes("nonce"))
          return;
        const value = generateRandomNonce();
        const maxAge = NONCE_MAX_AGE;
        const cookie = await signCookie("nonce", value, maxAge, options2);
        return { cookie, value };
      },
      /**
       * Returns nonce if the provider is configured to use nonce,
       * and clears the container cookie afterwards.
       * An error is thrown if the nonce is missing or invalid.
       * @see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
       * @see https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/#nonce
       */
      async use(cookies, resCookies, options2) {
        const { provider } = options2;
        if (!provider?.checks?.includes("nonce"))
          return;
        const nonce2 = cookies?.[options2.cookies.nonce.name];
        if (!nonce2)
          throw new InvalidCheck("Nonce cookie was missing.");
        const value = await decode3({
          ...options2.jwt,
          token: nonce2,
          salt: options2.cookies.nonce.name
        });
        if (!value?.value)
          throw new InvalidCheck("Nonce value could not be parsed.");
        resCookies.push({
          name: options2.cookies.nonce.name,
          value: "",
          options: { ...options2.cookies.nonce.options, maxAge: 0 }
        });
        return value.value;
      }
    };
    WEBAUTHN_CHALLENGE_MAX_AGE = 60 * 15;
    webauthnChallenge = {
      async create(options2, challenge, registerData) {
        const maxAge = WEBAUTHN_CHALLENGE_MAX_AGE;
        const data = { challenge, registerData };
        const cookie = await signCookie("webauthnChallenge", JSON.stringify(data), maxAge, options2);
        return { cookie };
      },
      /**
       * Returns challenge if present,
       */
      async use(options2, cookies, resCookies) {
        const challenge = cookies?.[options2.cookies.webauthnChallenge.name];
        if (!challenge)
          throw new InvalidCheck("Challenge cookie missing.");
        const value = await decode3({
          ...options2.jwt,
          token: challenge,
          salt: options2.cookies.webauthnChallenge.name
        });
        if (!value?.value)
          throw new InvalidCheck("Challenge value could not be parsed.");
        const cookie = {
          name: options2.cookies.webauthnChallenge.name,
          value: "",
          options: { ...options2.cookies.webauthnChallenge.options, maxAge: 0 }
        };
        resCookies.push(cookie);
        return JSON.parse(value.value);
      }
    };
  }
});

// node_modules/@auth/core/lib/actions/callback/oauth/callback.js
async function handleOAuth(query, cookies, options2, randomState) {
  const { logger: logger2, provider } = options2;
  let as;
  const { token, userinfo } = provider;
  if ((!token?.url || token.url.host === "authjs.dev") && (!userinfo?.url || userinfo.url.host === "authjs.dev")) {
    const issuer = new URL(provider.issuer);
    const discoveryResponse = await discoveryRequest(issuer);
    const discoveredAs = await processDiscoveryResponse(issuer, discoveryResponse);
    if (!discoveredAs.token_endpoint)
      throw new TypeError("TODO: Authorization server did not provide a token endpoint.");
    if (!discoveredAs.userinfo_endpoint)
      throw new TypeError("TODO: Authorization server did not provide a userinfo endpoint.");
    as = discoveredAs;
  } else {
    as = {
      issuer: provider.issuer ?? "https://authjs.dev",
      // TODO: review fallback issuer
      token_endpoint: token?.url.toString(),
      userinfo_endpoint: userinfo?.url.toString()
    };
  }
  const client = {
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    ...provider.client
  };
  const resCookies = [];
  const state2 = await state.use(cookies, resCookies, options2, randomState);
  const codeGrantParams = validateAuthResponse(as, client, new URLSearchParams(query), provider.checks.includes("state") ? state2 : skipStateCheck);
  if (isOAuth2Error(codeGrantParams)) {
    const cause = { providerId: provider.id, ...codeGrantParams };
    logger2.debug("OAuthCallbackError", cause);
    throw new OAuthCallbackError("OAuth Provider returned an error", cause);
  }
  const codeVerifier = await pkce.use(cookies, resCookies, options2);
  let redirect_uri = provider.callbackUrl;
  if (!options2.isOnRedirectProxy && provider.redirectProxyUrl) {
    redirect_uri = provider.redirectProxyUrl;
  }
  let codeGrantResponse = await authorizationCodeGrantRequest(
    as,
    client,
    codeGrantParams,
    redirect_uri,
    codeVerifier ?? "auth"
    // TODO: review fallback code verifier
  );
  if (provider.token?.conform) {
    codeGrantResponse = await provider.token.conform(codeGrantResponse.clone()) ?? codeGrantResponse;
  }
  let challenges;
  if (challenges = parseWwwAuthenticateChallenges(codeGrantResponse)) {
    for (const challenge of challenges) {
      console.log("challenge", challenge);
    }
    throw new Error("TODO: Handle www-authenticate challenges as needed");
  }
  let profile = {};
  let tokens;
  if (provider.type === "oidc") {
    const nonce2 = await nonce.use(cookies, resCookies, options2);
    const result = await processAuthorizationCodeOpenIDResponse(as, client, codeGrantResponse, nonce2 ?? expectNoNonce);
    if (isOAuth2Error(result)) {
      console.log("error", result);
      throw new Error("TODO: Handle OIDC response body error");
    }
    profile = getValidatedIdTokenClaims(result);
    tokens = result;
  } else {
    tokens = await processAuthorizationCodeOAuth2Response(as, client, codeGrantResponse);
    if (isOAuth2Error(tokens)) {
      console.log("error", tokens);
      throw new Error("TODO: Handle OAuth 2.0 response body error");
    }
    if (userinfo?.request) {
      const _profile = await userinfo.request({ tokens, provider });
      if (_profile instanceof Object)
        profile = _profile;
    } else if (userinfo?.url) {
      const userinfoResponse = await userInfoRequest(as, client, tokens.access_token);
      profile = await userinfoResponse.json();
    } else {
      throw new TypeError("No userinfo endpoint configured");
    }
  }
  if (tokens.expires_in) {
    tokens.expires_at = Math.floor(Date.now() / 1e3) + Number(tokens.expires_in);
  }
  const profileResult = await getUserAndAccount(profile, provider, tokens, logger2);
  return { ...profileResult, profile, cookies: resCookies };
}
async function getUserAndAccount(OAuthProfile, provider, tokens, logger2) {
  try {
    const userFromProfile = await provider.profile(OAuthProfile, tokens);
    const user = {
      ...userFromProfile,
      id: crypto.randomUUID(),
      email: userFromProfile.email?.toLowerCase()
    };
    return {
      user,
      account: {
        ...tokens,
        provider: provider.id,
        type: provider.type,
        providerAccountId: userFromProfile.id ?? crypto.randomUUID()
      }
    };
  } catch (e2) {
    logger2.debug("getProfile error details", OAuthProfile);
    logger2.error(new OAuthProfileParseError(e2, { provider: provider.id }));
  }
}
var init_callback = __esm({
  "node_modules/@auth/core/lib/actions/callback/oauth/callback.js"() {
    init_checks();
    init_build();
    init_errors();
  }
});

// node_modules/@auth/core/lib/utils/webauthn-utils.js
function inferWebAuthnOptions(action, loggedIn, userInfoResponse) {
  const { user, exists = false } = userInfoResponse ?? {};
  switch (action) {
    case "authenticate": {
      return "authenticate";
    }
    case "register": {
      if (user && loggedIn === exists)
        return "register";
      break;
    }
    case void 0: {
      if (!loggedIn) {
        if (user) {
          if (exists) {
            return "authenticate";
          } else {
            return "register";
          }
        } else {
          return "authenticate";
        }
      }
      break;
    }
  }
  return null;
}
async function getRegistrationResponse(options2, request, user, resCookies) {
  const regOptions = await getRegistrationOptions(options2, request, user);
  const { cookie } = await webauthnChallenge.create(options2, regOptions.challenge, user);
  return {
    status: 200,
    cookies: [...resCookies ?? [], cookie],
    body: {
      action: "register",
      options: regOptions
    },
    headers: {
      "Content-Type": "application/json"
    }
  };
}
async function getAuthenticationResponse(options2, request, user, resCookies) {
  const authOptions = await getAuthenticationOptions(options2, request, user);
  const { cookie } = await webauthnChallenge.create(options2, authOptions.challenge);
  return {
    status: 200,
    cookies: [...resCookies ?? [], cookie],
    body: {
      action: "authenticate",
      options: authOptions
    },
    headers: {
      "Content-Type": "application/json"
    }
  };
}
async function verifyAuthenticate(options2, request, resCookies) {
  const { adapter, provider } = options2;
  const data = request.body && typeof request.body.data === "string" ? JSON.parse(request.body.data) : void 0;
  if (!data || typeof data !== "object" || !("id" in data) || typeof data.id !== "string") {
    throw new AuthError("Invalid WebAuthn Authentication response.");
  }
  const credentialID = toBase64(fromBase64(data.id));
  const authenticator = await adapter.getAuthenticator(credentialID);
  if (!authenticator) {
    throw new AuthError(`WebAuthn authenticator not found in database: ${JSON.stringify({
      credentialID
    })}`);
  }
  const { challenge: expectedChallenge } = await webauthnChallenge.use(options2, request.cookies, resCookies);
  let verification;
  try {
    const relayingParty = provider.getRelayingParty(options2, request);
    verification = await provider.simpleWebAuthn.verifyAuthenticationResponse({
      ...provider.verifyAuthenticationOptions,
      expectedChallenge,
      response: data,
      authenticator: fromAdapterAuthenticator(authenticator),
      expectedOrigin: relayingParty.origin,
      expectedRPID: relayingParty.id
    });
  } catch (e2) {
    throw new WebAuthnVerificationError(e2);
  }
  const { verified, authenticationInfo } = verification;
  if (!verified) {
    throw new WebAuthnVerificationError("WebAuthn authentication response could not be verified.");
  }
  try {
    const { newCounter } = authenticationInfo;
    await adapter.updateAuthenticatorCounter(authenticator.credentialID, newCounter);
  } catch (e2) {
    throw new AdapterError(`Failed to update authenticator counter. This may cause future authentication attempts to fail. ${JSON.stringify({
      credentialID,
      oldCounter: authenticator.counter,
      newCounter: authenticationInfo.newCounter
    })}`, e2);
  }
  const account = await adapter.getAccount(authenticator.providerAccountId, provider.id);
  if (!account) {
    throw new AuthError(`WebAuthn account not found in database: ${JSON.stringify({
      credentialID,
      providerAccountId: authenticator.providerAccountId
    })}`);
  }
  const user = await adapter.getUser(account.userId);
  if (!user) {
    throw new AuthError(`WebAuthn user not found in database: ${JSON.stringify({
      credentialID,
      providerAccountId: authenticator.providerAccountId,
      userID: account.userId
    })}`);
  }
  return {
    account,
    user
  };
}
async function verifyRegister(options2, request, resCookies) {
  const { provider } = options2;
  const data = request.body && typeof request.body.data === "string" ? JSON.parse(request.body.data) : void 0;
  if (!data || typeof data !== "object" || !("id" in data) || typeof data.id !== "string") {
    throw new AuthError("Invalid WebAuthn Registration response.");
  }
  const { challenge: expectedChallenge, registerData: user } = await webauthnChallenge.use(options2, request.cookies, resCookies);
  if (!user) {
    throw new AuthError("Missing user registration data in WebAuthn challenge cookie.");
  }
  let verification;
  try {
    const relayingParty = provider.getRelayingParty(options2, request);
    verification = await provider.simpleWebAuthn.verifyRegistrationResponse({
      ...provider.verifyRegistrationOptions,
      expectedChallenge,
      response: data,
      expectedOrigin: relayingParty.origin,
      expectedRPID: relayingParty.id
    });
  } catch (e2) {
    throw new WebAuthnVerificationError(e2);
  }
  if (!verification.verified || !verification.registrationInfo) {
    throw new WebAuthnVerificationError("WebAuthn registration response could not be verified.");
  }
  const account = {
    providerAccountId: toBase64(verification.registrationInfo.credentialID),
    provider: options2.provider.id,
    type: provider.type
  };
  const authenticator = {
    providerAccountId: account.providerAccountId,
    counter: verification.registrationInfo.counter,
    credentialID: toBase64(verification.registrationInfo.credentialID),
    credentialPublicKey: toBase64(verification.registrationInfo.credentialPublicKey),
    credentialBackedUp: verification.registrationInfo.credentialBackedUp,
    credentialDeviceType: verification.registrationInfo.credentialDeviceType,
    transports: transportsToString(data.response.transports)
  };
  return {
    user,
    account,
    authenticator
  };
}
async function getAuthenticationOptions(options2, request, user) {
  const { provider, adapter } = options2;
  const authenticators = user && user["id"] ? await adapter.listAuthenticatorsByUserId(user.id) : null;
  const relayingParty = provider.getRelayingParty(options2, request);
  return await provider.simpleWebAuthn.generateAuthenticationOptions({
    ...provider.authenticationOptions,
    rpID: relayingParty.id,
    allowCredentials: authenticators?.map((a3) => ({
      id: fromBase64(a3.credentialID),
      type: "public-key",
      transports: stringToTransports(a3.transports)
    }))
  });
}
async function getRegistrationOptions(options2, request, user) {
  const { provider, adapter } = options2;
  const authenticators = user["id"] ? await adapter.listAuthenticatorsByUserId(user.id) : null;
  const userID = randomString(32);
  const relayingParty = provider.getRelayingParty(options2, request);
  return await provider.simpleWebAuthn.generateRegistrationOptions({
    ...provider.registrationOptions,
    userID,
    userName: user.email,
    userDisplayName: user.name ?? void 0,
    rpID: relayingParty.id,
    rpName: relayingParty.name,
    excludeCredentials: authenticators?.map((a3) => ({
      id: fromBase64(a3.credentialID),
      type: "public-key",
      transports: stringToTransports(a3.transports)
    }))
  });
}
function assertInternalOptionsWebAuthn(options2) {
  const { provider, adapter } = options2;
  if (!adapter)
    throw new MissingAdapter("An adapter is required for the WebAuthn provider");
  if (!provider || provider.type !== "webauthn") {
    throw new InvalidProvider("Provider must be WebAuthn");
  }
  return { ...options2, provider, adapter };
}
function fromAdapterAuthenticator(authenticator) {
  return {
    ...authenticator,
    credentialDeviceType: authenticator.credentialDeviceType,
    transports: stringToTransports(authenticator.transports),
    credentialID: fromBase64(authenticator.credentialID),
    credentialPublicKey: fromBase64(authenticator.credentialPublicKey)
  };
}
function fromBase64(base642) {
  return new Uint8Array(Buffer.from(base642, "base64"));
}
function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}
function transportsToString(transports) {
  return transports?.join(",");
}
function stringToTransports(tstring) {
  return tstring ? tstring.split(",") : void 0;
}
var init_webauthn_utils = __esm({
  "node_modules/@auth/core/lib/utils/webauthn-utils.js"() {
    init_errors();
    init_checks();
    init_web2();
  }
});

// node_modules/@auth/core/lib/actions/callback/index.js
async function callback(request, options2, sessionStore, cookies) {
  if (!options2.provider)
    throw new InvalidProvider("Callback route called without provider");
  const { query, body: body2, method, headers: headers2 } = request;
  const { provider, adapter, url, callbackUrl, pages, jwt: jwt2, events, callbacks, session: { strategy: sessionStrategy, maxAge: sessionMaxAge }, logger: logger2 } = options2;
  const useJwtSession = sessionStrategy === "jwt";
  try {
    if (provider.type === "oauth" || provider.type === "oidc") {
      const { proxyRedirect, randomState } = handleState(query, provider, options2.isOnRedirectProxy);
      if (proxyRedirect) {
        logger2.debug("proxy redirect", { proxyRedirect, randomState });
        return { redirect: proxyRedirect };
      }
      const authorizationResult = await handleOAuth(query, request.cookies, options2, randomState);
      if (authorizationResult.cookies.length) {
        cookies.push(...authorizationResult.cookies);
      }
      logger2.debug("authorization result", authorizationResult);
      const { user: userFromProvider, account, profile: OAuthProfile } = authorizationResult;
      if (!userFromProvider || !account || !OAuthProfile) {
        return { redirect: `${url}/signin`, cookies };
      }
      let userByAccount;
      if (adapter) {
        const { getUserByAccount } = adapter;
        userByAccount = await getUserByAccount({
          providerAccountId: account.providerAccountId,
          provider: provider.id
        });
      }
      const redirect2 = await handleAuthorized({
        user: userByAccount ?? userFromProvider,
        account,
        profile: OAuthProfile
      }, options2);
      if (redirect2)
        return { redirect: redirect2, cookies };
      const { user, session: session2, isNewUser } = await handleLoginOrRegister(sessionStore.value, userFromProvider, account, options2);
      if (useJwtSession) {
        const defaultToken = {
          name: user.name,
          email: user.email,
          picture: user.image,
          sub: user.id?.toString()
        };
        const token = await callbacks.jwt({
          token: defaultToken,
          user,
          account,
          profile: OAuthProfile,
          isNewUser,
          trigger: isNewUser ? "signUp" : "signIn"
        });
        if (token === null) {
          cookies.push(...sessionStore.clean());
        } else {
          const salt = options2.cookies.sessionToken.name;
          const newToken = await jwt2.encode({ ...jwt2, token, salt });
          const cookieExpires = /* @__PURE__ */ new Date();
          cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
          const sessionCookies = sessionStore.chunk(newToken, {
            expires: cookieExpires
          });
          cookies.push(...sessionCookies);
        }
      } else {
        cookies.push({
          name: options2.cookies.sessionToken.name,
          value: session2.sessionToken,
          options: {
            ...options2.cookies.sessionToken.options,
            expires: session2.expires
          }
        });
      }
      await events.signIn?.({
        user,
        account,
        profile: OAuthProfile,
        isNewUser
      });
      if (isNewUser && pages.newUser) {
        return {
          redirect: `${pages.newUser}${pages.newUser.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl })}`,
          cookies
        };
      }
      return { redirect: callbackUrl, cookies };
    } else if (provider.type === "email") {
      const token = query?.token;
      const identifier = query?.email;
      if (!token || !identifier) {
        const e2 = new TypeError("Missing token or email. The sign-in URL was manually opened without token/identifier or the link was not sent correctly in the email.", { cause: { hasToken: !!token, hasEmail: !!identifier } });
        e2.name = "Configuration";
        throw e2;
      }
      const secret = provider.secret ?? options2.secret;
      const invite = await adapter.useVerificationToken({
        identifier,
        token: await createHash(`${token}${secret}`)
      });
      const hasInvite = !!invite;
      const expired = invite ? invite.expires.valueOf() < Date.now() : void 0;
      const invalidInvite = !hasInvite || expired;
      if (invalidInvite)
        throw new Verification({ hasInvite, expired });
      const user = await adapter.getUserByEmail(identifier) ?? {
        id: crypto.randomUUID(),
        email: identifier,
        emailVerified: null
      };
      const account = {
        providerAccountId: user.email,
        userId: user.id,
        type: "email",
        provider: provider.id
      };
      const redirect2 = await handleAuthorized({ user, account }, options2);
      if (redirect2)
        return { redirect: redirect2, cookies };
      const { user: loggedInUser, session: session2, isNewUser } = await handleLoginOrRegister(sessionStore.value, user, account, options2);
      if (useJwtSession) {
        const defaultToken = {
          name: loggedInUser.name,
          email: loggedInUser.email,
          picture: loggedInUser.image,
          sub: loggedInUser.id?.toString()
        };
        const token2 = await callbacks.jwt({
          token: defaultToken,
          user: loggedInUser,
          account,
          isNewUser,
          trigger: isNewUser ? "signUp" : "signIn"
        });
        if (token2 === null) {
          cookies.push(...sessionStore.clean());
        } else {
          const salt = options2.cookies.sessionToken.name;
          const newToken = await jwt2.encode({ ...jwt2, token: token2, salt });
          const cookieExpires = /* @__PURE__ */ new Date();
          cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
          const sessionCookies = sessionStore.chunk(newToken, {
            expires: cookieExpires
          });
          cookies.push(...sessionCookies);
        }
      } else {
        cookies.push({
          name: options2.cookies.sessionToken.name,
          value: session2.sessionToken,
          options: {
            ...options2.cookies.sessionToken.options,
            expires: session2.expires
          }
        });
      }
      await events.signIn?.({ user: loggedInUser, account, isNewUser });
      if (isNewUser && pages.newUser) {
        return {
          redirect: `${pages.newUser}${pages.newUser.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl })}`,
          cookies
        };
      }
      return { redirect: callbackUrl, cookies };
    } else if (provider.type === "credentials" && method === "POST") {
      const credentials = body2 ?? {};
      Object.entries(query ?? {}).forEach(([k3, v3]) => url.searchParams.set(k3, v3));
      const userFromAuthorize = await provider.authorize(
        credentials,
        // prettier-ignore
        new Request(url, { headers: headers2, method, body: JSON.stringify(body2) })
      );
      const user = userFromAuthorize;
      if (!user)
        throw new CredentialsSignin();
      else
        user.id = user.id?.toString() ?? crypto.randomUUID();
      const account = {
        providerAccountId: user.id,
        type: "credentials",
        provider: provider.id
      };
      const redirect2 = await handleAuthorized({ user, account, credentials }, options2);
      if (redirect2)
        return { redirect: redirect2, cookies };
      const defaultToken = {
        name: user.name,
        email: user.email,
        picture: user.image,
        sub: user.id
      };
      const token = await callbacks.jwt({
        token: defaultToken,
        user,
        account,
        isNewUser: false,
        trigger: "signIn"
      });
      if (token === null) {
        cookies.push(...sessionStore.clean());
      } else {
        const salt = options2.cookies.sessionToken.name;
        const newToken = await jwt2.encode({ ...jwt2, token, salt });
        const cookieExpires = /* @__PURE__ */ new Date();
        cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
        const sessionCookies = sessionStore.chunk(newToken, {
          expires: cookieExpires
        });
        cookies.push(...sessionCookies);
      }
      await events.signIn?.({ user, account });
      return { redirect: callbackUrl, cookies };
    } else if (provider.type === "webauthn" && method === "POST") {
      const action = request.body?.action;
      if (typeof action !== "string" || action !== "authenticate" && action !== "register") {
        throw new AuthError("Invalid action parameter");
      }
      const localOptions = assertInternalOptionsWebAuthn(options2);
      let user;
      let account;
      let authenticator;
      switch (action) {
        case "authenticate": {
          const verified = await verifyAuthenticate(localOptions, request, cookies);
          user = verified.user;
          account = verified.account;
          break;
        }
        case "register": {
          const verified = await verifyRegister(options2, request, cookies);
          user = verified.user;
          account = verified.account;
          authenticator = verified.authenticator;
          break;
        }
      }
      await handleAuthorized({ user, account }, options2);
      const { user: loggedInUser, isNewUser, session: session2, account: currentAccount } = await handleLoginOrRegister(sessionStore.value, user, account, options2);
      if (!currentAccount) {
        throw new AuthError("Error creating or finding account");
      }
      if (authenticator && loggedInUser.id) {
        await localOptions.adapter.createAuthenticator({ ...authenticator, userId: loggedInUser.id });
      }
      if (useJwtSession) {
        const defaultToken = {
          name: loggedInUser.name,
          email: loggedInUser.email,
          picture: loggedInUser.image,
          sub: loggedInUser.id?.toString()
        };
        const token = await callbacks.jwt({
          token: defaultToken,
          user: loggedInUser,
          account: currentAccount,
          isNewUser,
          trigger: isNewUser ? "signUp" : "signIn"
        });
        if (token === null) {
          cookies.push(...sessionStore.clean());
        } else {
          const salt = options2.cookies.sessionToken.name;
          const newToken = await jwt2.encode({ ...jwt2, token, salt });
          const cookieExpires = /* @__PURE__ */ new Date();
          cookieExpires.setTime(cookieExpires.getTime() + sessionMaxAge * 1e3);
          const sessionCookies = sessionStore.chunk(newToken, {
            expires: cookieExpires
          });
          cookies.push(...sessionCookies);
        }
      } else {
        cookies.push({
          name: options2.cookies.sessionToken.name,
          value: session2.sessionToken,
          options: {
            ...options2.cookies.sessionToken.options,
            expires: session2.expires
          }
        });
      }
      await events.signIn?.({ user: loggedInUser, account: currentAccount, isNewUser });
      if (isNewUser && pages.newUser) {
        return {
          redirect: `${pages.newUser}${pages.newUser.includes("?") ? "&" : "?"}${new URLSearchParams({ callbackUrl })}`,
          cookies
        };
      }
      return { redirect: callbackUrl, cookies };
    }
    throw new InvalidProvider(`Callback for provider type (${provider.type}) is not supported`);
  } catch (e2) {
    if (e2 instanceof AuthError)
      throw e2;
    const error = new CallbackRouteError(e2, { provider: provider.id });
    logger2.debug("callback route error details", { method, query, body: body2 });
    throw error;
  }
}
async function handleAuthorized(params, config4) {
  let authorized;
  const { signIn: signIn3, redirect: redirect2 } = config4.callbacks;
  try {
    authorized = await signIn3(params);
  } catch (e2) {
    if (e2 instanceof AuthError)
      throw e2;
    throw new AccessDenied(e2);
  }
  if (!authorized)
    throw new AccessDenied("AccessDenied");
  if (typeof authorized !== "string")
    return;
  return await redirect2({ url: authorized, baseUrl: config4.url.origin });
}
var init_callback2 = __esm({
  "node_modules/@auth/core/lib/actions/callback/index.js"() {
    init_errors();
    init_handle_login();
    init_callback();
    init_checks();
    init_web2();
    init_webauthn_utils();
  }
});

// node_modules/@auth/core/lib/actions/session.js
async function session(options2, sessionStore, cookies, isUpdate, newSession) {
  const { adapter, jwt: jwt2, events, callbacks, logger: logger2, session: { strategy: sessionStrategy, maxAge: sessionMaxAge } } = options2;
  const response = {
    body: null,
    headers: { "Content-Type": "application/json" },
    cookies
  };
  const sessionToken = sessionStore.value;
  if (!sessionToken)
    return response;
  if (sessionStrategy === "jwt") {
    try {
      const salt = options2.cookies.sessionToken.name;
      const payload = await jwt2.decode({ ...jwt2, token: sessionToken, salt });
      if (!payload)
        throw new Error("Invalid JWT");
      const token = await callbacks.jwt({
        token: payload,
        ...isUpdate && { trigger: "update" },
        session: newSession
      });
      const newExpires = fromDate(sessionMaxAge);
      if (token !== null) {
        const session2 = {
          user: { name: token.name, email: token.email, image: token.picture },
          expires: newExpires.toISOString()
        };
        const newSession2 = await callbacks.session({ session: session2, token });
        response.body = newSession2;
        const newToken = await jwt2.encode({ ...jwt2, token, salt });
        const sessionCookies = sessionStore.chunk(newToken, {
          expires: newExpires
        });
        response.cookies?.push(...sessionCookies);
        await events.session?.({ session: newSession2, token });
      } else {
        response.cookies?.push(...sessionStore.clean());
      }
    } catch (e2) {
      logger2.error(new JWTSessionError(e2));
      response.cookies?.push(...sessionStore.clean());
    }
    return response;
  }
  try {
    const { getSessionAndUser, deleteSession, updateSession } = adapter;
    let userAndSession = await getSessionAndUser(sessionToken);
    if (userAndSession && userAndSession.session.expires.valueOf() < Date.now()) {
      await deleteSession(sessionToken);
      userAndSession = null;
    }
    if (userAndSession) {
      const { user, session: session2 } = userAndSession;
      const sessionUpdateAge = options2.session.updateAge;
      const sessionIsDueToBeUpdatedDate = session2.expires.valueOf() - sessionMaxAge * 1e3 + sessionUpdateAge * 1e3;
      const newExpires = fromDate(sessionMaxAge);
      if (sessionIsDueToBeUpdatedDate <= Date.now()) {
        await updateSession({
          sessionToken,
          expires: newExpires
        });
      }
      const sessionPayload = await callbacks.session({
        // TODO: user already passed below,
        // remove from session object in https://github.com/nextauthjs/next-auth/pull/9702
        // @ts-expect-error
        session: { ...session2, user },
        user,
        newSession,
        ...isUpdate ? { trigger: "update" } : {}
      });
      response.body = sessionPayload;
      response.cookies?.push({
        name: options2.cookies.sessionToken.name,
        value: sessionToken,
        options: {
          ...options2.cookies.sessionToken.options,
          expires: newExpires
        }
      });
      await events.session?.({ session: sessionPayload });
    } else if (sessionToken) {
      response.cookies?.push(...sessionStore.clean());
    }
  } catch (e2) {
    logger2.error(new SessionTokenError(e2));
  }
  return response;
}
var init_session = __esm({
  "node_modules/@auth/core/lib/actions/session.js"() {
    init_errors();
    init_date();
  }
});

// node_modules/@auth/core/lib/actions/signin/authorization-url.js
async function getAuthorizationUrl(query, options2) {
  const { logger: logger2, provider } = options2;
  let url = provider.authorization?.url;
  let as;
  if (!url || url.host === "authjs.dev") {
    const issuer = new URL(provider.issuer);
    const discoveryResponse = await discoveryRequest(issuer);
    const as2 = await processDiscoveryResponse(issuer, discoveryResponse);
    if (!as2.authorization_endpoint) {
      throw new TypeError("Authorization server did not provide an authorization endpoint.");
    }
    url = new URL(as2.authorization_endpoint);
  }
  const authParams = url.searchParams;
  let redirect_uri = provider.callbackUrl;
  let data;
  if (!options2.isOnRedirectProxy && provider.redirectProxyUrl) {
    redirect_uri = provider.redirectProxyUrl;
    data = { origin: provider.callbackUrl };
    logger2.debug("using redirect proxy", { redirect_uri, data });
  }
  const params = Object.assign({
    response_type: "code",
    // clientId can technically be undefined, should we check this in assert.ts or rely on the Authorization Server to do it?
    client_id: provider.clientId,
    redirect_uri,
    // @ts-expect-error TODO:
    ...provider.authorization?.params
  }, Object.fromEntries(provider.authorization?.url.searchParams ?? []), query);
  for (const k3 in params)
    authParams.set(k3, params[k3]);
  const cookies = [];
  const state2 = await state.create(options2, data);
  if (state2) {
    authParams.set("state", state2.value);
    cookies.push(state2.cookie);
  }
  if (provider.checks?.includes("pkce")) {
    if (as && !as.code_challenge_methods_supported?.includes("S256")) {
      if (provider.type === "oidc")
        provider.checks = ["nonce"];
    } else {
      const { value, cookie } = await pkce.create(options2);
      authParams.set("code_challenge", value);
      authParams.set("code_challenge_method", "S256");
      cookies.push(cookie);
    }
  }
  const nonce2 = await nonce.create(options2);
  if (nonce2) {
    authParams.set("nonce", nonce2.value);
    cookies.push(nonce2.cookie);
  }
  if (provider.type === "oidc" && !url.searchParams.has("scope")) {
    url.searchParams.set("scope", "openid profile email");
  }
  logger2.debug("authorization url is ready", { url, cookies, provider });
  return { redirect: url.toString(), cookies };
}
var init_authorization_url = __esm({
  "node_modules/@auth/core/lib/actions/signin/authorization-url.js"() {
    init_checks();
    init_build();
  }
});

// node_modules/@auth/core/lib/actions/signin/send-token.js
async function sendToken(request, options2) {
  const { body: body2 } = request;
  const { provider, callbacks, adapter } = options2;
  const normalizer = provider.normalizeIdentifier ?? defaultNormalizer;
  const email = normalizer(body2?.email);
  const defaultUser = { id: crypto.randomUUID(), email, emailVerified: null };
  const user = await adapter.getUserByEmail(email) ?? defaultUser;
  const account = {
    providerAccountId: email,
    userId: user.id,
    type: "email",
    provider: provider.id
  };
  let authorized;
  try {
    authorized = await callbacks.signIn({
      user,
      account,
      email: { verificationRequest: true }
    });
  } catch (e2) {
    throw new AccessDenied(e2);
  }
  if (!authorized)
    throw new AccessDenied("AccessDenied");
  if (typeof authorized === "string") {
    return {
      redirect: await callbacks.redirect({
        url: authorized,
        baseUrl: options2.url.origin
      })
    };
  }
  const { callbackUrl, theme } = options2;
  const token = await provider.generateVerificationToken?.() ?? randomString(32);
  const ONE_DAY_IN_SECONDS = 86400;
  const expires = new Date(Date.now() + (provider.maxAge ?? ONE_DAY_IN_SECONDS) * 1e3);
  const secret = provider.secret ?? options2.secret;
  const baseUrl = new URL(options2.basePath, options2.url.origin);
  const sendRequest = provider.sendVerificationRequest({
    identifier: email,
    token,
    expires,
    url: `${baseUrl}/callback/${provider.id}?${new URLSearchParams({
      callbackUrl,
      token,
      email
    })}`,
    provider,
    theme,
    request: toRequest(request)
  });
  const createToken = adapter.createVerificationToken?.({
    identifier: email,
    token: await createHash(`${token}${secret}`),
    expires
  });
  await Promise.all([sendRequest, createToken]);
  return {
    redirect: `${baseUrl}/verify-request?${new URLSearchParams({
      provider: provider.id,
      type: provider.type
    })}`
  };
}
function defaultNormalizer(email) {
  if (!email)
    throw new Error("Missing email from request body.");
  let [local, domain] = email.toLowerCase().trim().split("@");
  domain = domain.split(",")[0];
  return `${local}@${domain}`;
}
var init_send_token = __esm({
  "node_modules/@auth/core/lib/actions/signin/send-token.js"() {
    init_web2();
    init_errors();
  }
});

// node_modules/@auth/core/lib/actions/signin/index.js
async function signIn(request, cookies, options2) {
  const signInUrl = `${options2.url.origin}${options2.basePath}/signin`;
  if (!options2.provider)
    return { redirect: signInUrl, cookies };
  switch (options2.provider.type) {
    case "oauth":
    case "oidc": {
      const { redirect: redirect2, cookies: authCookies } = await getAuthorizationUrl(request.query, options2);
      if (authCookies)
        cookies.push(...authCookies);
      return { redirect: redirect2, cookies };
    }
    case "email": {
      const response = await sendToken(request, options2);
      return { ...response, cookies };
    }
    default:
      return { redirect: signInUrl, cookies };
  }
}
var init_signin2 = __esm({
  "node_modules/@auth/core/lib/actions/signin/index.js"() {
    init_authorization_url();
    init_send_token();
  }
});

// node_modules/@auth/core/lib/actions/signout.js
async function signOut(cookies, sessionStore, options2) {
  const { jwt: jwt2, events, callbackUrl: redirect2, logger: logger2, session: session2 } = options2;
  const sessionToken = sessionStore.value;
  if (!sessionToken)
    return { redirect: redirect2, cookies };
  try {
    if (session2.strategy === "jwt") {
      const salt = options2.cookies.sessionToken.name;
      const token = await jwt2.decode({ ...jwt2, token: sessionToken, salt });
      await events.signOut?.({ token });
    } else {
      const session3 = await options2.adapter?.deleteSession(sessionToken);
      await events.signOut?.({ session: session3 });
    }
  } catch (e2) {
    logger2.error(new SignOutError(e2));
  }
  cookies.push(...sessionStore.clean());
  return { redirect: redirect2, cookies };
}
var init_signout2 = __esm({
  "node_modules/@auth/core/lib/actions/signout.js"() {
    init_errors();
  }
});

// node_modules/@auth/core/lib/utils/session.js
async function getLoggedInUser(options2, sessionStore) {
  const { adapter, jwt: jwt2, session: { strategy: sessionStrategy } } = options2;
  const sessionToken = sessionStore.value;
  if (!sessionToken)
    return null;
  if (sessionStrategy === "jwt") {
    const salt = options2.cookies.sessionToken.name;
    const payload = await jwt2.decode({ ...jwt2, token: sessionToken, salt });
    if (payload && payload.sub) {
      return {
        id: payload.sub,
        name: payload.name,
        email: payload.email,
        image: payload.picture
      };
    }
  } else {
    const userAndSession = await adapter?.getSessionAndUser(sessionToken);
    if (userAndSession) {
      return userAndSession.user;
    }
  }
  return null;
}
var init_session2 = __esm({
  "node_modules/@auth/core/lib/utils/session.js"() {
  }
});

// node_modules/@auth/core/lib/actions/webauthn-options.js
async function webAuthnOptions(request, options2, sessionStore, cookies) {
  const narrowOptions = assertInternalOptionsWebAuthn(options2);
  const { provider } = narrowOptions;
  const { action } = request.query ?? {};
  if (action !== "register" && action !== "authenticate" && typeof action !== "undefined") {
    return {
      status: 400,
      body: { error: "Invalid action" },
      cookies,
      headers: {
        "Content-Type": "application/json"
      }
    };
  }
  const sessionUser = await getLoggedInUser(options2, sessionStore);
  const getUserInfoResponse = sessionUser ? {
    user: sessionUser,
    exists: true
  } : await provider.getUserInfo(options2, request);
  const userInfo = getUserInfoResponse?.user;
  const decision = inferWebAuthnOptions(action, !!sessionUser, getUserInfoResponse);
  switch (decision) {
    case "authenticate":
      return getAuthenticationResponse(narrowOptions, request, userInfo, cookies);
    case "register":
      if (typeof userInfo?.email === "string") {
        return getRegistrationResponse(narrowOptions, request, userInfo, cookies);
      }
    default:
      return {
        status: 400,
        body: { error: "Invalid request" },
        cookies,
        headers: {
          "Content-Type": "application/json"
        }
      };
  }
}
var init_webauthn_options = __esm({
  "node_modules/@auth/core/lib/actions/webauthn-options.js"() {
    init_session2();
    init_webauthn_utils();
  }
});

// node_modules/@auth/core/lib/actions/index.js
var init_actions2 = __esm({
  "node_modules/@auth/core/lib/actions/index.js"() {
    init_callback2();
    init_session();
    init_signin2();
    init_signout2();
    init_webauthn_options();
  }
});

// node_modules/@auth/core/lib/index.js
async function AuthInternal(request, authOptions) {
  const { action, providerId, error, method } = request;
  const csrfDisabled = authOptions.skipCSRFCheck === skipCSRFCheck;
  const { options: options2, cookies } = await init({
    authOptions,
    action,
    providerId,
    url: request.url,
    callbackUrl: request.body?.callbackUrl ?? request.query?.callbackUrl,
    csrfToken: request.body?.csrfToken,
    cookies: request.cookies,
    isPost: method === "POST",
    csrfDisabled
  });
  const sessionStore = new SessionStore(options2.cookies.sessionToken, request.cookies, options2.logger);
  if (method === "GET") {
    const render = renderPage({ ...options2, query: request.query, cookies });
    switch (action) {
      case "callback":
        return await callback(request, options2, sessionStore, cookies);
      case "csrf":
        return render.csrf(csrfDisabled, options2, cookies);
      case "error":
        return render.error(error);
      case "providers":
        return render.providers(options2.providers);
      case "session":
        return await session(options2, sessionStore, cookies);
      case "signin":
        return render.signin(providerId, error);
      case "signout":
        return render.signout();
      case "verify-request":
        return render.verifyRequest();
      case "webauthn-options":
        return await webAuthnOptions(request, options2, sessionStore, cookies);
      default:
    }
  } else {
    const { csrfTokenVerified } = options2;
    switch (action) {
      case "callback":
        if (options2.provider.type === "credentials")
          validateCSRF(action, csrfTokenVerified);
        return await callback(request, options2, sessionStore, cookies);
      case "session":
        validateCSRF(action, csrfTokenVerified);
        return await session(options2, sessionStore, cookies, true, request.body?.data);
      case "signin":
        validateCSRF(action, csrfTokenVerified);
        return await signIn(request, cookies, options2);
      case "signout":
        validateCSRF(action, csrfTokenVerified);
        return await signOut(cookies, sessionStore, options2);
      default:
    }
  }
  throw new UnknownAction(`Cannot handle action: ${action}`);
}
var skipCSRFCheck, raw2;
var init_lib = __esm({
  "node_modules/@auth/core/lib/index.js"() {
    init_errors();
    init_cookie();
    init_init();
    init_pages();
    init_actions2();
    init_csrf_token();
    skipCSRFCheck = Symbol("skip-csrf-check");
    raw2 = Symbol("return-type-raw");
  }
});

// node_modules/@auth/core/lib/utils/env.js
function setEnvDefaults(envObject, config4) {
  try {
    const url = envObject.AUTH_URL;
    if (url && !config4.basePath)
      config4.basePath = new URL(url).pathname;
  } catch {
  } finally {
    config4.basePath ?? (config4.basePath = `/auth`);
  }
  if (!config4.secret?.length) {
    config4.secret = [];
    const secret = envObject.AUTH_SECRET;
    if (secret)
      config4.secret.push(secret);
    for (const i3 of [1, 2, 3]) {
      const secret2 = envObject[`AUTH_SECRET_${i3}`];
      if (secret2)
        config4.secret.unshift(secret2);
    }
  }
  config4.redirectProxyUrl ?? (config4.redirectProxyUrl = envObject.AUTH_REDIRECT_PROXY_URL);
  config4.trustHost ?? (config4.trustHost = !!(envObject.AUTH_URL ?? envObject.AUTH_TRUST_HOST ?? envObject.VERCEL ?? envObject.CF_PAGES ?? envObject.NODE_ENV !== "production"));
  config4.providers = config4.providers.map((p3) => {
    const finalProvider = typeof p3 === "function" ? p3({}) : p3;
    const ID = finalProvider.id.toUpperCase();
    if (finalProvider.type === "oauth" || finalProvider.type === "oidc") {
      finalProvider.clientId ?? (finalProvider.clientId = envObject[`AUTH_${ID}_ID`]);
      finalProvider.clientSecret ?? (finalProvider.clientSecret = envObject[`AUTH_${ID}_SECRET`]);
      if (finalProvider.type === "oidc") {
        finalProvider.issuer ?? (finalProvider.issuer = envObject[`AUTH_${ID}_ISSUER`]);
      }
    } else if (finalProvider.type === "email") {
      finalProvider.apiKey ?? (finalProvider.apiKey = envObject[`AUTH_${ID}_KEY`]);
    }
    return finalProvider;
  });
}
var init_env = __esm({
  "node_modules/@auth/core/lib/utils/env.js"() {
  }
});

// node_modules/@auth/core/index.js
async function Auth(request, config4) {
  setLogger(config4.logger, config4.debug);
  const internalRequest = await toInternalRequest(request, config4);
  if (!internalRequest)
    return Response.json(`Bad request.`, { status: 400 });
  const warningsOrError = assertConfig(internalRequest, config4);
  if (Array.isArray(warningsOrError)) {
    warningsOrError.forEach(logger.warn);
  } else if (warningsOrError) {
    logger.error(warningsOrError);
    const htmlPages = /* @__PURE__ */ new Set([
      "signin",
      "signout",
      "error",
      "verify-request"
    ]);
    if (!htmlPages.has(internalRequest.action) || internalRequest.method !== "GET") {
      const message2 = "There was a problem with the server configuration. Check the server logs for more information.";
      return Response.json({ message: message2 }, { status: 500 });
    }
    const { pages, theme } = config4;
    const authOnErrorPage = pages?.error && internalRequest.url.searchParams.get("callbackUrl")?.startsWith(pages.error);
    if (!pages?.error || authOnErrorPage) {
      if (authOnErrorPage) {
        logger.error(new ErrorPageLoop(`The error page ${pages?.error} should not require authentication`));
      }
      const page2 = renderPage({ theme }).error("Configuration");
      return toResponse(page2);
    }
    return Response.redirect(`${pages.error}?error=Configuration`);
  }
  const isRedirect = request.headers?.has("X-Auth-Return-Redirect");
  const isRaw = config4.raw === raw2;
  try {
    const internalResponse = await AuthInternal(internalRequest, config4);
    if (isRaw)
      return internalResponse;
    const response = toResponse(internalResponse);
    const url = response.headers.get("Location");
    if (!isRedirect || !url)
      return response;
    return Response.json({ url }, { headers: response.headers });
  } catch (e2) {
    const error = e2;
    logger.error(error);
    const isAuthError = error instanceof AuthError;
    if (isAuthError && isRaw && !isRedirect)
      throw error;
    if (request.method === "POST" && internalRequest.action === "session")
      return Response.json(null, { status: 400 });
    const isClientSafeErrorType = isClientError(error);
    const type = isClientSafeErrorType ? error.type : "Configuration";
    const params = new URLSearchParams({ error: type });
    if (error instanceof CredentialsSignin)
      params.set("code", error.code);
    const pageKind = isAuthError && error.kind || "error";
    const pagePath = config4.pages?.[pageKind] ?? `/${pageKind.toLowerCase()}`;
    const url = `${internalRequest.url.origin}${config4.basePath}${pagePath}?${params}`;
    if (isRedirect)
      return Response.json({ url });
    return Response.redirect(url);
  }
}
var init_core = __esm({
  "node_modules/@auth/core/index.js"() {
    init_assert();
    init_errors();
    init_lib();
    init_env();
    init_pages();
    init_logger();
    init_web2();
    init_actions();
  }
});

// .svelte-kit/output/server/chunks/index.js
function redirect(status, location) {
  if (isNaN(status) || status < 300 || status > 308) {
    throw new Error("Invalid status code");
  }
  throw new Redirect(
    // @ts-ignore
    status,
    location.toString()
  );
}
function json(data, init3) {
  const body2 = JSON.stringify(data);
  const headers2 = new Headers(init3?.headers);
  if (!headers2.has("content-length")) {
    headers2.set("content-length", encoder3.encode(body2).byteLength.toString());
  }
  if (!headers2.has("content-type")) {
    headers2.set("content-type", "application/json");
  }
  return new Response(body2, {
    ...init3,
    headers: headers2
  });
}
function text(body2, init3) {
  const headers2 = new Headers(init3?.headers);
  if (!headers2.has("content-length")) {
    const encoded = encoder3.encode(body2);
    headers2.set("content-length", encoded.byteLength.toString());
    return new Response(encoded, {
      ...init3,
      headers: headers2
    });
  }
  return new Response(body2, {
    ...init3,
    headers: headers2
  });
}
function fail(status, data) {
  return new ActionFailure(status, data);
}
var HttpError, Redirect, SvelteKitError, ActionFailure, encoder3;
var init_chunks = __esm({
  ".svelte-kit/output/server/chunks/index.js"() {
    HttpError = class {
      /**
       * @param {number} status
       * @param {{message: string} extends App.Error ? (App.Error | string | undefined) : App.Error} body
       */
      constructor(status, body2) {
        this.status = status;
        if (typeof body2 === "string") {
          this.body = { message: body2 };
        } else if (body2) {
          this.body = body2;
        } else {
          this.body = { message: `Error: ${status}` };
        }
      }
      toString() {
        return JSON.stringify(this.body);
      }
    };
    Redirect = class {
      /**
       * @param {300 | 301 | 302 | 303 | 304 | 305 | 306 | 307 | 308} status
       * @param {string} location
       */
      constructor(status, location) {
        this.status = status;
        this.location = location;
      }
    };
    SvelteKitError = class extends Error {
      /**
       * @param {number} status
       * @param {string} text
       * @param {string} message
       */
      constructor(status, text2, message2) {
        super(message2);
        this.status = status;
        this.text = text2;
      }
    };
    ActionFailure = class {
      /**
       * @param {number} status
       * @param {T} data
       */
      constructor(status, data) {
        this.status = status;
        this.data = data;
      }
    };
    encoder3 = new TextEncoder();
  }
});

// node_modules/set-cookie-parser/lib/set-cookie.js
var require_set_cookie = __commonJS({
  "node_modules/set-cookie-parser/lib/set-cookie.js"(exports, module) {
    "use strict";
    var defaultParseOptions = {
      decodeValues: true,
      map: false,
      silent: false
    };
    function isNonEmptyString(str) {
      return typeof str === "string" && !!str.trim();
    }
    function parseString2(setCookieValue, options2) {
      var parts = setCookieValue.split(";").filter(isNonEmptyString);
      var nameValuePairStr = parts.shift();
      var parsed = parseNameValuePair(nameValuePairStr);
      var name = parsed.name;
      var value = parsed.value;
      options2 = options2 ? Object.assign({}, defaultParseOptions, options2) : defaultParseOptions;
      try {
        value = options2.decodeValues ? decodeURIComponent(value) : value;
      } catch (e2) {
        console.error(
          "set-cookie-parser encountered an error while decoding a cookie with value '" + value + "'. Set options.decodeValues to false to disable this feature.",
          e2
        );
      }
      var cookie = {
        name,
        value
      };
      parts.forEach(function(part) {
        var sides = part.split("=");
        var key2 = sides.shift().trimLeft().toLowerCase();
        var value2 = sides.join("=");
        if (key2 === "expires") {
          cookie.expires = new Date(value2);
        } else if (key2 === "max-age") {
          cookie.maxAge = parseInt(value2, 10);
        } else if (key2 === "secure") {
          cookie.secure = true;
        } else if (key2 === "httponly") {
          cookie.httpOnly = true;
        } else if (key2 === "samesite") {
          cookie.sameSite = value2;
        } else {
          cookie[key2] = value2;
        }
      });
      return cookie;
    }
    function parseNameValuePair(nameValuePairStr) {
      var name = "";
      var value = "";
      var nameValueArr = nameValuePairStr.split("=");
      if (nameValueArr.length > 1) {
        name = nameValueArr.shift();
        value = nameValueArr.join("=");
      } else {
        value = nameValuePairStr;
      }
      return { name, value };
    }
    function parse6(input, options2) {
      options2 = options2 ? Object.assign({}, defaultParseOptions, options2) : defaultParseOptions;
      if (!input) {
        if (!options2.map) {
          return [];
        } else {
          return {};
        }
      }
      if (input.headers) {
        if (typeof input.headers.getSetCookie === "function") {
          input = input.headers.getSetCookie();
        } else if (input.headers["set-cookie"]) {
          input = input.headers["set-cookie"];
        } else {
          var sch = input.headers[Object.keys(input.headers).find(function(key2) {
            return key2.toLowerCase() === "set-cookie";
          })];
          if (!sch && input.headers.cookie && !options2.silent) {
            console.warn(
              "Warning: set-cookie-parser appears to have been called on a request object. It is designed to parse Set-Cookie headers from responses, not Cookie headers from requests. Set the option {silent: true} to suppress this warning."
            );
          }
          input = sch;
        }
      }
      if (!Array.isArray(input)) {
        input = [input];
      }
      options2 = options2 ? Object.assign({}, defaultParseOptions, options2) : defaultParseOptions;
      if (!options2.map) {
        return input.filter(isNonEmptyString).map(function(str) {
          return parseString2(str, options2);
        });
      } else {
        var cookies = {};
        return input.filter(isNonEmptyString).reduce(function(cookies2, str) {
          var cookie = parseString2(str, options2);
          cookies2[cookie.name] = cookie;
          return cookies2;
        }, cookies);
      }
    }
    function splitCookiesString2(cookiesString) {
      if (Array.isArray(cookiesString)) {
        return cookiesString;
      }
      if (typeof cookiesString !== "string") {
        return [];
      }
      var cookiesStrings = [];
      var pos = 0;
      var start;
      var ch;
      var lastComma;
      var nextStart;
      var cookiesSeparatorFound;
      function skipWhitespace() {
        while (pos < cookiesString.length && /\s/.test(cookiesString.charAt(pos))) {
          pos += 1;
        }
        return pos < cookiesString.length;
      }
      function notSpecialChar() {
        ch = cookiesString.charAt(pos);
        return ch !== "=" && ch !== ";" && ch !== ",";
      }
      while (pos < cookiesString.length) {
        start = pos;
        cookiesSeparatorFound = false;
        while (skipWhitespace()) {
          ch = cookiesString.charAt(pos);
          if (ch === ",") {
            lastComma = pos;
            pos += 1;
            skipWhitespace();
            nextStart = pos;
            while (pos < cookiesString.length && notSpecialChar()) {
              pos += 1;
            }
            if (pos < cookiesString.length && cookiesString.charAt(pos) === "=") {
              cookiesSeparatorFound = true;
              pos = nextStart;
              cookiesStrings.push(cookiesString.substring(start, lastComma));
              start = pos;
            } else {
              pos = lastComma + 1;
            }
          } else {
            pos += 1;
          }
        }
        if (!cookiesSeparatorFound || pos >= cookiesString.length) {
          cookiesStrings.push(cookiesString.substring(start, cookiesString.length));
        }
      }
      return cookiesStrings;
    }
    module.exports = parse6;
    module.exports.parse = parse6;
    module.exports.parseString = parseString2;
    module.exports.splitCookiesString = splitCookiesString2;
  }
});

// node_modules/@auth/core/providers/github.js
function GitHub(config4) {
  const baseUrl = config4?.enterprise?.baseUrl ?? "https://github.com";
  const apiBaseUrl = config4?.enterprise?.baseUrl ? `${config4?.enterprise?.baseUrl}/api/v3` : "https://api.github.com";
  return {
    id: "github",
    name: "GitHub",
    type: "oauth",
    authorization: {
      url: `${baseUrl}/login/oauth/authorize`,
      params: { scope: "read:user user:email" }
    },
    token: `${baseUrl}/login/oauth/access_token`,
    userinfo: {
      url: `${apiBaseUrl}/user`,
      async request({ tokens, provider }) {
        const profile = await fetch(provider.userinfo?.url, {
          headers: {
            Authorization: `Bearer ${tokens.access_token}`,
            "User-Agent": "authjs"
          }
        }).then(async (res) => await res.json());
        if (!profile.email) {
          const res = await fetch(`${apiBaseUrl}/user/emails`, {
            headers: {
              Authorization: `Bearer ${tokens.access_token}`,
              "User-Agent": "authjs"
            }
          });
          if (res.ok) {
            const emails = await res.json();
            profile.email = (emails.find((e2) => e2.primary) ?? emails[0]).email;
          }
        }
        return profile;
      }
    },
    profile(profile) {
      return {
        id: profile.id.toString(),
        name: profile.name ?? profile.login,
        email: profile.email,
        image: profile.avatar_url
      };
    },
    style: { logo: "/github.svg", bg: "#24292f", text: "#fff" },
    options: config4
  };
}
var init_github = __esm({
  "node_modules/@auth/core/providers/github.js"() {
  }
});

// node_modules/@auth/prisma-adapter/index.js
function PrismaAdapter(prisma2) {
  const p3 = prisma2;
  return {
    // We need to let Prisma generate the ID because our default UUID is incompatible with MongoDB
    createUser: ({ id: _id, ...data }) => {
      return p3.user.create({ data });
    },
    getUser: (id) => p3.user.findUnique({ where: { id } }),
    getUserByEmail: (email) => p3.user.findUnique({ where: { email } }),
    async getUserByAccount(provider_providerAccountId) {
      const account = await p3.account.findUnique({
        where: { provider_providerAccountId },
        select: { user: true }
      });
      return account?.user ?? null;
    },
    updateUser: ({ id, ...data }) => p3.user.update({ where: { id }, data }),
    deleteUser: (id) => p3.user.delete({ where: { id } }),
    linkAccount: (data) => p3.account.create({ data }),
    unlinkAccount: (provider_providerAccountId) => p3.account.delete({
      where: { provider_providerAccountId }
    }),
    async getSessionAndUser(sessionToken) {
      const userAndSession = await p3.session.findUnique({
        where: { sessionToken },
        include: { user: true }
      });
      if (!userAndSession)
        return null;
      const { user, ...session2 } = userAndSession;
      return { user, session: session2 };
    },
    createSession: (data) => p3.session.create({ data }),
    updateSession: (data) => p3.session.update({ where: { sessionToken: data.sessionToken }, data }),
    deleteSession: (sessionToken) => p3.session.delete({ where: { sessionToken } }),
    async createVerificationToken(data) {
      const verificationToken = await p3.verificationToken.create({ data });
      if (verificationToken.id)
        delete verificationToken.id;
      return verificationToken;
    },
    async useVerificationToken(identifier_token) {
      try {
        const verificationToken = await p3.verificationToken.delete({
          where: { identifier_token }
        });
        if (verificationToken.id)
          delete verificationToken.id;
        return verificationToken;
      } catch (error) {
        if (error.code === "P2025")
          return null;
        throw error;
      }
    },
    async getAccount(providerAccountId, provider) {
      return p3.account.findFirst({
        where: { providerAccountId, provider }
      });
    },
    async createAuthenticator(authenticator) {
      return p3.authenticator.create({
        data: authenticator
      }).then(fromDBAuthenticator);
    },
    async getAuthenticator(credentialID) {
      const authenticator = await p3.authenticator.findUnique({
        where: { credentialID }
      });
      return authenticator ? fromDBAuthenticator(authenticator) : null;
    },
    async listAuthenticatorsByUserId(userId) {
      const authenticators = await p3.authenticator.findMany({
        where: { userId }
      });
      return authenticators.map(fromDBAuthenticator);
    },
    async updateAuthenticatorCounter(credentialID, counter) {
      return p3.authenticator.update({
        where: { credentialID },
        data: { counter }
      }).then(fromDBAuthenticator);
    }
  };
}
function fromDBAuthenticator(authenticator) {
  const { transports, id, user, ...other } = authenticator;
  return {
    ...other,
    transports: transports || void 0
  };
}
var init_prisma_adapter = __esm({
  "node_modules/@auth/prisma-adapter/index.js"() {
  }
});

// node_modules/@prisma/client/runtime/edge.js
var require_edge = __commonJS({
  "node_modules/@prisma/client/runtime/edge.js"(exports, module) {
    "use strict";
    var ua = Object.create;
    var ir = Object.defineProperty;
    var la = Object.getOwnPropertyDescriptor;
    var ca = Object.getOwnPropertyNames;
    var pa = Object.getPrototypeOf;
    var fa = Object.prototype.hasOwnProperty;
    var be = (e2, t2) => () => (e2 && (t2 = e2(e2 = 0)), t2);
    var Ie = (e2, t2) => () => (t2 || e2((t2 = { exports: {} }).exports, t2), t2.exports);
    var vt = (e2, t2) => {
      for (var r3 in t2)
        ir(e2, r3, { get: t2[r3], enumerable: true });
    };
    var zn = (e2, t2, r3, n3) => {
      if (t2 && typeof t2 == "object" || typeof t2 == "function")
        for (let i3 of ca(t2))
          !fa.call(e2, i3) && i3 !== r3 && ir(e2, i3, { get: () => t2[i3], enumerable: !(n3 = la(t2, i3)) || n3.enumerable });
      return e2;
    };
    var Ve = (e2, t2, r3) => (r3 = e2 != null ? ua(pa(e2)) : {}, zn(t2 || !e2 || !e2.__esModule ? ir(r3, "default", { value: e2, enumerable: true }) : r3, e2));
    var Gr = (e2) => zn(ir({}, "__esModule", { value: true }), e2);
    var y2;
    var c3 = be(() => {
      "use strict";
      y2 = { nextTick: (e2, ...t2) => {
        setTimeout(() => {
          e2(...t2);
        }, 0);
      }, env: {}, version: "", cwd: () => "/", stderr: {}, argv: ["/bin/node"] };
    });
    var Yn;
    var b3;
    var p3 = be(() => {
      "use strict";
      b3 = (Yn = globalThis.performance) != null ? Yn : (() => {
        let e2 = Date.now();
        return { now: () => Date.now() - e2 };
      })();
    });
    var E;
    var f3 = be(() => {
      "use strict";
      E = () => {
      };
      E.prototype = E;
    });
    var m3 = be(() => {
      "use strict";
    });
    var hi = Ie((nt) => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      var ri = (e2, t2) => () => (t2 || e2((t2 = { exports: {} }).exports, t2), t2.exports), ma = ri((e2) => {
        "use strict";
        e2.byteLength = u3, e2.toByteArray = g3, e2.fromByteArray = S2;
        var t2 = [], r3 = [], n3 = typeof Uint8Array < "u" ? Uint8Array : Array, i3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (o4 = 0, s4 = i3.length; o4 < s4; ++o4)
          t2[o4] = i3[o4], r3[i3.charCodeAt(o4)] = o4;
        var o4, s4;
        r3[45] = 62, r3[95] = 63;
        function a3(A2) {
          var R = A2.length;
          if (R % 4 > 0)
            throw new Error("Invalid string. Length must be a multiple of 4");
          var D = A2.indexOf("=");
          D === -1 && (D = R);
          var M2 = D === R ? 0 : 4 - D % 4;
          return [D, M2];
        }
        function u3(A2) {
          var R = a3(A2), D = R[0], M2 = R[1];
          return (D + M2) * 3 / 4 - M2;
        }
        function l3(A2, R, D) {
          return (R + D) * 3 / 4 - D;
        }
        function g3(A2) {
          var R, D = a3(A2), M2 = D[0], B = D[1], I2 = new n3(l3(A2, M2, B)), L2 = 0, ee = B > 0 ? M2 - 4 : M2, F;
          for (F = 0; F < ee; F += 4)
            R = r3[A2.charCodeAt(F)] << 18 | r3[A2.charCodeAt(F + 1)] << 12 | r3[A2.charCodeAt(F + 2)] << 6 | r3[A2.charCodeAt(F + 3)], I2[L2++] = R >> 16 & 255, I2[L2++] = R >> 8 & 255, I2[L2++] = R & 255;
          return B === 2 && (R = r3[A2.charCodeAt(F)] << 2 | r3[A2.charCodeAt(F + 1)] >> 4, I2[L2++] = R & 255), B === 1 && (R = r3[A2.charCodeAt(F)] << 10 | r3[A2.charCodeAt(F + 1)] << 4 | r3[A2.charCodeAt(F + 2)] >> 2, I2[L2++] = R >> 8 & 255, I2[L2++] = R & 255), I2;
        }
        function h2(A2) {
          return t2[A2 >> 18 & 63] + t2[A2 >> 12 & 63] + t2[A2 >> 6 & 63] + t2[A2 & 63];
        }
        function v3(A2, R, D) {
          for (var M2, B = [], I2 = R; I2 < D; I2 += 3)
            M2 = (A2[I2] << 16 & 16711680) + (A2[I2 + 1] << 8 & 65280) + (A2[I2 + 2] & 255), B.push(h2(M2));
          return B.join("");
        }
        function S2(A2) {
          for (var R, D = A2.length, M2 = D % 3, B = [], I2 = 16383, L2 = 0, ee = D - M2; L2 < ee; L2 += I2)
            B.push(v3(A2, L2, L2 + I2 > ee ? ee : L2 + I2));
          return M2 === 1 ? (R = A2[D - 1], B.push(t2[R >> 2] + t2[R << 4 & 63] + "==")) : M2 === 2 && (R = (A2[D - 2] << 8) + A2[D - 1], B.push(t2[R >> 10] + t2[R >> 4 & 63] + t2[R << 2 & 63] + "=")), B.join("");
        }
      }), da = ri((e2) => {
        e2.read = function(t2, r3, n3, i3, o4) {
          var s4, a3, u3 = o4 * 8 - i3 - 1, l3 = (1 << u3) - 1, g3 = l3 >> 1, h2 = -7, v3 = n3 ? o4 - 1 : 0, S2 = n3 ? -1 : 1, A2 = t2[r3 + v3];
          for (v3 += S2, s4 = A2 & (1 << -h2) - 1, A2 >>= -h2, h2 += u3; h2 > 0; s4 = s4 * 256 + t2[r3 + v3], v3 += S2, h2 -= 8)
            ;
          for (a3 = s4 & (1 << -h2) - 1, s4 >>= -h2, h2 += i3; h2 > 0; a3 = a3 * 256 + t2[r3 + v3], v3 += S2, h2 -= 8)
            ;
          if (s4 === 0)
            s4 = 1 - g3;
          else {
            if (s4 === l3)
              return a3 ? NaN : (A2 ? -1 : 1) * (1 / 0);
            a3 = a3 + Math.pow(2, i3), s4 = s4 - g3;
          }
          return (A2 ? -1 : 1) * a3 * Math.pow(2, s4 - i3);
        }, e2.write = function(t2, r3, n3, i3, o4, s4) {
          var a3, u3, l3, g3 = s4 * 8 - o4 - 1, h2 = (1 << g3) - 1, v3 = h2 >> 1, S2 = o4 === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0, A2 = i3 ? 0 : s4 - 1, R = i3 ? 1 : -1, D = r3 < 0 || r3 === 0 && 1 / r3 < 0 ? 1 : 0;
          for (r3 = Math.abs(r3), isNaN(r3) || r3 === 1 / 0 ? (u3 = isNaN(r3) ? 1 : 0, a3 = h2) : (a3 = Math.floor(Math.log(r3) / Math.LN2), r3 * (l3 = Math.pow(2, -a3)) < 1 && (a3--, l3 *= 2), a3 + v3 >= 1 ? r3 += S2 / l3 : r3 += S2 * Math.pow(2, 1 - v3), r3 * l3 >= 2 && (a3++, l3 /= 2), a3 + v3 >= h2 ? (u3 = 0, a3 = h2) : a3 + v3 >= 1 ? (u3 = (r3 * l3 - 1) * Math.pow(2, o4), a3 = a3 + v3) : (u3 = r3 * Math.pow(2, v3 - 1) * Math.pow(2, o4), a3 = 0)); o4 >= 8; t2[n3 + A2] = u3 & 255, A2 += R, u3 /= 256, o4 -= 8)
            ;
          for (a3 = a3 << o4 | u3, g3 += o4; g3 > 0; t2[n3 + A2] = a3 & 255, A2 += R, a3 /= 256, g3 -= 8)
            ;
          t2[n3 + A2 - R] |= D * 128;
        };
      }), Hr = ma(), tt = da(), Zn = typeof Symbol == "function" && typeof Symbol.for == "function" ? Symbol.for("nodejs.util.inspect.custom") : null;
      nt.Buffer = T2;
      nt.SlowBuffer = ba;
      nt.INSPECT_MAX_BYTES = 50;
      var or = 2147483647;
      nt.kMaxLength = or;
      T2.TYPED_ARRAY_SUPPORT = ga();
      !T2.TYPED_ARRAY_SUPPORT && typeof console < "u" && typeof console.error == "function" && console.error("This browser lacks typed array (Uint8Array) support which is required by `buffer` v5.x. Use `buffer` v4.x if you require old browser support.");
      function ga() {
        try {
          let e2 = new Uint8Array(1), t2 = { foo: function() {
            return 42;
          } };
          return Object.setPrototypeOf(t2, Uint8Array.prototype), Object.setPrototypeOf(e2, t2), e2.foo() === 42;
        } catch (e2) {
          return false;
        }
      }
      Object.defineProperty(T2.prototype, "parent", { enumerable: true, get: function() {
        if (T2.isBuffer(this))
          return this.buffer;
      } });
      Object.defineProperty(T2.prototype, "offset", { enumerable: true, get: function() {
        if (T2.isBuffer(this))
          return this.byteOffset;
      } });
      function xe(e2) {
        if (e2 > or)
          throw new RangeError('The value "' + e2 + '" is invalid for option "size"');
        let t2 = new Uint8Array(e2);
        return Object.setPrototypeOf(t2, T2.prototype), t2;
      }
      function T2(e2, t2, r3) {
        if (typeof e2 == "number") {
          if (typeof t2 == "string")
            throw new TypeError('The "string" argument must be of type string. Received type number');
          return zr(e2);
        }
        return ni(e2, t2, r3);
      }
      T2.poolSize = 8192;
      function ni(e2, t2, r3) {
        if (typeof e2 == "string")
          return ya(e2, t2);
        if (ArrayBuffer.isView(e2))
          return wa(e2);
        if (e2 == null)
          throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof e2);
        if (me(e2, ArrayBuffer) || e2 && me(e2.buffer, ArrayBuffer) || typeof SharedArrayBuffer < "u" && (me(e2, SharedArrayBuffer) || e2 && me(e2.buffer, SharedArrayBuffer)))
          return oi(e2, t2, r3);
        if (typeof e2 == "number")
          throw new TypeError('The "value" argument must not be of type number. Received type number');
        let n3 = e2.valueOf && e2.valueOf();
        if (n3 != null && n3 !== e2)
          return T2.from(n3, t2, r3);
        let i3 = Ea(e2);
        if (i3)
          return i3;
        if (typeof Symbol < "u" && Symbol.toPrimitive != null && typeof e2[Symbol.toPrimitive] == "function")
          return T2.from(e2[Symbol.toPrimitive]("string"), t2, r3);
        throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof e2);
      }
      T2.from = function(e2, t2, r3) {
        return ni(e2, t2, r3);
      };
      Object.setPrototypeOf(T2.prototype, Uint8Array.prototype);
      Object.setPrototypeOf(T2, Uint8Array);
      function ii(e2) {
        if (typeof e2 != "number")
          throw new TypeError('"size" argument must be of type number');
        if (e2 < 0)
          throw new RangeError('The value "' + e2 + '" is invalid for option "size"');
      }
      function ha(e2, t2, r3) {
        return ii(e2), e2 <= 0 ? xe(e2) : t2 !== void 0 ? typeof r3 == "string" ? xe(e2).fill(t2, r3) : xe(e2).fill(t2) : xe(e2);
      }
      T2.alloc = function(e2, t2, r3) {
        return ha(e2, t2, r3);
      };
      function zr(e2) {
        return ii(e2), xe(e2 < 0 ? 0 : Yr(e2) | 0);
      }
      T2.allocUnsafe = function(e2) {
        return zr(e2);
      };
      T2.allocUnsafeSlow = function(e2) {
        return zr(e2);
      };
      function ya(e2, t2) {
        if ((typeof t2 != "string" || t2 === "") && (t2 = "utf8"), !T2.isEncoding(t2))
          throw new TypeError("Unknown encoding: " + t2);
        let r3 = si(e2, t2) | 0, n3 = xe(r3), i3 = n3.write(e2, t2);
        return i3 !== r3 && (n3 = n3.slice(0, i3)), n3;
      }
      function Wr(e2) {
        let t2 = e2.length < 0 ? 0 : Yr(e2.length) | 0, r3 = xe(t2);
        for (let n3 = 0; n3 < t2; n3 += 1)
          r3[n3] = e2[n3] & 255;
        return r3;
      }
      function wa(e2) {
        if (me(e2, Uint8Array)) {
          let t2 = new Uint8Array(e2);
          return oi(t2.buffer, t2.byteOffset, t2.byteLength);
        }
        return Wr(e2);
      }
      function oi(e2, t2, r3) {
        if (t2 < 0 || e2.byteLength < t2)
          throw new RangeError('"offset" is outside of buffer bounds');
        if (e2.byteLength < t2 + (r3 || 0))
          throw new RangeError('"length" is outside of buffer bounds');
        let n3;
        return t2 === void 0 && r3 === void 0 ? n3 = new Uint8Array(e2) : r3 === void 0 ? n3 = new Uint8Array(e2, t2) : n3 = new Uint8Array(e2, t2, r3), Object.setPrototypeOf(n3, T2.prototype), n3;
      }
      function Ea(e2) {
        if (T2.isBuffer(e2)) {
          let t2 = Yr(e2.length) | 0, r3 = xe(t2);
          return r3.length === 0 || e2.copy(r3, 0, 0, t2), r3;
        }
        if (e2.length !== void 0)
          return typeof e2.length != "number" || Xr(e2.length) ? xe(0) : Wr(e2);
        if (e2.type === "Buffer" && Array.isArray(e2.data))
          return Wr(e2.data);
      }
      function Yr(e2) {
        if (e2 >= or)
          throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + or.toString(16) + " bytes");
        return e2 | 0;
      }
      function ba(e2) {
        return +e2 != e2 && (e2 = 0), T2.alloc(+e2);
      }
      T2.isBuffer = function(e2) {
        return e2 != null && e2._isBuffer === true && e2 !== T2.prototype;
      };
      T2.compare = function(e2, t2) {
        if (me(e2, Uint8Array) && (e2 = T2.from(e2, e2.offset, e2.byteLength)), me(t2, Uint8Array) && (t2 = T2.from(t2, t2.offset, t2.byteLength)), !T2.isBuffer(e2) || !T2.isBuffer(t2))
          throw new TypeError('The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array');
        if (e2 === t2)
          return 0;
        let r3 = e2.length, n3 = t2.length;
        for (let i3 = 0, o4 = Math.min(r3, n3); i3 < o4; ++i3)
          if (e2[i3] !== t2[i3]) {
            r3 = e2[i3], n3 = t2[i3];
            break;
          }
        return r3 < n3 ? -1 : n3 < r3 ? 1 : 0;
      };
      T2.isEncoding = function(e2) {
        switch (String(e2).toLowerCase()) {
          case "hex":
          case "utf8":
          case "utf-8":
          case "ascii":
          case "latin1":
          case "binary":
          case "base64":
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return true;
          default:
            return false;
        }
      };
      T2.concat = function(e2, t2) {
        if (!Array.isArray(e2))
          throw new TypeError('"list" argument must be an Array of Buffers');
        if (e2.length === 0)
          return T2.alloc(0);
        let r3;
        if (t2 === void 0)
          for (t2 = 0, r3 = 0; r3 < e2.length; ++r3)
            t2 += e2[r3].length;
        let n3 = T2.allocUnsafe(t2), i3 = 0;
        for (r3 = 0; r3 < e2.length; ++r3) {
          let o4 = e2[r3];
          if (me(o4, Uint8Array))
            i3 + o4.length > n3.length ? (T2.isBuffer(o4) || (o4 = T2.from(o4)), o4.copy(n3, i3)) : Uint8Array.prototype.set.call(n3, o4, i3);
          else if (T2.isBuffer(o4))
            o4.copy(n3, i3);
          else
            throw new TypeError('"list" argument must be an Array of Buffers');
          i3 += o4.length;
        }
        return n3;
      };
      function si(e2, t2) {
        if (T2.isBuffer(e2))
          return e2.length;
        if (ArrayBuffer.isView(e2) || me(e2, ArrayBuffer))
          return e2.byteLength;
        if (typeof e2 != "string")
          throw new TypeError('The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type ' + typeof e2);
        let r3 = e2.length, n3 = arguments.length > 2 && arguments[2] === true;
        if (!n3 && r3 === 0)
          return 0;
        let i3 = false;
        for (; ; )
          switch (t2) {
            case "ascii":
            case "latin1":
            case "binary":
              return r3;
            case "utf8":
            case "utf-8":
              return Kr(e2).length;
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return r3 * 2;
            case "hex":
              return r3 >>> 1;
            case "base64":
              return gi(e2).length;
            default:
              if (i3)
                return n3 ? -1 : Kr(e2).length;
              t2 = ("" + t2).toLowerCase(), i3 = true;
          }
      }
      T2.byteLength = si;
      function xa(e2, t2, r3) {
        let n3 = false;
        if ((t2 === void 0 || t2 < 0) && (t2 = 0), t2 > this.length || ((r3 === void 0 || r3 > this.length) && (r3 = this.length), r3 <= 0) || (r3 >>>= 0, t2 >>>= 0, r3 <= t2))
          return "";
        for (e2 || (e2 = "utf8"); ; )
          switch (e2) {
            case "hex":
              return Da(this, t2, r3);
            case "utf8":
            case "utf-8":
              return ui(this, t2, r3);
            case "ascii":
              return Ia(this, t2, r3);
            case "latin1":
            case "binary":
              return ka(this, t2, r3);
            case "base64":
              return Ra(this, t2, r3);
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return Ma(this, t2, r3);
            default:
              if (n3)
                throw new TypeError("Unknown encoding: " + e2);
              e2 = (e2 + "").toLowerCase(), n3 = true;
          }
      }
      T2.prototype._isBuffer = true;
      function je(e2, t2, r3) {
        let n3 = e2[t2];
        e2[t2] = e2[r3], e2[r3] = n3;
      }
      T2.prototype.swap16 = function() {
        let e2 = this.length;
        if (e2 % 2 !== 0)
          throw new RangeError("Buffer size must be a multiple of 16-bits");
        for (let t2 = 0; t2 < e2; t2 += 2)
          je(this, t2, t2 + 1);
        return this;
      };
      T2.prototype.swap32 = function() {
        let e2 = this.length;
        if (e2 % 4 !== 0)
          throw new RangeError("Buffer size must be a multiple of 32-bits");
        for (let t2 = 0; t2 < e2; t2 += 4)
          je(this, t2, t2 + 3), je(this, t2 + 1, t2 + 2);
        return this;
      };
      T2.prototype.swap64 = function() {
        let e2 = this.length;
        if (e2 % 8 !== 0)
          throw new RangeError("Buffer size must be a multiple of 64-bits");
        for (let t2 = 0; t2 < e2; t2 += 8)
          je(this, t2, t2 + 7), je(this, t2 + 1, t2 + 6), je(this, t2 + 2, t2 + 5), je(this, t2 + 3, t2 + 4);
        return this;
      };
      T2.prototype.toString = function() {
        let e2 = this.length;
        return e2 === 0 ? "" : arguments.length === 0 ? ui(this, 0, e2) : xa.apply(this, arguments);
      };
      T2.prototype.toLocaleString = T2.prototype.toString;
      T2.prototype.equals = function(e2) {
        if (!T2.isBuffer(e2))
          throw new TypeError("Argument must be a Buffer");
        return this === e2 ? true : T2.compare(this, e2) === 0;
      };
      T2.prototype.inspect = function() {
        let e2 = "", t2 = nt.INSPECT_MAX_BYTES;
        return e2 = this.toString("hex", 0, t2).replace(/(.{2})/g, "$1 ").trim(), this.length > t2 && (e2 += " ... "), "<Buffer " + e2 + ">";
      };
      Zn && (T2.prototype[Zn] = T2.prototype.inspect);
      T2.prototype.compare = function(e2, t2, r3, n3, i3) {
        if (me(e2, Uint8Array) && (e2 = T2.from(e2, e2.offset, e2.byteLength)), !T2.isBuffer(e2))
          throw new TypeError('The "target" argument must be one of type Buffer or Uint8Array. Received type ' + typeof e2);
        if (t2 === void 0 && (t2 = 0), r3 === void 0 && (r3 = e2 ? e2.length : 0), n3 === void 0 && (n3 = 0), i3 === void 0 && (i3 = this.length), t2 < 0 || r3 > e2.length || n3 < 0 || i3 > this.length)
          throw new RangeError("out of range index");
        if (n3 >= i3 && t2 >= r3)
          return 0;
        if (n3 >= i3)
          return -1;
        if (t2 >= r3)
          return 1;
        if (t2 >>>= 0, r3 >>>= 0, n3 >>>= 0, i3 >>>= 0, this === e2)
          return 0;
        let o4 = i3 - n3, s4 = r3 - t2, a3 = Math.min(o4, s4), u3 = this.slice(n3, i3), l3 = e2.slice(t2, r3);
        for (let g3 = 0; g3 < a3; ++g3)
          if (u3[g3] !== l3[g3]) {
            o4 = u3[g3], s4 = l3[g3];
            break;
          }
        return o4 < s4 ? -1 : s4 < o4 ? 1 : 0;
      };
      function ai(e2, t2, r3, n3, i3) {
        if (e2.length === 0)
          return -1;
        if (typeof r3 == "string" ? (n3 = r3, r3 = 0) : r3 > 2147483647 ? r3 = 2147483647 : r3 < -2147483648 && (r3 = -2147483648), r3 = +r3, Xr(r3) && (r3 = i3 ? 0 : e2.length - 1), r3 < 0 && (r3 = e2.length + r3), r3 >= e2.length) {
          if (i3)
            return -1;
          r3 = e2.length - 1;
        } else if (r3 < 0)
          if (i3)
            r3 = 0;
          else
            return -1;
        if (typeof t2 == "string" && (t2 = T2.from(t2, n3)), T2.isBuffer(t2))
          return t2.length === 0 ? -1 : Xn(e2, t2, r3, n3, i3);
        if (typeof t2 == "number")
          return t2 = t2 & 255, typeof Uint8Array.prototype.indexOf == "function" ? i3 ? Uint8Array.prototype.indexOf.call(e2, t2, r3) : Uint8Array.prototype.lastIndexOf.call(e2, t2, r3) : Xn(e2, [t2], r3, n3, i3);
        throw new TypeError("val must be string, number or Buffer");
      }
      function Xn(e2, t2, r3, n3, i3) {
        let o4 = 1, s4 = e2.length, a3 = t2.length;
        if (n3 !== void 0 && (n3 = String(n3).toLowerCase(), n3 === "ucs2" || n3 === "ucs-2" || n3 === "utf16le" || n3 === "utf-16le")) {
          if (e2.length < 2 || t2.length < 2)
            return -1;
          o4 = 2, s4 /= 2, a3 /= 2, r3 /= 2;
        }
        function u3(g3, h2) {
          return o4 === 1 ? g3[h2] : g3.readUInt16BE(h2 * o4);
        }
        let l3;
        if (i3) {
          let g3 = -1;
          for (l3 = r3; l3 < s4; l3++)
            if (u3(e2, l3) === u3(t2, g3 === -1 ? 0 : l3 - g3)) {
              if (g3 === -1 && (g3 = l3), l3 - g3 + 1 === a3)
                return g3 * o4;
            } else
              g3 !== -1 && (l3 -= l3 - g3), g3 = -1;
        } else
          for (r3 + a3 > s4 && (r3 = s4 - a3), l3 = r3; l3 >= 0; l3--) {
            let g3 = true;
            for (let h2 = 0; h2 < a3; h2++)
              if (u3(e2, l3 + h2) !== u3(t2, h2)) {
                g3 = false;
                break;
              }
            if (g3)
              return l3;
          }
        return -1;
      }
      T2.prototype.includes = function(e2, t2, r3) {
        return this.indexOf(e2, t2, r3) !== -1;
      };
      T2.prototype.indexOf = function(e2, t2, r3) {
        return ai(this, e2, t2, r3, true);
      };
      T2.prototype.lastIndexOf = function(e2, t2, r3) {
        return ai(this, e2, t2, r3, false);
      };
      function Pa(e2, t2, r3, n3) {
        r3 = Number(r3) || 0;
        let i3 = e2.length - r3;
        n3 ? (n3 = Number(n3), n3 > i3 && (n3 = i3)) : n3 = i3;
        let o4 = t2.length;
        n3 > o4 / 2 && (n3 = o4 / 2);
        let s4;
        for (s4 = 0; s4 < n3; ++s4) {
          let a3 = parseInt(t2.substr(s4 * 2, 2), 16);
          if (Xr(a3))
            return s4;
          e2[r3 + s4] = a3;
        }
        return s4;
      }
      function va(e2, t2, r3, n3) {
        return sr(Kr(t2, e2.length - r3), e2, r3, n3);
      }
      function Ta(e2, t2, r3, n3) {
        return sr(La(t2), e2, r3, n3);
      }
      function Ca(e2, t2, r3, n3) {
        return sr(gi(t2), e2, r3, n3);
      }
      function Aa(e2, t2, r3, n3) {
        return sr(Fa(t2, e2.length - r3), e2, r3, n3);
      }
      T2.prototype.write = function(e2, t2, r3, n3) {
        if (t2 === void 0)
          n3 = "utf8", r3 = this.length, t2 = 0;
        else if (r3 === void 0 && typeof t2 == "string")
          n3 = t2, r3 = this.length, t2 = 0;
        else if (isFinite(t2))
          t2 = t2 >>> 0, isFinite(r3) ? (r3 = r3 >>> 0, n3 === void 0 && (n3 = "utf8")) : (n3 = r3, r3 = void 0);
        else
          throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");
        let i3 = this.length - t2;
        if ((r3 === void 0 || r3 > i3) && (r3 = i3), e2.length > 0 && (r3 < 0 || t2 < 0) || t2 > this.length)
          throw new RangeError("Attempt to write outside buffer bounds");
        n3 || (n3 = "utf8");
        let o4 = false;
        for (; ; )
          switch (n3) {
            case "hex":
              return Pa(this, e2, t2, r3);
            case "utf8":
            case "utf-8":
              return va(this, e2, t2, r3);
            case "ascii":
            case "latin1":
            case "binary":
              return Ta(this, e2, t2, r3);
            case "base64":
              return Ca(this, e2, t2, r3);
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return Aa(this, e2, t2, r3);
            default:
              if (o4)
                throw new TypeError("Unknown encoding: " + n3);
              n3 = ("" + n3).toLowerCase(), o4 = true;
          }
      };
      T2.prototype.toJSON = function() {
        return { type: "Buffer", data: Array.prototype.slice.call(this._arr || this, 0) };
      };
      function Ra(e2, t2, r3) {
        return t2 === 0 && r3 === e2.length ? Hr.fromByteArray(e2) : Hr.fromByteArray(e2.slice(t2, r3));
      }
      function ui(e2, t2, r3) {
        r3 = Math.min(e2.length, r3);
        let n3 = [], i3 = t2;
        for (; i3 < r3; ) {
          let o4 = e2[i3], s4 = null, a3 = o4 > 239 ? 4 : o4 > 223 ? 3 : o4 > 191 ? 2 : 1;
          if (i3 + a3 <= r3) {
            let u3, l3, g3, h2;
            switch (a3) {
              case 1:
                o4 < 128 && (s4 = o4);
                break;
              case 2:
                u3 = e2[i3 + 1], (u3 & 192) === 128 && (h2 = (o4 & 31) << 6 | u3 & 63, h2 > 127 && (s4 = h2));
                break;
              case 3:
                u3 = e2[i3 + 1], l3 = e2[i3 + 2], (u3 & 192) === 128 && (l3 & 192) === 128 && (h2 = (o4 & 15) << 12 | (u3 & 63) << 6 | l3 & 63, h2 > 2047 && (h2 < 55296 || h2 > 57343) && (s4 = h2));
                break;
              case 4:
                u3 = e2[i3 + 1], l3 = e2[i3 + 2], g3 = e2[i3 + 3], (u3 & 192) === 128 && (l3 & 192) === 128 && (g3 & 192) === 128 && (h2 = (o4 & 15) << 18 | (u3 & 63) << 12 | (l3 & 63) << 6 | g3 & 63, h2 > 65535 && h2 < 1114112 && (s4 = h2));
            }
          }
          s4 === null ? (s4 = 65533, a3 = 1) : s4 > 65535 && (s4 -= 65536, n3.push(s4 >>> 10 & 1023 | 55296), s4 = 56320 | s4 & 1023), n3.push(s4), i3 += a3;
        }
        return Sa(n3);
      }
      var ei = 4096;
      function Sa(e2) {
        let t2 = e2.length;
        if (t2 <= ei)
          return String.fromCharCode.apply(String, e2);
        let r3 = "", n3 = 0;
        for (; n3 < t2; )
          r3 += String.fromCharCode.apply(String, e2.slice(n3, n3 += ei));
        return r3;
      }
      function Ia(e2, t2, r3) {
        let n3 = "";
        r3 = Math.min(e2.length, r3);
        for (let i3 = t2; i3 < r3; ++i3)
          n3 += String.fromCharCode(e2[i3] & 127);
        return n3;
      }
      function ka(e2, t2, r3) {
        let n3 = "";
        r3 = Math.min(e2.length, r3);
        for (let i3 = t2; i3 < r3; ++i3)
          n3 += String.fromCharCode(e2[i3]);
        return n3;
      }
      function Da(e2, t2, r3) {
        let n3 = e2.length;
        (!t2 || t2 < 0) && (t2 = 0), (!r3 || r3 < 0 || r3 > n3) && (r3 = n3);
        let i3 = "";
        for (let o4 = t2; o4 < r3; ++o4)
          i3 += Ba[e2[o4]];
        return i3;
      }
      function Ma(e2, t2, r3) {
        let n3 = e2.slice(t2, r3), i3 = "";
        for (let o4 = 0; o4 < n3.length - 1; o4 += 2)
          i3 += String.fromCharCode(n3[o4] + n3[o4 + 1] * 256);
        return i3;
      }
      T2.prototype.slice = function(e2, t2) {
        let r3 = this.length;
        e2 = ~~e2, t2 = t2 === void 0 ? r3 : ~~t2, e2 < 0 ? (e2 += r3, e2 < 0 && (e2 = 0)) : e2 > r3 && (e2 = r3), t2 < 0 ? (t2 += r3, t2 < 0 && (t2 = 0)) : t2 > r3 && (t2 = r3), t2 < e2 && (t2 = e2);
        let n3 = this.subarray(e2, t2);
        return Object.setPrototypeOf(n3, T2.prototype), n3;
      };
      function W(e2, t2, r3) {
        if (e2 % 1 !== 0 || e2 < 0)
          throw new RangeError("offset is not uint");
        if (e2 + t2 > r3)
          throw new RangeError("Trying to access beyond buffer length");
      }
      T2.prototype.readUintLE = T2.prototype.readUIntLE = function(e2, t2, r3) {
        e2 = e2 >>> 0, t2 = t2 >>> 0, r3 || W(e2, t2, this.length);
        let n3 = this[e2], i3 = 1, o4 = 0;
        for (; ++o4 < t2 && (i3 *= 256); )
          n3 += this[e2 + o4] * i3;
        return n3;
      };
      T2.prototype.readUintBE = T2.prototype.readUIntBE = function(e2, t2, r3) {
        e2 = e2 >>> 0, t2 = t2 >>> 0, r3 || W(e2, t2, this.length);
        let n3 = this[e2 + --t2], i3 = 1;
        for (; t2 > 0 && (i3 *= 256); )
          n3 += this[e2 + --t2] * i3;
        return n3;
      };
      T2.prototype.readUint8 = T2.prototype.readUInt8 = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 1, this.length), this[e2];
      };
      T2.prototype.readUint16LE = T2.prototype.readUInt16LE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 2, this.length), this[e2] | this[e2 + 1] << 8;
      };
      T2.prototype.readUint16BE = T2.prototype.readUInt16BE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 2, this.length), this[e2] << 8 | this[e2 + 1];
      };
      T2.prototype.readUint32LE = T2.prototype.readUInt32LE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 4, this.length), (this[e2] | this[e2 + 1] << 8 | this[e2 + 2] << 16) + this[e2 + 3] * 16777216;
      };
      T2.prototype.readUint32BE = T2.prototype.readUInt32BE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 4, this.length), this[e2] * 16777216 + (this[e2 + 1] << 16 | this[e2 + 2] << 8 | this[e2 + 3]);
      };
      T2.prototype.readBigUInt64LE = ke(function(e2) {
        e2 = e2 >>> 0, rt(e2, "offset");
        let t2 = this[e2], r3 = this[e2 + 7];
        (t2 === void 0 || r3 === void 0) && Tt(e2, this.length - 8);
        let n3 = t2 + this[++e2] * 2 ** 8 + this[++e2] * 2 ** 16 + this[++e2] * 2 ** 24, i3 = this[++e2] + this[++e2] * 2 ** 8 + this[++e2] * 2 ** 16 + r3 * 2 ** 24;
        return BigInt(n3) + (BigInt(i3) << BigInt(32));
      });
      T2.prototype.readBigUInt64BE = ke(function(e2) {
        e2 = e2 >>> 0, rt(e2, "offset");
        let t2 = this[e2], r3 = this[e2 + 7];
        (t2 === void 0 || r3 === void 0) && Tt(e2, this.length - 8);
        let n3 = t2 * 2 ** 24 + this[++e2] * 2 ** 16 + this[++e2] * 2 ** 8 + this[++e2], i3 = this[++e2] * 2 ** 24 + this[++e2] * 2 ** 16 + this[++e2] * 2 ** 8 + r3;
        return (BigInt(n3) << BigInt(32)) + BigInt(i3);
      });
      T2.prototype.readIntLE = function(e2, t2, r3) {
        e2 = e2 >>> 0, t2 = t2 >>> 0, r3 || W(e2, t2, this.length);
        let n3 = this[e2], i3 = 1, o4 = 0;
        for (; ++o4 < t2 && (i3 *= 256); )
          n3 += this[e2 + o4] * i3;
        return i3 *= 128, n3 >= i3 && (n3 -= Math.pow(2, 8 * t2)), n3;
      };
      T2.prototype.readIntBE = function(e2, t2, r3) {
        e2 = e2 >>> 0, t2 = t2 >>> 0, r3 || W(e2, t2, this.length);
        let n3 = t2, i3 = 1, o4 = this[e2 + --n3];
        for (; n3 > 0 && (i3 *= 256); )
          o4 += this[e2 + --n3] * i3;
        return i3 *= 128, o4 >= i3 && (o4 -= Math.pow(2, 8 * t2)), o4;
      };
      T2.prototype.readInt8 = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 1, this.length), this[e2] & 128 ? (255 - this[e2] + 1) * -1 : this[e2];
      };
      T2.prototype.readInt16LE = function(e2, t2) {
        e2 = e2 >>> 0, t2 || W(e2, 2, this.length);
        let r3 = this[e2] | this[e2 + 1] << 8;
        return r3 & 32768 ? r3 | 4294901760 : r3;
      };
      T2.prototype.readInt16BE = function(e2, t2) {
        e2 = e2 >>> 0, t2 || W(e2, 2, this.length);
        let r3 = this[e2 + 1] | this[e2] << 8;
        return r3 & 32768 ? r3 | 4294901760 : r3;
      };
      T2.prototype.readInt32LE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 4, this.length), this[e2] | this[e2 + 1] << 8 | this[e2 + 2] << 16 | this[e2 + 3] << 24;
      };
      T2.prototype.readInt32BE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 4, this.length), this[e2] << 24 | this[e2 + 1] << 16 | this[e2 + 2] << 8 | this[e2 + 3];
      };
      T2.prototype.readBigInt64LE = ke(function(e2) {
        e2 = e2 >>> 0, rt(e2, "offset");
        let t2 = this[e2], r3 = this[e2 + 7];
        (t2 === void 0 || r3 === void 0) && Tt(e2, this.length - 8);
        let n3 = this[e2 + 4] + this[e2 + 5] * 2 ** 8 + this[e2 + 6] * 2 ** 16 + (r3 << 24);
        return (BigInt(n3) << BigInt(32)) + BigInt(t2 + this[++e2] * 2 ** 8 + this[++e2] * 2 ** 16 + this[++e2] * 2 ** 24);
      });
      T2.prototype.readBigInt64BE = ke(function(e2) {
        e2 = e2 >>> 0, rt(e2, "offset");
        let t2 = this[e2], r3 = this[e2 + 7];
        (t2 === void 0 || r3 === void 0) && Tt(e2, this.length - 8);
        let n3 = (t2 << 24) + this[++e2] * 2 ** 16 + this[++e2] * 2 ** 8 + this[++e2];
        return (BigInt(n3) << BigInt(32)) + BigInt(this[++e2] * 2 ** 24 + this[++e2] * 2 ** 16 + this[++e2] * 2 ** 8 + r3);
      });
      T2.prototype.readFloatLE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 4, this.length), tt.read(this, e2, true, 23, 4);
      };
      T2.prototype.readFloatBE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 4, this.length), tt.read(this, e2, false, 23, 4);
      };
      T2.prototype.readDoubleLE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 8, this.length), tt.read(this, e2, true, 52, 8);
      };
      T2.prototype.readDoubleBE = function(e2, t2) {
        return e2 = e2 >>> 0, t2 || W(e2, 8, this.length), tt.read(this, e2, false, 52, 8);
      };
      function oe(e2, t2, r3, n3, i3, o4) {
        if (!T2.isBuffer(e2))
          throw new TypeError('"buffer" argument must be a Buffer instance');
        if (t2 > i3 || t2 < o4)
          throw new RangeError('"value" argument is out of bounds');
        if (r3 + n3 > e2.length)
          throw new RangeError("Index out of range");
      }
      T2.prototype.writeUintLE = T2.prototype.writeUIntLE = function(e2, t2, r3, n3) {
        if (e2 = +e2, t2 = t2 >>> 0, r3 = r3 >>> 0, !n3) {
          let s4 = Math.pow(2, 8 * r3) - 1;
          oe(this, e2, t2, r3, s4, 0);
        }
        let i3 = 1, o4 = 0;
        for (this[t2] = e2 & 255; ++o4 < r3 && (i3 *= 256); )
          this[t2 + o4] = e2 / i3 & 255;
        return t2 + r3;
      };
      T2.prototype.writeUintBE = T2.prototype.writeUIntBE = function(e2, t2, r3, n3) {
        if (e2 = +e2, t2 = t2 >>> 0, r3 = r3 >>> 0, !n3) {
          let s4 = Math.pow(2, 8 * r3) - 1;
          oe(this, e2, t2, r3, s4, 0);
        }
        let i3 = r3 - 1, o4 = 1;
        for (this[t2 + i3] = e2 & 255; --i3 >= 0 && (o4 *= 256); )
          this[t2 + i3] = e2 / o4 & 255;
        return t2 + r3;
      };
      T2.prototype.writeUint8 = T2.prototype.writeUInt8 = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 1, 255, 0), this[t2] = e2 & 255, t2 + 1;
      };
      T2.prototype.writeUint16LE = T2.prototype.writeUInt16LE = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 2, 65535, 0), this[t2] = e2 & 255, this[t2 + 1] = e2 >>> 8, t2 + 2;
      };
      T2.prototype.writeUint16BE = T2.prototype.writeUInt16BE = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 2, 65535, 0), this[t2] = e2 >>> 8, this[t2 + 1] = e2 & 255, t2 + 2;
      };
      T2.prototype.writeUint32LE = T2.prototype.writeUInt32LE = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 4, 4294967295, 0), this[t2 + 3] = e2 >>> 24, this[t2 + 2] = e2 >>> 16, this[t2 + 1] = e2 >>> 8, this[t2] = e2 & 255, t2 + 4;
      };
      T2.prototype.writeUint32BE = T2.prototype.writeUInt32BE = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 4, 4294967295, 0), this[t2] = e2 >>> 24, this[t2 + 1] = e2 >>> 16, this[t2 + 2] = e2 >>> 8, this[t2 + 3] = e2 & 255, t2 + 4;
      };
      function li(e2, t2, r3, n3, i3) {
        di(t2, n3, i3, e2, r3, 7);
        let o4 = Number(t2 & BigInt(4294967295));
        e2[r3++] = o4, o4 = o4 >> 8, e2[r3++] = o4, o4 = o4 >> 8, e2[r3++] = o4, o4 = o4 >> 8, e2[r3++] = o4;
        let s4 = Number(t2 >> BigInt(32) & BigInt(4294967295));
        return e2[r3++] = s4, s4 = s4 >> 8, e2[r3++] = s4, s4 = s4 >> 8, e2[r3++] = s4, s4 = s4 >> 8, e2[r3++] = s4, r3;
      }
      function ci(e2, t2, r3, n3, i3) {
        di(t2, n3, i3, e2, r3, 7);
        let o4 = Number(t2 & BigInt(4294967295));
        e2[r3 + 7] = o4, o4 = o4 >> 8, e2[r3 + 6] = o4, o4 = o4 >> 8, e2[r3 + 5] = o4, o4 = o4 >> 8, e2[r3 + 4] = o4;
        let s4 = Number(t2 >> BigInt(32) & BigInt(4294967295));
        return e2[r3 + 3] = s4, s4 = s4 >> 8, e2[r3 + 2] = s4, s4 = s4 >> 8, e2[r3 + 1] = s4, s4 = s4 >> 8, e2[r3] = s4, r3 + 8;
      }
      T2.prototype.writeBigUInt64LE = ke(function(e2, t2 = 0) {
        return li(this, e2, t2, BigInt(0), BigInt("0xffffffffffffffff"));
      });
      T2.prototype.writeBigUInt64BE = ke(function(e2, t2 = 0) {
        return ci(this, e2, t2, BigInt(0), BigInt("0xffffffffffffffff"));
      });
      T2.prototype.writeIntLE = function(e2, t2, r3, n3) {
        if (e2 = +e2, t2 = t2 >>> 0, !n3) {
          let a3 = Math.pow(2, 8 * r3 - 1);
          oe(this, e2, t2, r3, a3 - 1, -a3);
        }
        let i3 = 0, o4 = 1, s4 = 0;
        for (this[t2] = e2 & 255; ++i3 < r3 && (o4 *= 256); )
          e2 < 0 && s4 === 0 && this[t2 + i3 - 1] !== 0 && (s4 = 1), this[t2 + i3] = (e2 / o4 >> 0) - s4 & 255;
        return t2 + r3;
      };
      T2.prototype.writeIntBE = function(e2, t2, r3, n3) {
        if (e2 = +e2, t2 = t2 >>> 0, !n3) {
          let a3 = Math.pow(2, 8 * r3 - 1);
          oe(this, e2, t2, r3, a3 - 1, -a3);
        }
        let i3 = r3 - 1, o4 = 1, s4 = 0;
        for (this[t2 + i3] = e2 & 255; --i3 >= 0 && (o4 *= 256); )
          e2 < 0 && s4 === 0 && this[t2 + i3 + 1] !== 0 && (s4 = 1), this[t2 + i3] = (e2 / o4 >> 0) - s4 & 255;
        return t2 + r3;
      };
      T2.prototype.writeInt8 = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 1, 127, -128), e2 < 0 && (e2 = 255 + e2 + 1), this[t2] = e2 & 255, t2 + 1;
      };
      T2.prototype.writeInt16LE = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 2, 32767, -32768), this[t2] = e2 & 255, this[t2 + 1] = e2 >>> 8, t2 + 2;
      };
      T2.prototype.writeInt16BE = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 2, 32767, -32768), this[t2] = e2 >>> 8, this[t2 + 1] = e2 & 255, t2 + 2;
      };
      T2.prototype.writeInt32LE = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 4, 2147483647, -2147483648), this[t2] = e2 & 255, this[t2 + 1] = e2 >>> 8, this[t2 + 2] = e2 >>> 16, this[t2 + 3] = e2 >>> 24, t2 + 4;
      };
      T2.prototype.writeInt32BE = function(e2, t2, r3) {
        return e2 = +e2, t2 = t2 >>> 0, r3 || oe(this, e2, t2, 4, 2147483647, -2147483648), e2 < 0 && (e2 = 4294967295 + e2 + 1), this[t2] = e2 >>> 24, this[t2 + 1] = e2 >>> 16, this[t2 + 2] = e2 >>> 8, this[t2 + 3] = e2 & 255, t2 + 4;
      };
      T2.prototype.writeBigInt64LE = ke(function(e2, t2 = 0) {
        return li(this, e2, t2, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
      });
      T2.prototype.writeBigInt64BE = ke(function(e2, t2 = 0) {
        return ci(this, e2, t2, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
      });
      function pi(e2, t2, r3, n3, i3, o4) {
        if (r3 + n3 > e2.length)
          throw new RangeError("Index out of range");
        if (r3 < 0)
          throw new RangeError("Index out of range");
      }
      function fi(e2, t2, r3, n3, i3) {
        return t2 = +t2, r3 = r3 >>> 0, i3 || pi(e2, t2, r3, 4, 34028234663852886e22, -34028234663852886e22), tt.write(e2, t2, r3, n3, 23, 4), r3 + 4;
      }
      T2.prototype.writeFloatLE = function(e2, t2, r3) {
        return fi(this, e2, t2, true, r3);
      };
      T2.prototype.writeFloatBE = function(e2, t2, r3) {
        return fi(this, e2, t2, false, r3);
      };
      function mi(e2, t2, r3, n3, i3) {
        return t2 = +t2, r3 = r3 >>> 0, i3 || pi(e2, t2, r3, 8, 17976931348623157e292, -17976931348623157e292), tt.write(e2, t2, r3, n3, 52, 8), r3 + 8;
      }
      T2.prototype.writeDoubleLE = function(e2, t2, r3) {
        return mi(this, e2, t2, true, r3);
      };
      T2.prototype.writeDoubleBE = function(e2, t2, r3) {
        return mi(this, e2, t2, false, r3);
      };
      T2.prototype.copy = function(e2, t2, r3, n3) {
        if (!T2.isBuffer(e2))
          throw new TypeError("argument should be a Buffer");
        if (r3 || (r3 = 0), !n3 && n3 !== 0 && (n3 = this.length), t2 >= e2.length && (t2 = e2.length), t2 || (t2 = 0), n3 > 0 && n3 < r3 && (n3 = r3), n3 === r3 || e2.length === 0 || this.length === 0)
          return 0;
        if (t2 < 0)
          throw new RangeError("targetStart out of bounds");
        if (r3 < 0 || r3 >= this.length)
          throw new RangeError("Index out of range");
        if (n3 < 0)
          throw new RangeError("sourceEnd out of bounds");
        n3 > this.length && (n3 = this.length), e2.length - t2 < n3 - r3 && (n3 = e2.length - t2 + r3);
        let i3 = n3 - r3;
        return this === e2 && typeof Uint8Array.prototype.copyWithin == "function" ? this.copyWithin(t2, r3, n3) : Uint8Array.prototype.set.call(e2, this.subarray(r3, n3), t2), i3;
      };
      T2.prototype.fill = function(e2, t2, r3, n3) {
        if (typeof e2 == "string") {
          if (typeof t2 == "string" ? (n3 = t2, t2 = 0, r3 = this.length) : typeof r3 == "string" && (n3 = r3, r3 = this.length), n3 !== void 0 && typeof n3 != "string")
            throw new TypeError("encoding must be a string");
          if (typeof n3 == "string" && !T2.isEncoding(n3))
            throw new TypeError("Unknown encoding: " + n3);
          if (e2.length === 1) {
            let o4 = e2.charCodeAt(0);
            (n3 === "utf8" && o4 < 128 || n3 === "latin1") && (e2 = o4);
          }
        } else
          typeof e2 == "number" ? e2 = e2 & 255 : typeof e2 == "boolean" && (e2 = Number(e2));
        if (t2 < 0 || this.length < t2 || this.length < r3)
          throw new RangeError("Out of range index");
        if (r3 <= t2)
          return this;
        t2 = t2 >>> 0, r3 = r3 === void 0 ? this.length : r3 >>> 0, e2 || (e2 = 0);
        let i3;
        if (typeof e2 == "number")
          for (i3 = t2; i3 < r3; ++i3)
            this[i3] = e2;
        else {
          let o4 = T2.isBuffer(e2) ? e2 : T2.from(e2, n3), s4 = o4.length;
          if (s4 === 0)
            throw new TypeError('The value "' + e2 + '" is invalid for argument "value"');
          for (i3 = 0; i3 < r3 - t2; ++i3)
            this[i3 + t2] = o4[i3 % s4];
        }
        return this;
      };
      var et = {};
      function Zr(e2, t2, r3) {
        et[e2] = class extends r3 {
          constructor() {
            super(), Object.defineProperty(this, "message", { value: t2.apply(this, arguments), writable: true, configurable: true }), this.name = `${this.name} [${e2}]`, this.stack, delete this.name;
          }
          get code() {
            return e2;
          }
          set code(n3) {
            Object.defineProperty(this, "code", { configurable: true, enumerable: true, value: n3, writable: true });
          }
          toString() {
            return `${this.name} [${e2}]: ${this.message}`;
          }
        };
      }
      Zr("ERR_BUFFER_OUT_OF_BOUNDS", function(e2) {
        return e2 ? `${e2} is outside of buffer bounds` : "Attempt to access memory outside buffer bounds";
      }, RangeError);
      Zr("ERR_INVALID_ARG_TYPE", function(e2, t2) {
        return `The "${e2}" argument must be of type number. Received type ${typeof t2}`;
      }, TypeError);
      Zr("ERR_OUT_OF_RANGE", function(e2, t2, r3) {
        let n3 = `The value of "${e2}" is out of range.`, i3 = r3;
        return Number.isInteger(r3) && Math.abs(r3) > 2 ** 32 ? i3 = ti(String(r3)) : typeof r3 == "bigint" && (i3 = String(r3), (r3 > BigInt(2) ** BigInt(32) || r3 < -(BigInt(2) ** BigInt(32))) && (i3 = ti(i3)), i3 += "n"), n3 += ` It must be ${t2}. Received ${i3}`, n3;
      }, RangeError);
      function ti(e2) {
        let t2 = "", r3 = e2.length, n3 = e2[0] === "-" ? 1 : 0;
        for (; r3 >= n3 + 4; r3 -= 3)
          t2 = `_${e2.slice(r3 - 3, r3)}${t2}`;
        return `${e2.slice(0, r3)}${t2}`;
      }
      function Oa(e2, t2, r3) {
        rt(t2, "offset"), (e2[t2] === void 0 || e2[t2 + r3] === void 0) && Tt(t2, e2.length - (r3 + 1));
      }
      function di(e2, t2, r3, n3, i3, o4) {
        if (e2 > r3 || e2 < t2) {
          let s4 = typeof t2 == "bigint" ? "n" : "", a3;
          throw o4 > 3 ? t2 === 0 || t2 === BigInt(0) ? a3 = `>= 0${s4} and < 2${s4} ** ${(o4 + 1) * 8}${s4}` : a3 = `>= -(2${s4} ** ${(o4 + 1) * 8 - 1}${s4}) and < 2 ** ${(o4 + 1) * 8 - 1}${s4}` : a3 = `>= ${t2}${s4} and <= ${r3}${s4}`, new et.ERR_OUT_OF_RANGE("value", a3, e2);
        }
        Oa(n3, i3, o4);
      }
      function rt(e2, t2) {
        if (typeof e2 != "number")
          throw new et.ERR_INVALID_ARG_TYPE(t2, "number", e2);
      }
      function Tt(e2, t2, r3) {
        throw Math.floor(e2) !== e2 ? (rt(e2, r3), new et.ERR_OUT_OF_RANGE(r3 || "offset", "an integer", e2)) : t2 < 0 ? new et.ERR_BUFFER_OUT_OF_BOUNDS() : new et.ERR_OUT_OF_RANGE(r3 || "offset", `>= ${r3 ? 1 : 0} and <= ${t2}`, e2);
      }
      var Na = /[^+/0-9A-Za-z-_]/g;
      function _a(e2) {
        if (e2 = e2.split("=")[0], e2 = e2.trim().replace(Na, ""), e2.length < 2)
          return "";
        for (; e2.length % 4 !== 0; )
          e2 = e2 + "=";
        return e2;
      }
      function Kr(e2, t2) {
        t2 = t2 || 1 / 0;
        let r3, n3 = e2.length, i3 = null, o4 = [];
        for (let s4 = 0; s4 < n3; ++s4) {
          if (r3 = e2.charCodeAt(s4), r3 > 55295 && r3 < 57344) {
            if (!i3) {
              if (r3 > 56319) {
                (t2 -= 3) > -1 && o4.push(239, 191, 189);
                continue;
              } else if (s4 + 1 === n3) {
                (t2 -= 3) > -1 && o4.push(239, 191, 189);
                continue;
              }
              i3 = r3;
              continue;
            }
            if (r3 < 56320) {
              (t2 -= 3) > -1 && o4.push(239, 191, 189), i3 = r3;
              continue;
            }
            r3 = (i3 - 55296 << 10 | r3 - 56320) + 65536;
          } else
            i3 && (t2 -= 3) > -1 && o4.push(239, 191, 189);
          if (i3 = null, r3 < 128) {
            if ((t2 -= 1) < 0)
              break;
            o4.push(r3);
          } else if (r3 < 2048) {
            if ((t2 -= 2) < 0)
              break;
            o4.push(r3 >> 6 | 192, r3 & 63 | 128);
          } else if (r3 < 65536) {
            if ((t2 -= 3) < 0)
              break;
            o4.push(r3 >> 12 | 224, r3 >> 6 & 63 | 128, r3 & 63 | 128);
          } else if (r3 < 1114112) {
            if ((t2 -= 4) < 0)
              break;
            o4.push(r3 >> 18 | 240, r3 >> 12 & 63 | 128, r3 >> 6 & 63 | 128, r3 & 63 | 128);
          } else
            throw new Error("Invalid code point");
        }
        return o4;
      }
      function La(e2) {
        let t2 = [];
        for (let r3 = 0; r3 < e2.length; ++r3)
          t2.push(e2.charCodeAt(r3) & 255);
        return t2;
      }
      function Fa(e2, t2) {
        let r3, n3, i3, o4 = [];
        for (let s4 = 0; s4 < e2.length && !((t2 -= 2) < 0); ++s4)
          r3 = e2.charCodeAt(s4), n3 = r3 >> 8, i3 = r3 % 256, o4.push(i3), o4.push(n3);
        return o4;
      }
      function gi(e2) {
        return Hr.toByteArray(_a(e2));
      }
      function sr(e2, t2, r3, n3) {
        let i3;
        for (i3 = 0; i3 < n3 && !(i3 + r3 >= t2.length || i3 >= e2.length); ++i3)
          t2[i3 + r3] = e2[i3];
        return i3;
      }
      function me(e2, t2) {
        return e2 instanceof t2 || e2 != null && e2.constructor != null && e2.constructor.name != null && e2.constructor.name === t2.name;
      }
      function Xr(e2) {
        return e2 !== e2;
      }
      var Ba = function() {
        let e2 = "0123456789abcdef", t2 = new Array(256);
        for (let r3 = 0; r3 < 16; ++r3) {
          let n3 = r3 * 16;
          for (let i3 = 0; i3 < 16; ++i3)
            t2[n3 + i3] = e2[r3] + e2[i3];
        }
        return t2;
      }();
      function ke(e2) {
        return typeof BigInt > "u" ? $a : e2;
      }
      function $a() {
        throw new Error("BigInt not supported");
      }
    });
    var w3;
    var d3 = be(() => {
      "use strict";
      w3 = Ve(hi());
    });
    function qa() {
      return false;
    }
    var Ua;
    var Va;
    var bi;
    var xi = be(() => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      Ua = {}, Va = { existsSync: qa, promises: Ua }, bi = Va;
    });
    var Oi = Ie((uf, Mi) => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      Mi.exports = (on(), Gr(nn)).format;
    });
    var nn = {};
    vt(nn, { default: () => Qa, deprecate: () => _i, format: () => Fi, inspect: () => Li, promisify: () => Ni });
    function Ni(e2) {
      return (...t2) => new Promise((r3, n3) => {
        e2(...t2, (i3, o4) => {
          i3 ? n3(i3) : r3(o4);
        });
      });
    }
    function _i(e2, t2) {
      return (...r3) => (console.warn(t2), e2(...r3));
    }
    function Li(e2) {
      return JSON.stringify(e2, (t2, r3) => typeof r3 == "function" ? r3.toString() : typeof r3 == "bigint" ? `${r3}n` : r3 instanceof Error ? { ...r3, message: r3.message, stack: r3.stack } : r3);
    }
    var Fi;
    var Ja;
    var Qa;
    var on = be(() => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      Fi = Oi(), Ja = { promisify: Ni, deprecate: _i, inspect: Li, format: Fi }, Qa = Ja;
    });
    function za(...e2) {
      return e2.join("/");
    }
    function Ya(...e2) {
      return e2.join("/");
    }
    var Ji;
    var Za;
    var Xa;
    var At;
    var Qi = be(() => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      Ji = "/", Za = { sep: Ji }, Xa = { resolve: za, posix: Za, join: Ya, sep: Ji }, At = Xa;
    });
    var cr;
    var Hi = be(() => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      cr = class {
        constructor() {
          this.events = {};
        }
        on(t2, r3) {
          return this.events[t2] || (this.events[t2] = []), this.events[t2].push(r3), this;
        }
        emit(t2, ...r3) {
          return this.events[t2] ? (this.events[t2].forEach((n3) => {
            n3(...r3);
          }), true) : false;
        }
      };
    });
    var Ki = Ie((mm, Wi) => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      Wi.exports = (e2, t2 = 1, r3) => {
        if (r3 = { indent: " ", includeEmptyLines: false, ...r3 }, typeof e2 != "string")
          throw new TypeError(`Expected \`input\` to be a \`string\`, got \`${typeof e2}\``);
        if (typeof t2 != "number")
          throw new TypeError(`Expected \`count\` to be a \`number\`, got \`${typeof t2}\``);
        if (typeof r3.indent != "string")
          throw new TypeError(`Expected \`options.indent\` to be a \`string\`, got \`${typeof r3.indent}\``);
        if (t2 === 0)
          return e2;
        let n3 = r3.includeEmptyLines ? /^/gm : /^(?!\s*$)/gm;
        return e2.replace(n3, r3.indent.repeat(t2));
      };
    });
    var Zi = Ie((Cm, Yi) => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      Yi.exports = ({ onlyFirst: e2 = false } = {}) => {
        let t2 = ["[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]+)*|[a-zA-Z\\d]+(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)", "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))"].join("|");
        return new RegExp(t2, e2 ? void 0 : "g");
      };
    });
    var eo = Ie((Dm, Xi) => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      var ou = Zi();
      Xi.exports = (e2) => typeof e2 == "string" ? e2.replace(ou(), "") : e2;
    });
    var io = Ie((Rh, lu) => {
      lu.exports = { name: "@prisma/engines-version", version: "5.11.0-15.efd2449663b3d73d637ea1fd226bafbcf45b3102", main: "index.js", types: "index.d.ts", license: "Apache-2.0", author: "Tim Suchanek <suchanek@prisma.io>", prisma: { enginesVersion: "efd2449663b3d73d637ea1fd226bafbcf45b3102" }, repository: { type: "git", url: "https://github.com/prisma/engines-wrapper.git", directory: "packages/engines-version" }, devDependencies: { "@types/node": "18.19.22", typescript: "4.9.5" }, files: ["index.js", "index.d.ts"], scripts: { build: "tsc -d" } };
    });
    var oo = Ie(() => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
    });
    var Un = Ie((tR, hs) => {
      "use strict";
      d3();
      c3();
      p3();
      f3();
      m3();
      hs.exports = /* @__PURE__ */ function() {
        function e2(t2, r3, n3, i3, o4) {
          return t2 < r3 || n3 < r3 ? t2 > n3 ? n3 + 1 : t2 + 1 : i3 === o4 ? r3 : r3 + 1;
        }
        return function(t2, r3) {
          if (t2 === r3)
            return 0;
          if (t2.length > r3.length) {
            var n3 = t2;
            t2 = r3, r3 = n3;
          }
          for (var i3 = t2.length, o4 = r3.length; i3 > 0 && t2.charCodeAt(i3 - 1) === r3.charCodeAt(o4 - 1); )
            i3--, o4--;
          for (var s4 = 0; s4 < i3 && t2.charCodeAt(s4) === r3.charCodeAt(s4); )
            s4++;
          if (i3 -= s4, o4 -= s4, i3 === 0 || o4 < 3)
            return o4;
          var a3 = 0, u3, l3, g3, h2, v3, S2, A2, R, D, M2, B, I2, L2 = [];
          for (u3 = 0; u3 < i3; u3++)
            L2.push(u3 + 1), L2.push(t2.charCodeAt(s4 + u3));
          for (var ee = L2.length - 1; a3 < o4 - 3; )
            for (D = r3.charCodeAt(s4 + (l3 = a3)), M2 = r3.charCodeAt(s4 + (g3 = a3 + 1)), B = r3.charCodeAt(s4 + (h2 = a3 + 2)), I2 = r3.charCodeAt(s4 + (v3 = a3 + 3)), S2 = a3 += 4, u3 = 0; u3 < ee; u3 += 2)
              A2 = L2[u3], R = L2[u3 + 1], l3 = e2(A2, l3, g3, D, R), g3 = e2(l3, g3, h2, M2, R), h2 = e2(g3, h2, v3, B, R), S2 = e2(h2, v3, S2, I2, R), L2[u3] = S2, v3 = h2, h2 = g3, g3 = l3, l3 = A2;
          for (; a3 < o4; )
            for (D = r3.charCodeAt(s4 + (l3 = a3)), S2 = ++a3, u3 = 0; u3 < ee; u3 += 2)
              A2 = L2[u3], L2[u3] = S2 = e2(A2, l3, S2, D, L2[u3 + 1]), l3 = A2;
          return S2;
        };
      }();
    });
    var Uc = {};
    vt(Uc, { Debug: () => an, Decimal: () => ye, Extensions: () => en, MetricsClient: () => at, NotFoundError: () => Pe, PrismaClientInitializationError: () => G, PrismaClientKnownRequestError: () => K, PrismaClientRustPanicError: () => ve, PrismaClientUnknownRequestError: () => se, PrismaClientValidationError: () => Z, Public: () => tn, Sql: () => ae, defineDmmfProperty: () => no, empty: () => ao, getPrismaClient: () => oa, getRuntime: () => Or, join: () => so, makeStrictEnum: () => sa, objectEnumValues: () => fr, raw: () => yn, sqltag: () => wn, warnEnvConflicts: () => void 0, warnOnce: () => It });
    module.exports = Gr(Uc);
    d3();
    c3();
    p3();
    f3();
    m3();
    var en = {};
    vt(en, { defineExtension: () => yi, getExtensionContext: () => wi });
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function yi(e2) {
      return typeof e2 == "function" ? e2 : (t2) => t2.$extends(e2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function wi(e2) {
      return e2;
    }
    var tn = {};
    vt(tn, { validator: () => Ei });
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function Ei(...e2) {
      return (t2) => t2;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var rn;
    var Pi;
    var vi;
    var Ti;
    var Ci = true;
    typeof y2 != "undefined" && ({ FORCE_COLOR: rn, NODE_DISABLE_COLORS: Pi, NO_COLOR: vi, TERM: Ti } = y2.env || {}, Ci = y2.stdout && y2.stdout.isTTY);
    var ja = { enabled: !Pi && vi == null && Ti !== "dumb" && (rn != null && rn !== "0" || Ci) };
    function V(e2, t2) {
      let r3 = new RegExp(`\\x1b\\[${t2}m`, "g"), n3 = `\x1B[${e2}m`, i3 = `\x1B[${t2}m`;
      return function(o4) {
        return !ja.enabled || o4 == null ? o4 : n3 + (~("" + o4).indexOf(i3) ? o4.replace(r3, i3 + n3) : o4) + i3;
      };
    }
    var Bp = V(0, 0);
    var ar = V(1, 22);
    var ur = V(2, 22);
    var $p = V(3, 23);
    var Ai = V(4, 24);
    var qp = V(7, 27);
    var Up = V(8, 28);
    var Vp = V(9, 29);
    var jp = V(30, 39);
    var it = V(31, 39);
    var Ri = V(32, 39);
    var Si = V(33, 39);
    var Ii = V(34, 39);
    var Jp = V(35, 39);
    var ki = V(36, 39);
    var Qp = V(37, 39);
    var Di = V(90, 39);
    var Gp = V(90, 39);
    var Hp = V(40, 49);
    var Wp = V(41, 49);
    var Kp = V(42, 49);
    var zp = V(43, 49);
    var Yp = V(44, 49);
    var Zp = V(45, 49);
    var Xp = V(46, 49);
    var ef = V(47, 49);
    d3();
    c3();
    p3();
    f3();
    m3();
    var Ga = 100;
    var Bi = ["green", "yellow", "blue", "magenta", "cyan", "red"];
    var lr = [];
    var $i = Date.now();
    var Ha = 0;
    var sn = typeof y2 != "undefined" ? y2.env : {};
    var qi;
    var Ui;
    (Ui = globalThis.DEBUG) != null || (globalThis.DEBUG = (qi = sn.DEBUG) != null ? qi : "");
    var Vi;
    (Vi = globalThis.DEBUG_COLORS) != null || (globalThis.DEBUG_COLORS = sn.DEBUG_COLORS ? sn.DEBUG_COLORS === "true" : true);
    var Ct = { enable(e2) {
      typeof e2 == "string" && (globalThis.DEBUG = e2);
    }, disable() {
      let e2 = globalThis.DEBUG;
      return globalThis.DEBUG = "", e2;
    }, enabled(e2) {
      let t2 = globalThis.DEBUG.split(",").map((i3) => i3.replace(/[.+?^${}()|[\]\\]/g, "\\$&")), r3 = t2.some((i3) => i3 === "" || i3[0] === "-" ? false : e2.match(RegExp(i3.split("*").join(".*") + "$"))), n3 = t2.some((i3) => i3 === "" || i3[0] !== "-" ? false : e2.match(RegExp(i3.slice(1).split("*").join(".*") + "$")));
      return r3 && !n3;
    }, log: (...e2) => {
      var o4;
      let [t2, r3, ...n3] = e2, i3;
      typeof __require == "function" && typeof y2 != "undefined" && typeof y2.stderr != "undefined" && typeof y2.stderr.write == "function" ? i3 = (...s4) => {
        let a3 = (on(), Gr(nn));
        y2.stderr.write(a3.format(...s4) + `
`);
      } : i3 = (o4 = console.warn) != null ? o4 : console.log, i3(`${t2} ${r3}`, ...n3);
    }, formatters: {} };
    function Wa(e2) {
      let t2 = { color: Bi[Ha++ % Bi.length], enabled: Ct.enabled(e2), namespace: e2, log: Ct.log, extend: () => {
      } }, r3 = (...n3) => {
        let { enabled: i3, namespace: o4, color: s4, log: a3 } = t2;
        if (n3.length !== 0 && lr.push([o4, ...n3]), lr.length > Ga && lr.shift(), Ct.enabled(o4) || i3) {
          let u3 = n3.map((g3) => typeof g3 == "string" ? g3 : Ka(g3)), l3 = `+${Date.now() - $i}ms`;
          $i = Date.now(), a3(o4, ...u3, l3);
        }
      };
      return new Proxy(r3, { get: (n3, i3) => t2[i3], set: (n3, i3, o4) => t2[i3] = o4 });
    }
    var an = new Proxy(Wa, { get: (e2, t2) => Ct[t2], set: (e2, t2, r3) => Ct[t2] = r3 });
    function Ka(e2, t2 = 2) {
      let r3 = /* @__PURE__ */ new Set();
      return JSON.stringify(e2, (n3, i3) => {
        if (typeof i3 == "object" && i3 !== null) {
          if (r3.has(i3))
            return "[Circular *]";
          r3.add(i3);
        } else if (typeof i3 == "bigint")
          return i3.toString();
        return i3;
      }, t2);
    }
    function ji() {
      lr.length = 0;
    }
    var ne = an;
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var Gi = "library";
    function Rt(e2) {
      let t2 = eu();
      return t2 || ((e2 == null ? void 0 : e2.config.engineType) === "library" ? "library" : (e2 == null ? void 0 : e2.config.engineType) === "binary" ? "binary" : Gi);
    }
    function eu() {
      let e2 = y2.env.PRISMA_CLIENT_ENGINE_TYPE;
      return e2 === "library" ? "library" : e2 === "binary" ? "binary" : void 0;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var De;
    ((t2) => {
      let e2;
      ((I2) => (I2.findUnique = "findUnique", I2.findUniqueOrThrow = "findUniqueOrThrow", I2.findFirst = "findFirst", I2.findFirstOrThrow = "findFirstOrThrow", I2.findMany = "findMany", I2.create = "create", I2.createMany = "createMany", I2.update = "update", I2.updateMany = "updateMany", I2.upsert = "upsert", I2.delete = "delete", I2.deleteMany = "deleteMany", I2.groupBy = "groupBy", I2.count = "count", I2.aggregate = "aggregate", I2.findRaw = "findRaw", I2.aggregateRaw = "aggregateRaw"))(e2 = t2.ModelAction || (t2.ModelAction = {}));
    })(De || (De = {}));
    var ot = {};
    vt(ot, { error: () => nu, info: () => ru, log: () => tu, query: () => iu, should: () => zi, tags: () => St, warn: () => un });
    d3();
    c3();
    p3();
    f3();
    m3();
    var St = { error: it("prisma:error"), warn: Si("prisma:warn"), info: ki("prisma:info"), query: Ii("prisma:query") };
    var zi = { warn: () => !y2.env.PRISMA_DISABLE_WARNINGS };
    function tu(...e2) {
      console.log(...e2);
    }
    function un(e2, ...t2) {
      zi.warn() && console.warn(`${St.warn} ${e2}`, ...t2);
    }
    function ru(e2, ...t2) {
      console.info(`${St.info} ${e2}`, ...t2);
    }
    function nu(e2, ...t2) {
      console.error(`${St.error} ${e2}`, ...t2);
    }
    function iu(e2, ...t2) {
      console.log(`${St.query} ${e2}`, ...t2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function Je(e2, t2) {
      throw new Error(t2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function ln(e2, t2) {
      return Object.prototype.hasOwnProperty.call(e2, t2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var cn = (e2, t2) => e2.reduce((r3, n3) => (r3[t2(n3)] = n3, r3), {});
    d3();
    c3();
    p3();
    f3();
    m3();
    function st(e2, t2) {
      let r3 = {};
      for (let n3 of Object.keys(e2))
        r3[n3] = t2(e2[n3], n3);
      return r3;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function pn(e2, t2) {
      if (e2.length === 0)
        return;
      let r3 = e2[0];
      for (let n3 = 1; n3 < e2.length; n3++)
        t2(r3, e2[n3]) < 0 && (r3 = e2[n3]);
      return r3;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function N2(e2, t2) {
      Object.defineProperty(e2, "name", { value: t2, configurable: true });
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var to = /* @__PURE__ */ new Set();
    var It = (e2, t2, ...r3) => {
      to.has(e2) || (to.add(e2), un(t2, ...r3));
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var K = class extends Error {
      constructor(t2, { code: r3, clientVersion: n3, meta: i3, batchRequestIdx: o4 }) {
        super(t2), this.name = "PrismaClientKnownRequestError", this.code = r3, this.clientVersion = n3, this.meta = i3, Object.defineProperty(this, "batchRequestIdx", { value: o4, enumerable: false, writable: true });
      }
      get [Symbol.toStringTag]() {
        return "PrismaClientKnownRequestError";
      }
    };
    N2(K, "PrismaClientKnownRequestError");
    var Pe = class extends K {
      constructor(t2, r3) {
        super(t2, { code: "P2025", clientVersion: r3 }), this.name = "NotFoundError";
      }
    };
    N2(Pe, "NotFoundError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var G = class e2 extends Error {
      constructor(t2, r3, n3) {
        super(t2), this.name = "PrismaClientInitializationError", this.clientVersion = r3, this.errorCode = n3, Error.captureStackTrace(e2);
      }
      get [Symbol.toStringTag]() {
        return "PrismaClientInitializationError";
      }
    };
    N2(G, "PrismaClientInitializationError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var ve = class extends Error {
      constructor(t2, r3) {
        super(t2), this.name = "PrismaClientRustPanicError", this.clientVersion = r3;
      }
      get [Symbol.toStringTag]() {
        return "PrismaClientRustPanicError";
      }
    };
    N2(ve, "PrismaClientRustPanicError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var se = class extends Error {
      constructor(t2, { clientVersion: r3, batchRequestIdx: n3 }) {
        super(t2), this.name = "PrismaClientUnknownRequestError", this.clientVersion = r3, Object.defineProperty(this, "batchRequestIdx", { value: n3, writable: true, enumerable: false });
      }
      get [Symbol.toStringTag]() {
        return "PrismaClientUnknownRequestError";
      }
    };
    N2(se, "PrismaClientUnknownRequestError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Z = class extends Error {
      constructor(r3, { clientVersion: n3 }) {
        super(r3);
        this.name = "PrismaClientValidationError";
        this.clientVersion = n3;
      }
      get [Symbol.toStringTag]() {
        return "PrismaClientValidationError";
      }
    };
    N2(Z, "PrismaClientValidationError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var at = class {
      constructor(t2) {
        this._engine = t2;
      }
      prometheus(t2) {
        return this._engine.metrics({ format: "prometheus", ...t2 });
      }
      json(t2) {
        return this._engine.metrics({ format: "json", ...t2 });
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function kt(e2) {
      let t2;
      return { get() {
        return t2 || (t2 = { value: e2() }), t2.value;
      } };
    }
    function no(e2, t2) {
      let r3 = kt(() => su(t2));
      Object.defineProperty(e2, "dmmf", { get: () => r3.get() });
    }
    function su(e2) {
      return { datamodel: { models: fn(e2.models), enums: fn(e2.enums), types: fn(e2.types) } };
    }
    function fn(e2) {
      return Object.entries(e2).map(([t2, r3]) => ({ name: t2, ...r3 }));
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var pr = Symbol();
    var mn = /* @__PURE__ */ new WeakMap();
    var Te = class {
      constructor(t2) {
        t2 === pr ? mn.set(this, `Prisma.${this._getName()}`) : mn.set(this, `new Prisma.${this._getNamespace()}.${this._getName()}()`);
      }
      _getName() {
        return this.constructor.name;
      }
      toString() {
        return mn.get(this);
      }
    };
    var Dt = class extends Te {
      _getNamespace() {
        return "NullTypes";
      }
    };
    var Mt = class extends Dt {
    };
    dn(Mt, "DbNull");
    var Ot = class extends Dt {
    };
    dn(Ot, "JsonNull");
    var Nt = class extends Dt {
    };
    dn(Nt, "AnyNull");
    var fr = { classes: { DbNull: Mt, JsonNull: Ot, AnyNull: Nt }, instances: { DbNull: new Mt(pr), JsonNull: new Ot(pr), AnyNull: new Nt(pr) } };
    function dn(e2, t2) {
      Object.defineProperty(e2, "name", { value: t2, configurable: true });
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function _t(e2) {
      return { ok: false, error: e2, map() {
        return _t(e2);
      }, flatMap() {
        return _t(e2);
      } };
    }
    var gn = class {
      constructor() {
        this.registeredErrors = [];
      }
      consumeError(t2) {
        return this.registeredErrors[t2];
      }
      registerNewError(t2) {
        let r3 = 0;
        for (; this.registeredErrors[r3] !== void 0; )
          r3++;
        return this.registeredErrors[r3] = { error: t2 }, r3;
      }
    };
    var hn = (e2) => {
      let t2 = new gn(), r3 = Qe(t2, e2.startTransaction.bind(e2)), n3 = { errorRegistry: t2, queryRaw: Qe(t2, e2.queryRaw.bind(e2)), executeRaw: Qe(t2, e2.executeRaw.bind(e2)), provider: e2.provider, startTransaction: async (...i3) => (await r3(...i3)).map((s4) => au(t2, s4)) };
      return e2.getConnectionInfo && (n3.getConnectionInfo = uu(t2, e2.getConnectionInfo.bind(e2))), n3;
    };
    var au = (e2, t2) => ({ provider: t2.provider, options: t2.options, queryRaw: Qe(e2, t2.queryRaw.bind(t2)), executeRaw: Qe(e2, t2.executeRaw.bind(t2)), commit: Qe(e2, t2.commit.bind(t2)), rollback: Qe(e2, t2.rollback.bind(t2)) });
    function Qe(e2, t2) {
      return async (...r3) => {
        try {
          return await t2(...r3);
        } catch (n3) {
          let i3 = e2.registerNewError(n3);
          return _t({ kind: "GenericJs", id: i3 });
        }
      };
    }
    function uu(e2, t2) {
      return (...r3) => {
        try {
          return t2(...r3);
        } catch (n3) {
          let i3 = e2.registerNewError(n3);
          return _t({ kind: "GenericJs", id: i3 });
        }
      };
    }
    var ia = Ve(io());
    var cD = Ve(oo());
    Hi();
    xi();
    Qi();
    d3();
    c3();
    p3();
    f3();
    m3();
    var ae = class e2 {
      constructor(t2, r3) {
        if (t2.length - 1 !== r3.length)
          throw t2.length === 0 ? new TypeError("Expected at least 1 string") : new TypeError(`Expected ${t2.length} strings to have ${t2.length - 1} values`);
        let n3 = r3.reduce((s4, a3) => s4 + (a3 instanceof e2 ? a3.values.length : 1), 0);
        this.values = new Array(n3), this.strings = new Array(n3 + 1), this.strings[0] = t2[0];
        let i3 = 0, o4 = 0;
        for (; i3 < r3.length; ) {
          let s4 = r3[i3++], a3 = t2[i3];
          if (s4 instanceof e2) {
            this.strings[o4] += s4.strings[0];
            let u3 = 0;
            for (; u3 < s4.values.length; )
              this.values[o4++] = s4.values[u3++], this.strings[o4] = s4.strings[u3];
            this.strings[o4] += a3;
          } else
            this.values[o4++] = s4, this.strings[o4] = a3;
        }
      }
      get text() {
        let t2 = this.strings.length, r3 = 1, n3 = this.strings[0];
        for (; r3 < t2; )
          n3 += `$${r3}${this.strings[r3++]}`;
        return n3;
      }
      get sql() {
        let t2 = this.strings.length, r3 = 1, n3 = this.strings[0];
        for (; r3 < t2; )
          n3 += `?${this.strings[r3++]}`;
        return n3;
      }
      get statement() {
        let t2 = this.strings.length, r3 = 1, n3 = this.strings[0];
        for (; r3 < t2; )
          n3 += `:${r3}${this.strings[r3++]}`;
        return n3;
      }
      inspect() {
        return { text: this.text, sql: this.sql, values: this.values };
      }
    };
    function so(e2, t2 = ",", r3 = "", n3 = "") {
      if (e2.length === 0)
        throw new TypeError("Expected `join([])` to be called with an array of multiple elements, but got an empty array");
      return new ae([r3, ...Array(e2.length - 1).fill(t2), n3], e2);
    }
    function yn(e2) {
      return new ae([e2], []);
    }
    var ao = yn("");
    function wn(e2, ...t2) {
      return new ae(e2, t2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function Lt(e2) {
      return { getKeys() {
        return Object.keys(e2);
      }, getPropertyValue(t2) {
        return e2[t2];
      } };
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function ie(e2, t2) {
      return { getKeys() {
        return [e2];
      }, getPropertyValue() {
        return t2();
      } };
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var de = class {
      constructor() {
        this._map = /* @__PURE__ */ new Map();
      }
      get(t2) {
        var r3;
        return (r3 = this._map.get(t2)) == null ? void 0 : r3.value;
      }
      set(t2, r3) {
        this._map.set(t2, { value: r3 });
      }
      getOrCreate(t2, r3) {
        let n3 = this._map.get(t2);
        if (n3)
          return n3.value;
        let i3 = r3();
        return this.set(t2, i3), i3;
      }
    };
    function Ge(e2) {
      let t2 = new de();
      return { getKeys() {
        return e2.getKeys();
      }, getPropertyValue(r3) {
        return t2.getOrCreate(r3, () => e2.getPropertyValue(r3));
      }, getPropertyDescriptor(r3) {
        var n3;
        return (n3 = e2.getPropertyDescriptor) == null ? void 0 : n3.call(e2, r3);
      } };
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var mr = { enumerable: true, configurable: true, writable: true };
    function dr(e2) {
      let t2 = new Set(e2);
      return { getOwnPropertyDescriptor: () => mr, has: (r3, n3) => t2.has(n3), set: (r3, n3, i3) => t2.add(n3) && Reflect.set(r3, n3, i3), ownKeys: () => [...t2] };
    }
    var uo = Symbol.for("nodejs.util.inspect.custom");
    function ge(e2, t2) {
      let r3 = cu(t2), n3 = /* @__PURE__ */ new Set(), i3 = new Proxy(e2, { get(o4, s4) {
        if (n3.has(s4))
          return o4[s4];
        let a3 = r3.get(s4);
        return a3 ? a3.getPropertyValue(s4) : o4[s4];
      }, has(o4, s4) {
        var u3, l3;
        if (n3.has(s4))
          return true;
        let a3 = r3.get(s4);
        return a3 ? (l3 = (u3 = a3.has) == null ? void 0 : u3.call(a3, s4)) != null ? l3 : true : Reflect.has(o4, s4);
      }, ownKeys(o4) {
        let s4 = lo(Reflect.ownKeys(o4), r3), a3 = lo(Array.from(r3.keys()), r3);
        return [.../* @__PURE__ */ new Set([...s4, ...a3, ...n3])];
      }, set(o4, s4, a3) {
        var l3, g3;
        let u3 = r3.get(s4);
        return ((g3 = (l3 = u3 == null ? void 0 : u3.getPropertyDescriptor) == null ? void 0 : l3.call(u3, s4)) == null ? void 0 : g3.writable) === false ? false : (n3.add(s4), Reflect.set(o4, s4, a3));
      }, getOwnPropertyDescriptor(o4, s4) {
        let a3 = Reflect.getOwnPropertyDescriptor(o4, s4);
        if (a3 && !a3.configurable)
          return a3;
        let u3 = r3.get(s4);
        return u3 ? u3.getPropertyDescriptor ? { ...mr, ...u3 == null ? void 0 : u3.getPropertyDescriptor(s4) } : mr : a3;
      }, defineProperty(o4, s4, a3) {
        return n3.add(s4), Reflect.defineProperty(o4, s4, a3);
      } });
      return i3[uo] = function() {
        let o4 = { ...this };
        return delete o4[uo], o4;
      }, i3;
    }
    function cu(e2) {
      let t2 = /* @__PURE__ */ new Map();
      for (let r3 of e2) {
        let n3 = r3.getKeys();
        for (let i3 of n3)
          t2.set(i3, r3);
      }
      return t2;
    }
    function lo(e2, t2) {
      return e2.filter((r3) => {
        var i3, o4;
        let n3 = t2.get(r3);
        return (o4 = (i3 = n3 == null ? void 0 : n3.has) == null ? void 0 : i3.call(n3, r3)) != null ? o4 : true;
      });
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function Ft(e2) {
      return { getKeys() {
        return e2;
      }, has() {
        return false;
      }, getPropertyValue() {
      } };
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function gr(e2, t2) {
      return { batch: e2, transaction: (t2 == null ? void 0 : t2.kind) === "batch" ? { isolationLevel: t2.options.isolationLevel } : void 0 };
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var ut = class {
      constructor(t2 = 0, r3) {
        this.context = r3;
        this.lines = [];
        this.currentLine = "";
        this.currentIndent = 0;
        this.currentIndent = t2;
      }
      write(t2) {
        return typeof t2 == "string" ? this.currentLine += t2 : t2.write(this), this;
      }
      writeJoined(t2, r3) {
        let n3 = r3.length - 1;
        for (let i3 = 0; i3 < r3.length; i3++)
          this.write(r3[i3]), i3 !== n3 && this.write(t2);
        return this;
      }
      writeLine(t2) {
        return this.write(t2).newLine();
      }
      newLine() {
        this.lines.push(this.indentedCurrentLine()), this.currentLine = "", this.marginSymbol = void 0;
        let t2 = this.afterNextNewLineCallback;
        return this.afterNextNewLineCallback = void 0, t2 == null || t2(), this;
      }
      withIndent(t2) {
        return this.indent(), t2(this), this.unindent(), this;
      }
      afterNextNewline(t2) {
        return this.afterNextNewLineCallback = t2, this;
      }
      indent() {
        return this.currentIndent++, this;
      }
      unindent() {
        return this.currentIndent > 0 && this.currentIndent--, this;
      }
      addMarginSymbol(t2) {
        return this.marginSymbol = t2, this;
      }
      toString() {
        return this.lines.concat(this.indentedCurrentLine()).join(`
`);
      }
      getCurrentLineLength() {
        return this.currentLine.length;
      }
      indentedCurrentLine() {
        let t2 = this.currentLine.padStart(this.currentLine.length + 2 * this.currentIndent);
        return this.marginSymbol ? this.marginSymbol + t2.slice(1) : t2;
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function co(e2) {
      return e2.substring(0, 1).toLowerCase() + e2.substring(1);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function lt(e2) {
      return e2 instanceof Date || Object.prototype.toString.call(e2) === "[object Date]";
    }
    function hr(e2) {
      return e2.toString() !== "Invalid Date";
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var ct = 9e15;
    var _e = 1e9;
    var En = "0123456789abcdef";
    var wr = "2.3025850929940456840179914546843642076011014886287729760333279009675726096773524802359972050895982983419677840422862486334095254650828067566662873690987816894829072083255546808437998948262331985283935053089653777326288461633662222876982198867465436674744042432743651550489343149393914796194044002221051017141748003688084012647080685567743216228355220114804663715659121373450747856947683463616792101806445070648000277502684916746550586856935673420670581136429224554405758925724208241314695689016758940256776311356919292033376587141660230105703089634572075440370847469940168269282808481184289314848524948644871927809676271275775397027668605952496716674183485704422507197965004714951050492214776567636938662976979522110718264549734772662425709429322582798502585509785265383207606726317164309505995087807523710333101197857547331541421808427543863591778117054309827482385045648019095610299291824318237525357709750539565187697510374970888692180205189339507238539205144634197265287286965110862571492198849978748873771345686209167058";
    var Er = "3.1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821480865132823066470938446095505822317253594081284811174502841027019385211055596446229489549303819644288109756659334461284756482337867831652712019091456485669234603486104543266482133936072602491412737245870066063155881748815209209628292540917153643678925903600113305305488204665213841469519415116094330572703657595919530921861173819326117931051185480744623799627495673518857527248912279381830119491298336733624406566430860213949463952247371907021798609437027705392171762931767523846748184676694051320005681271452635608277857713427577896091736371787214684409012249534301465495853710507922796892589235420199561121290219608640344181598136297747713099605187072113499999983729780499510597317328160963185950244594553469083026425223082533446850352619311881710100031378387528865875332083814206171776691473035982534904287554687311595628638823537875937519577818577805321712268066130019278766111959092164201989380952572010654858632789";
    var bn = { precision: 20, rounding: 4, modulo: 1, toExpNeg: -7, toExpPos: 21, minE: -ct, maxE: ct, crypto: false };
    var go;
    var Ce;
    var _4 = true;
    var xr = "[DecimalError] ";
    var Ne = xr + "Invalid argument: ";
    var ho = xr + "Precision limit exceeded";
    var yo = xr + "crypto unavailable";
    var wo = "[object Decimal]";
    var re = Math.floor;
    var H2 = Math.pow;
    var pu = /^0b([01]+(\.[01]*)?|\.[01]+)(p[+-]?\d+)?$/i;
    var fu = /^0x([0-9a-f]+(\.[0-9a-f]*)?|\.[0-9a-f]+)(p[+-]?\d+)?$/i;
    var mu = /^0o([0-7]+(\.[0-7]*)?|\.[0-7]+)(p[+-]?\d+)?$/i;
    var Eo = /^(\d+(\.\d*)?|\.\d+)(e[+-]?\d+)?$/i;
    var pe = 1e7;
    var O3 = 7;
    var du = 9007199254740991;
    var gu = wr.length - 1;
    var xn = Er.length - 1;
    var C3 = { toStringTag: wo };
    C3.absoluteValue = C3.abs = function() {
      var e2 = new this.constructor(this);
      return e2.s < 0 && (e2.s = 1), k3(e2);
    };
    C3.ceil = function() {
      return k3(new this.constructor(this), this.e + 1, 2);
    };
    C3.clampedTo = C3.clamp = function(e2, t2) {
      var r3, n3 = this, i3 = n3.constructor;
      if (e2 = new i3(e2), t2 = new i3(t2), !e2.s || !t2.s)
        return new i3(NaN);
      if (e2.gt(t2))
        throw Error(Ne + t2);
      return r3 = n3.cmp(e2), r3 < 0 ? e2 : n3.cmp(t2) > 0 ? t2 : new i3(n3);
    };
    C3.comparedTo = C3.cmp = function(e2) {
      var t2, r3, n3, i3, o4 = this, s4 = o4.d, a3 = (e2 = new o4.constructor(e2)).d, u3 = o4.s, l3 = e2.s;
      if (!s4 || !a3)
        return !u3 || !l3 ? NaN : u3 !== l3 ? u3 : s4 === a3 ? 0 : !s4 ^ u3 < 0 ? 1 : -1;
      if (!s4[0] || !a3[0])
        return s4[0] ? u3 : a3[0] ? -l3 : 0;
      if (u3 !== l3)
        return u3;
      if (o4.e !== e2.e)
        return o4.e > e2.e ^ u3 < 0 ? 1 : -1;
      for (n3 = s4.length, i3 = a3.length, t2 = 0, r3 = n3 < i3 ? n3 : i3; t2 < r3; ++t2)
        if (s4[t2] !== a3[t2])
          return s4[t2] > a3[t2] ^ u3 < 0 ? 1 : -1;
      return n3 === i3 ? 0 : n3 > i3 ^ u3 < 0 ? 1 : -1;
    };
    C3.cosine = C3.cos = function() {
      var e2, t2, r3 = this, n3 = r3.constructor;
      return r3.d ? r3.d[0] ? (e2 = n3.precision, t2 = n3.rounding, n3.precision = e2 + Math.max(r3.e, r3.sd()) + O3, n3.rounding = 1, r3 = hu(n3, To(n3, r3)), n3.precision = e2, n3.rounding = t2, k3(Ce == 2 || Ce == 3 ? r3.neg() : r3, e2, t2, true)) : new n3(1) : new n3(NaN);
    };
    C3.cubeRoot = C3.cbrt = function() {
      var e2, t2, r3, n3, i3, o4, s4, a3, u3, l3, g3 = this, h2 = g3.constructor;
      if (!g3.isFinite() || g3.isZero())
        return new h2(g3);
      for (_4 = false, o4 = g3.s * H2(g3.s * g3, 1 / 3), !o4 || Math.abs(o4) == 1 / 0 ? (r3 = X(g3.d), e2 = g3.e, (o4 = (e2 - r3.length + 1) % 3) && (r3 += o4 == 1 || o4 == -2 ? "0" : "00"), o4 = H2(r3, 1 / 3), e2 = re((e2 + 1) / 3) - (e2 % 3 == (e2 < 0 ? -1 : 2)), o4 == 1 / 0 ? r3 = "5e" + e2 : (r3 = o4.toExponential(), r3 = r3.slice(0, r3.indexOf("e") + 1) + e2), n3 = new h2(r3), n3.s = g3.s) : n3 = new h2(o4.toString()), s4 = (e2 = h2.precision) + 3; ; )
        if (a3 = n3, u3 = a3.times(a3).times(a3), l3 = u3.plus(g3), n3 = q(l3.plus(g3).times(a3), l3.plus(u3), s4 + 2, 1), X(a3.d).slice(0, s4) === (r3 = X(n3.d)).slice(0, s4))
          if (r3 = r3.slice(s4 - 3, s4 + 1), r3 == "9999" || !i3 && r3 == "4999") {
            if (!i3 && (k3(a3, e2 + 1, 0), a3.times(a3).times(a3).eq(g3))) {
              n3 = a3;
              break;
            }
            s4 += 4, i3 = 1;
          } else {
            (!+r3 || !+r3.slice(1) && r3.charAt(0) == "5") && (k3(n3, e2 + 1, 1), t2 = !n3.times(n3).times(n3).eq(g3));
            break;
          }
      return _4 = true, k3(n3, e2, h2.rounding, t2);
    };
    C3.decimalPlaces = C3.dp = function() {
      var e2, t2 = this.d, r3 = NaN;
      if (t2) {
        if (e2 = t2.length - 1, r3 = (e2 - re(this.e / O3)) * O3, e2 = t2[e2], e2)
          for (; e2 % 10 == 0; e2 /= 10)
            r3--;
        r3 < 0 && (r3 = 0);
      }
      return r3;
    };
    C3.dividedBy = C3.div = function(e2) {
      return q(this, new this.constructor(e2));
    };
    C3.dividedToIntegerBy = C3.divToInt = function(e2) {
      var t2 = this, r3 = t2.constructor;
      return k3(q(t2, new r3(e2), 0, 1, 1), r3.precision, r3.rounding);
    };
    C3.equals = C3.eq = function(e2) {
      return this.cmp(e2) === 0;
    };
    C3.floor = function() {
      return k3(new this.constructor(this), this.e + 1, 3);
    };
    C3.greaterThan = C3.gt = function(e2) {
      return this.cmp(e2) > 0;
    };
    C3.greaterThanOrEqualTo = C3.gte = function(e2) {
      var t2 = this.cmp(e2);
      return t2 == 1 || t2 === 0;
    };
    C3.hyperbolicCosine = C3.cosh = function() {
      var e2, t2, r3, n3, i3, o4 = this, s4 = o4.constructor, a3 = new s4(1);
      if (!o4.isFinite())
        return new s4(o4.s ? 1 / 0 : NaN);
      if (o4.isZero())
        return a3;
      r3 = s4.precision, n3 = s4.rounding, s4.precision = r3 + Math.max(o4.e, o4.sd()) + 4, s4.rounding = 1, i3 = o4.d.length, i3 < 32 ? (e2 = Math.ceil(i3 / 3), t2 = (1 / vr(4, e2)).toString()) : (e2 = 16, t2 = "2.3283064365386962890625e-10"), o4 = pt(s4, 1, o4.times(t2), new s4(1), true);
      for (var u3, l3 = e2, g3 = new s4(8); l3--; )
        u3 = o4.times(o4), o4 = a3.minus(u3.times(g3.minus(u3.times(g3))));
      return k3(o4, s4.precision = r3, s4.rounding = n3, true);
    };
    C3.hyperbolicSine = C3.sinh = function() {
      var e2, t2, r3, n3, i3 = this, o4 = i3.constructor;
      if (!i3.isFinite() || i3.isZero())
        return new o4(i3);
      if (t2 = o4.precision, r3 = o4.rounding, o4.precision = t2 + Math.max(i3.e, i3.sd()) + 4, o4.rounding = 1, n3 = i3.d.length, n3 < 3)
        i3 = pt(o4, 2, i3, i3, true);
      else {
        e2 = 1.4 * Math.sqrt(n3), e2 = e2 > 16 ? 16 : e2 | 0, i3 = i3.times(1 / vr(5, e2)), i3 = pt(o4, 2, i3, i3, true);
        for (var s4, a3 = new o4(5), u3 = new o4(16), l3 = new o4(20); e2--; )
          s4 = i3.times(i3), i3 = i3.times(a3.plus(s4.times(u3.times(s4).plus(l3))));
      }
      return o4.precision = t2, o4.rounding = r3, k3(i3, t2, r3, true);
    };
    C3.hyperbolicTangent = C3.tanh = function() {
      var e2, t2, r3 = this, n3 = r3.constructor;
      return r3.isFinite() ? r3.isZero() ? new n3(r3) : (e2 = n3.precision, t2 = n3.rounding, n3.precision = e2 + 7, n3.rounding = 1, q(r3.sinh(), r3.cosh(), n3.precision = e2, n3.rounding = t2)) : new n3(r3.s);
    };
    C3.inverseCosine = C3.acos = function() {
      var e2, t2 = this, r3 = t2.constructor, n3 = t2.abs().cmp(1), i3 = r3.precision, o4 = r3.rounding;
      return n3 !== -1 ? n3 === 0 ? t2.isNeg() ? ce(r3, i3, o4) : new r3(0) : new r3(NaN) : t2.isZero() ? ce(r3, i3 + 4, o4).times(0.5) : (r3.precision = i3 + 6, r3.rounding = 1, t2 = t2.asin(), e2 = ce(r3, i3 + 4, o4).times(0.5), r3.precision = i3, r3.rounding = o4, e2.minus(t2));
    };
    C3.inverseHyperbolicCosine = C3.acosh = function() {
      var e2, t2, r3 = this, n3 = r3.constructor;
      return r3.lte(1) ? new n3(r3.eq(1) ? 0 : NaN) : r3.isFinite() ? (e2 = n3.precision, t2 = n3.rounding, n3.precision = e2 + Math.max(Math.abs(r3.e), r3.sd()) + 4, n3.rounding = 1, _4 = false, r3 = r3.times(r3).minus(1).sqrt().plus(r3), _4 = true, n3.precision = e2, n3.rounding = t2, r3.ln()) : new n3(r3);
    };
    C3.inverseHyperbolicSine = C3.asinh = function() {
      var e2, t2, r3 = this, n3 = r3.constructor;
      return !r3.isFinite() || r3.isZero() ? new n3(r3) : (e2 = n3.precision, t2 = n3.rounding, n3.precision = e2 + 2 * Math.max(Math.abs(r3.e), r3.sd()) + 6, n3.rounding = 1, _4 = false, r3 = r3.times(r3).plus(1).sqrt().plus(r3), _4 = true, n3.precision = e2, n3.rounding = t2, r3.ln());
    };
    C3.inverseHyperbolicTangent = C3.atanh = function() {
      var e2, t2, r3, n3, i3 = this, o4 = i3.constructor;
      return i3.isFinite() ? i3.e >= 0 ? new o4(i3.abs().eq(1) ? i3.s / 0 : i3.isZero() ? i3 : NaN) : (e2 = o4.precision, t2 = o4.rounding, n3 = i3.sd(), Math.max(n3, e2) < 2 * -i3.e - 1 ? k3(new o4(i3), e2, t2, true) : (o4.precision = r3 = n3 - i3.e, i3 = q(i3.plus(1), new o4(1).minus(i3), r3 + e2, 1), o4.precision = e2 + 4, o4.rounding = 1, i3 = i3.ln(), o4.precision = e2, o4.rounding = t2, i3.times(0.5))) : new o4(NaN);
    };
    C3.inverseSine = C3.asin = function() {
      var e2, t2, r3, n3, i3 = this, o4 = i3.constructor;
      return i3.isZero() ? new o4(i3) : (t2 = i3.abs().cmp(1), r3 = o4.precision, n3 = o4.rounding, t2 !== -1 ? t2 === 0 ? (e2 = ce(o4, r3 + 4, n3).times(0.5), e2.s = i3.s, e2) : new o4(NaN) : (o4.precision = r3 + 6, o4.rounding = 1, i3 = i3.div(new o4(1).minus(i3.times(i3)).sqrt().plus(1)).atan(), o4.precision = r3, o4.rounding = n3, i3.times(2)));
    };
    C3.inverseTangent = C3.atan = function() {
      var e2, t2, r3, n3, i3, o4, s4, a3, u3, l3 = this, g3 = l3.constructor, h2 = g3.precision, v3 = g3.rounding;
      if (l3.isFinite()) {
        if (l3.isZero())
          return new g3(l3);
        if (l3.abs().eq(1) && h2 + 4 <= xn)
          return s4 = ce(g3, h2 + 4, v3).times(0.25), s4.s = l3.s, s4;
      } else {
        if (!l3.s)
          return new g3(NaN);
        if (h2 + 4 <= xn)
          return s4 = ce(g3, h2 + 4, v3).times(0.5), s4.s = l3.s, s4;
      }
      for (g3.precision = a3 = h2 + 10, g3.rounding = 1, r3 = Math.min(28, a3 / O3 + 2 | 0), e2 = r3; e2; --e2)
        l3 = l3.div(l3.times(l3).plus(1).sqrt().plus(1));
      for (_4 = false, t2 = Math.ceil(a3 / O3), n3 = 1, u3 = l3.times(l3), s4 = new g3(l3), i3 = l3; e2 !== -1; )
        if (i3 = i3.times(u3), o4 = s4.minus(i3.div(n3 += 2)), i3 = i3.times(u3), s4 = o4.plus(i3.div(n3 += 2)), s4.d[t2] !== void 0)
          for (e2 = t2; s4.d[e2] === o4.d[e2] && e2--; )
            ;
      return r3 && (s4 = s4.times(2 << r3 - 1)), _4 = true, k3(s4, g3.precision = h2, g3.rounding = v3, true);
    };
    C3.isFinite = function() {
      return !!this.d;
    };
    C3.isInteger = C3.isInt = function() {
      return !!this.d && re(this.e / O3) > this.d.length - 2;
    };
    C3.isNaN = function() {
      return !this.s;
    };
    C3.isNegative = C3.isNeg = function() {
      return this.s < 0;
    };
    C3.isPositive = C3.isPos = function() {
      return this.s > 0;
    };
    C3.isZero = function() {
      return !!this.d && this.d[0] === 0;
    };
    C3.lessThan = C3.lt = function(e2) {
      return this.cmp(e2) < 0;
    };
    C3.lessThanOrEqualTo = C3.lte = function(e2) {
      return this.cmp(e2) < 1;
    };
    C3.logarithm = C3.log = function(e2) {
      var t2, r3, n3, i3, o4, s4, a3, u3, l3 = this, g3 = l3.constructor, h2 = g3.precision, v3 = g3.rounding, S2 = 5;
      if (e2 == null)
        e2 = new g3(10), t2 = true;
      else {
        if (e2 = new g3(e2), r3 = e2.d, e2.s < 0 || !r3 || !r3[0] || e2.eq(1))
          return new g3(NaN);
        t2 = e2.eq(10);
      }
      if (r3 = l3.d, l3.s < 0 || !r3 || !r3[0] || l3.eq(1))
        return new g3(r3 && !r3[0] ? -1 / 0 : l3.s != 1 ? NaN : r3 ? 0 : 1 / 0);
      if (t2)
        if (r3.length > 1)
          o4 = true;
        else {
          for (i3 = r3[0]; i3 % 10 === 0; )
            i3 /= 10;
          o4 = i3 !== 1;
        }
      if (_4 = false, a3 = h2 + S2, s4 = Oe(l3, a3), n3 = t2 ? br(g3, a3 + 10) : Oe(e2, a3), u3 = q(s4, n3, a3, 1), Bt(u3.d, i3 = h2, v3))
        do
          if (a3 += 10, s4 = Oe(l3, a3), n3 = t2 ? br(g3, a3 + 10) : Oe(e2, a3), u3 = q(s4, n3, a3, 1), !o4) {
            +X(u3.d).slice(i3 + 1, i3 + 15) + 1 == 1e14 && (u3 = k3(u3, h2 + 1, 0));
            break;
          }
        while (Bt(u3.d, i3 += 10, v3));
      return _4 = true, k3(u3, h2, v3);
    };
    C3.minus = C3.sub = function(e2) {
      var t2, r3, n3, i3, o4, s4, a3, u3, l3, g3, h2, v3, S2 = this, A2 = S2.constructor;
      if (e2 = new A2(e2), !S2.d || !e2.d)
        return !S2.s || !e2.s ? e2 = new A2(NaN) : S2.d ? e2.s = -e2.s : e2 = new A2(e2.d || S2.s !== e2.s ? S2 : NaN), e2;
      if (S2.s != e2.s)
        return e2.s = -e2.s, S2.plus(e2);
      if (l3 = S2.d, v3 = e2.d, a3 = A2.precision, u3 = A2.rounding, !l3[0] || !v3[0]) {
        if (v3[0])
          e2.s = -e2.s;
        else if (l3[0])
          e2 = new A2(S2);
        else
          return new A2(u3 === 3 ? -0 : 0);
        return _4 ? k3(e2, a3, u3) : e2;
      }
      if (r3 = re(e2.e / O3), g3 = re(S2.e / O3), l3 = l3.slice(), o4 = g3 - r3, o4) {
        for (h2 = o4 < 0, h2 ? (t2 = l3, o4 = -o4, s4 = v3.length) : (t2 = v3, r3 = g3, s4 = l3.length), n3 = Math.max(Math.ceil(a3 / O3), s4) + 2, o4 > n3 && (o4 = n3, t2.length = 1), t2.reverse(), n3 = o4; n3--; )
          t2.push(0);
        t2.reverse();
      } else {
        for (n3 = l3.length, s4 = v3.length, h2 = n3 < s4, h2 && (s4 = n3), n3 = 0; n3 < s4; n3++)
          if (l3[n3] != v3[n3]) {
            h2 = l3[n3] < v3[n3];
            break;
          }
        o4 = 0;
      }
      for (h2 && (t2 = l3, l3 = v3, v3 = t2, e2.s = -e2.s), s4 = l3.length, n3 = v3.length - s4; n3 > 0; --n3)
        l3[s4++] = 0;
      for (n3 = v3.length; n3 > o4; ) {
        if (l3[--n3] < v3[n3]) {
          for (i3 = n3; i3 && l3[--i3] === 0; )
            l3[i3] = pe - 1;
          --l3[i3], l3[n3] += pe;
        }
        l3[n3] -= v3[n3];
      }
      for (; l3[--s4] === 0; )
        l3.pop();
      for (; l3[0] === 0; l3.shift())
        --r3;
      return l3[0] ? (e2.d = l3, e2.e = Pr(l3, r3), _4 ? k3(e2, a3, u3) : e2) : new A2(u3 === 3 ? -0 : 0);
    };
    C3.modulo = C3.mod = function(e2) {
      var t2, r3 = this, n3 = r3.constructor;
      return e2 = new n3(e2), !r3.d || !e2.s || e2.d && !e2.d[0] ? new n3(NaN) : !e2.d || r3.d && !r3.d[0] ? k3(new n3(r3), n3.precision, n3.rounding) : (_4 = false, n3.modulo == 9 ? (t2 = q(r3, e2.abs(), 0, 3, 1), t2.s *= e2.s) : t2 = q(r3, e2, 0, n3.modulo, 1), t2 = t2.times(e2), _4 = true, r3.minus(t2));
    };
    C3.naturalExponential = C3.exp = function() {
      return Pn(this);
    };
    C3.naturalLogarithm = C3.ln = function() {
      return Oe(this);
    };
    C3.negated = C3.neg = function() {
      var e2 = new this.constructor(this);
      return e2.s = -e2.s, k3(e2);
    };
    C3.plus = C3.add = function(e2) {
      var t2, r3, n3, i3, o4, s4, a3, u3, l3, g3, h2 = this, v3 = h2.constructor;
      if (e2 = new v3(e2), !h2.d || !e2.d)
        return !h2.s || !e2.s ? e2 = new v3(NaN) : h2.d || (e2 = new v3(e2.d || h2.s === e2.s ? h2 : NaN)), e2;
      if (h2.s != e2.s)
        return e2.s = -e2.s, h2.minus(e2);
      if (l3 = h2.d, g3 = e2.d, a3 = v3.precision, u3 = v3.rounding, !l3[0] || !g3[0])
        return g3[0] || (e2 = new v3(h2)), _4 ? k3(e2, a3, u3) : e2;
      if (o4 = re(h2.e / O3), n3 = re(e2.e / O3), l3 = l3.slice(), i3 = o4 - n3, i3) {
        for (i3 < 0 ? (r3 = l3, i3 = -i3, s4 = g3.length) : (r3 = g3, n3 = o4, s4 = l3.length), o4 = Math.ceil(a3 / O3), s4 = o4 > s4 ? o4 + 1 : s4 + 1, i3 > s4 && (i3 = s4, r3.length = 1), r3.reverse(); i3--; )
          r3.push(0);
        r3.reverse();
      }
      for (s4 = l3.length, i3 = g3.length, s4 - i3 < 0 && (i3 = s4, r3 = g3, g3 = l3, l3 = r3), t2 = 0; i3; )
        t2 = (l3[--i3] = l3[i3] + g3[i3] + t2) / pe | 0, l3[i3] %= pe;
      for (t2 && (l3.unshift(t2), ++n3), s4 = l3.length; l3[--s4] == 0; )
        l3.pop();
      return e2.d = l3, e2.e = Pr(l3, n3), _4 ? k3(e2, a3, u3) : e2;
    };
    C3.precision = C3.sd = function(e2) {
      var t2, r3 = this;
      if (e2 !== void 0 && e2 !== !!e2 && e2 !== 1 && e2 !== 0)
        throw Error(Ne + e2);
      return r3.d ? (t2 = bo(r3.d), e2 && r3.e + 1 > t2 && (t2 = r3.e + 1)) : t2 = NaN, t2;
    };
    C3.round = function() {
      var e2 = this, t2 = e2.constructor;
      return k3(new t2(e2), e2.e + 1, t2.rounding);
    };
    C3.sine = C3.sin = function() {
      var e2, t2, r3 = this, n3 = r3.constructor;
      return r3.isFinite() ? r3.isZero() ? new n3(r3) : (e2 = n3.precision, t2 = n3.rounding, n3.precision = e2 + Math.max(r3.e, r3.sd()) + O3, n3.rounding = 1, r3 = wu(n3, To(n3, r3)), n3.precision = e2, n3.rounding = t2, k3(Ce > 2 ? r3.neg() : r3, e2, t2, true)) : new n3(NaN);
    };
    C3.squareRoot = C3.sqrt = function() {
      var e2, t2, r3, n3, i3, o4, s4 = this, a3 = s4.d, u3 = s4.e, l3 = s4.s, g3 = s4.constructor;
      if (l3 !== 1 || !a3 || !a3[0])
        return new g3(!l3 || l3 < 0 && (!a3 || a3[0]) ? NaN : a3 ? s4 : 1 / 0);
      for (_4 = false, l3 = Math.sqrt(+s4), l3 == 0 || l3 == 1 / 0 ? (t2 = X(a3), (t2.length + u3) % 2 == 0 && (t2 += "0"), l3 = Math.sqrt(t2), u3 = re((u3 + 1) / 2) - (u3 < 0 || u3 % 2), l3 == 1 / 0 ? t2 = "5e" + u3 : (t2 = l3.toExponential(), t2 = t2.slice(0, t2.indexOf("e") + 1) + u3), n3 = new g3(t2)) : n3 = new g3(l3.toString()), r3 = (u3 = g3.precision) + 3; ; )
        if (o4 = n3, n3 = o4.plus(q(s4, o4, r3 + 2, 1)).times(0.5), X(o4.d).slice(0, r3) === (t2 = X(n3.d)).slice(0, r3))
          if (t2 = t2.slice(r3 - 3, r3 + 1), t2 == "9999" || !i3 && t2 == "4999") {
            if (!i3 && (k3(o4, u3 + 1, 0), o4.times(o4).eq(s4))) {
              n3 = o4;
              break;
            }
            r3 += 4, i3 = 1;
          } else {
            (!+t2 || !+t2.slice(1) && t2.charAt(0) == "5") && (k3(n3, u3 + 1, 1), e2 = !n3.times(n3).eq(s4));
            break;
          }
      return _4 = true, k3(n3, u3, g3.rounding, e2);
    };
    C3.tangent = C3.tan = function() {
      var e2, t2, r3 = this, n3 = r3.constructor;
      return r3.isFinite() ? r3.isZero() ? new n3(r3) : (e2 = n3.precision, t2 = n3.rounding, n3.precision = e2 + 10, n3.rounding = 1, r3 = r3.sin(), r3.s = 1, r3 = q(r3, new n3(1).minus(r3.times(r3)).sqrt(), e2 + 10, 0), n3.precision = e2, n3.rounding = t2, k3(Ce == 2 || Ce == 4 ? r3.neg() : r3, e2, t2, true)) : new n3(NaN);
    };
    C3.times = C3.mul = function(e2) {
      var t2, r3, n3, i3, o4, s4, a3, u3, l3, g3 = this, h2 = g3.constructor, v3 = g3.d, S2 = (e2 = new h2(e2)).d;
      if (e2.s *= g3.s, !v3 || !v3[0] || !S2 || !S2[0])
        return new h2(!e2.s || v3 && !v3[0] && !S2 || S2 && !S2[0] && !v3 ? NaN : !v3 || !S2 ? e2.s / 0 : e2.s * 0);
      for (r3 = re(g3.e / O3) + re(e2.e / O3), u3 = v3.length, l3 = S2.length, u3 < l3 && (o4 = v3, v3 = S2, S2 = o4, s4 = u3, u3 = l3, l3 = s4), o4 = [], s4 = u3 + l3, n3 = s4; n3--; )
        o4.push(0);
      for (n3 = l3; --n3 >= 0; ) {
        for (t2 = 0, i3 = u3 + n3; i3 > n3; )
          a3 = o4[i3] + S2[n3] * v3[i3 - n3 - 1] + t2, o4[i3--] = a3 % pe | 0, t2 = a3 / pe | 0;
        o4[i3] = (o4[i3] + t2) % pe | 0;
      }
      for (; !o4[--s4]; )
        o4.pop();
      return t2 ? ++r3 : o4.shift(), e2.d = o4, e2.e = Pr(o4, r3), _4 ? k3(e2, h2.precision, h2.rounding) : e2;
    };
    C3.toBinary = function(e2, t2) {
      return Tn(this, 2, e2, t2);
    };
    C3.toDecimalPlaces = C3.toDP = function(e2, t2) {
      var r3 = this, n3 = r3.constructor;
      return r3 = new n3(r3), e2 === void 0 ? r3 : (ue(e2, 0, _e), t2 === void 0 ? t2 = n3.rounding : ue(t2, 0, 8), k3(r3, e2 + r3.e + 1, t2));
    };
    C3.toExponential = function(e2, t2) {
      var r3, n3 = this, i3 = n3.constructor;
      return e2 === void 0 ? r3 = he(n3, true) : (ue(e2, 0, _e), t2 === void 0 ? t2 = i3.rounding : ue(t2, 0, 8), n3 = k3(new i3(n3), e2 + 1, t2), r3 = he(n3, true, e2 + 1)), n3.isNeg() && !n3.isZero() ? "-" + r3 : r3;
    };
    C3.toFixed = function(e2, t2) {
      var r3, n3, i3 = this, o4 = i3.constructor;
      return e2 === void 0 ? r3 = he(i3) : (ue(e2, 0, _e), t2 === void 0 ? t2 = o4.rounding : ue(t2, 0, 8), n3 = k3(new o4(i3), e2 + i3.e + 1, t2), r3 = he(n3, false, e2 + n3.e + 1)), i3.isNeg() && !i3.isZero() ? "-" + r3 : r3;
    };
    C3.toFraction = function(e2) {
      var t2, r3, n3, i3, o4, s4, a3, u3, l3, g3, h2, v3, S2 = this, A2 = S2.d, R = S2.constructor;
      if (!A2)
        return new R(S2);
      if (l3 = r3 = new R(1), n3 = u3 = new R(0), t2 = new R(n3), o4 = t2.e = bo(A2) - S2.e - 1, s4 = o4 % O3, t2.d[0] = H2(10, s4 < 0 ? O3 + s4 : s4), e2 == null)
        e2 = o4 > 0 ? t2 : l3;
      else {
        if (a3 = new R(e2), !a3.isInt() || a3.lt(l3))
          throw Error(Ne + a3);
        e2 = a3.gt(t2) ? o4 > 0 ? t2 : l3 : a3;
      }
      for (_4 = false, a3 = new R(X(A2)), g3 = R.precision, R.precision = o4 = A2.length * O3 * 2; h2 = q(a3, t2, 0, 1, 1), i3 = r3.plus(h2.times(n3)), i3.cmp(e2) != 1; )
        r3 = n3, n3 = i3, i3 = l3, l3 = u3.plus(h2.times(i3)), u3 = i3, i3 = t2, t2 = a3.minus(h2.times(i3)), a3 = i3;
      return i3 = q(e2.minus(r3), n3, 0, 1, 1), u3 = u3.plus(i3.times(l3)), r3 = r3.plus(i3.times(n3)), u3.s = l3.s = S2.s, v3 = q(l3, n3, o4, 1).minus(S2).abs().cmp(q(u3, r3, o4, 1).minus(S2).abs()) < 1 ? [l3, n3] : [u3, r3], R.precision = g3, _4 = true, v3;
    };
    C3.toHexadecimal = C3.toHex = function(e2, t2) {
      return Tn(this, 16, e2, t2);
    };
    C3.toNearest = function(e2, t2) {
      var r3 = this, n3 = r3.constructor;
      if (r3 = new n3(r3), e2 == null) {
        if (!r3.d)
          return r3;
        e2 = new n3(1), t2 = n3.rounding;
      } else {
        if (e2 = new n3(e2), t2 === void 0 ? t2 = n3.rounding : ue(t2, 0, 8), !r3.d)
          return e2.s ? r3 : e2;
        if (!e2.d)
          return e2.s && (e2.s = r3.s), e2;
      }
      return e2.d[0] ? (_4 = false, r3 = q(r3, e2, 0, t2, 1).times(e2), _4 = true, k3(r3)) : (e2.s = r3.s, r3 = e2), r3;
    };
    C3.toNumber = function() {
      return +this;
    };
    C3.toOctal = function(e2, t2) {
      return Tn(this, 8, e2, t2);
    };
    C3.toPower = C3.pow = function(e2) {
      var t2, r3, n3, i3, o4, s4, a3 = this, u3 = a3.constructor, l3 = +(e2 = new u3(e2));
      if (!a3.d || !e2.d || !a3.d[0] || !e2.d[0])
        return new u3(H2(+a3, l3));
      if (a3 = new u3(a3), a3.eq(1))
        return a3;
      if (n3 = u3.precision, o4 = u3.rounding, e2.eq(1))
        return k3(a3, n3, o4);
      if (t2 = re(e2.e / O3), t2 >= e2.d.length - 1 && (r3 = l3 < 0 ? -l3 : l3) <= du)
        return i3 = xo(u3, a3, r3, n3), e2.s < 0 ? new u3(1).div(i3) : k3(i3, n3, o4);
      if (s4 = a3.s, s4 < 0) {
        if (t2 < e2.d.length - 1)
          return new u3(NaN);
        if (e2.d[t2] & 1 || (s4 = 1), a3.e == 0 && a3.d[0] == 1 && a3.d.length == 1)
          return a3.s = s4, a3;
      }
      return r3 = H2(+a3, l3), t2 = r3 == 0 || !isFinite(r3) ? re(l3 * (Math.log("0." + X(a3.d)) / Math.LN10 + a3.e + 1)) : new u3(r3 + "").e, t2 > u3.maxE + 1 || t2 < u3.minE - 1 ? new u3(t2 > 0 ? s4 / 0 : 0) : (_4 = false, u3.rounding = a3.s = 1, r3 = Math.min(12, (t2 + "").length), i3 = Pn(e2.times(Oe(a3, n3 + r3)), n3), i3.d && (i3 = k3(i3, n3 + 5, 1), Bt(i3.d, n3, o4) && (t2 = n3 + 10, i3 = k3(Pn(e2.times(Oe(a3, t2 + r3)), t2), t2 + 5, 1), +X(i3.d).slice(n3 + 1, n3 + 15) + 1 == 1e14 && (i3 = k3(i3, n3 + 1, 0)))), i3.s = s4, _4 = true, u3.rounding = o4, k3(i3, n3, o4));
    };
    C3.toPrecision = function(e2, t2) {
      var r3, n3 = this, i3 = n3.constructor;
      return e2 === void 0 ? r3 = he(n3, n3.e <= i3.toExpNeg || n3.e >= i3.toExpPos) : (ue(e2, 1, _e), t2 === void 0 ? t2 = i3.rounding : ue(t2, 0, 8), n3 = k3(new i3(n3), e2, t2), r3 = he(n3, e2 <= n3.e || n3.e <= i3.toExpNeg, e2)), n3.isNeg() && !n3.isZero() ? "-" + r3 : r3;
    };
    C3.toSignificantDigits = C3.toSD = function(e2, t2) {
      var r3 = this, n3 = r3.constructor;
      return e2 === void 0 ? (e2 = n3.precision, t2 = n3.rounding) : (ue(e2, 1, _e), t2 === void 0 ? t2 = n3.rounding : ue(t2, 0, 8)), k3(new n3(r3), e2, t2);
    };
    C3.toString = function() {
      var e2 = this, t2 = e2.constructor, r3 = he(e2, e2.e <= t2.toExpNeg || e2.e >= t2.toExpPos);
      return e2.isNeg() && !e2.isZero() ? "-" + r3 : r3;
    };
    C3.truncated = C3.trunc = function() {
      return k3(new this.constructor(this), this.e + 1, 1);
    };
    C3.valueOf = C3.toJSON = function() {
      var e2 = this, t2 = e2.constructor, r3 = he(e2, e2.e <= t2.toExpNeg || e2.e >= t2.toExpPos);
      return e2.isNeg() ? "-" + r3 : r3;
    };
    function X(e2) {
      var t2, r3, n3, i3 = e2.length - 1, o4 = "", s4 = e2[0];
      if (i3 > 0) {
        for (o4 += s4, t2 = 1; t2 < i3; t2++)
          n3 = e2[t2] + "", r3 = O3 - n3.length, r3 && (o4 += Me(r3)), o4 += n3;
        s4 = e2[t2], n3 = s4 + "", r3 = O3 - n3.length, r3 && (o4 += Me(r3));
      } else if (s4 === 0)
        return "0";
      for (; s4 % 10 === 0; )
        s4 /= 10;
      return o4 + s4;
    }
    function ue(e2, t2, r3) {
      if (e2 !== ~~e2 || e2 < t2 || e2 > r3)
        throw Error(Ne + e2);
    }
    function Bt(e2, t2, r3, n3) {
      var i3, o4, s4, a3;
      for (o4 = e2[0]; o4 >= 10; o4 /= 10)
        --t2;
      return --t2 < 0 ? (t2 += O3, i3 = 0) : (i3 = Math.ceil((t2 + 1) / O3), t2 %= O3), o4 = H2(10, O3 - t2), a3 = e2[i3] % o4 | 0, n3 == null ? t2 < 3 ? (t2 == 0 ? a3 = a3 / 100 | 0 : t2 == 1 && (a3 = a3 / 10 | 0), s4 = r3 < 4 && a3 == 99999 || r3 > 3 && a3 == 49999 || a3 == 5e4 || a3 == 0) : s4 = (r3 < 4 && a3 + 1 == o4 || r3 > 3 && a3 + 1 == o4 / 2) && (e2[i3 + 1] / o4 / 100 | 0) == H2(10, t2 - 2) - 1 || (a3 == o4 / 2 || a3 == 0) && (e2[i3 + 1] / o4 / 100 | 0) == 0 : t2 < 4 ? (t2 == 0 ? a3 = a3 / 1e3 | 0 : t2 == 1 ? a3 = a3 / 100 | 0 : t2 == 2 && (a3 = a3 / 10 | 0), s4 = (n3 || r3 < 4) && a3 == 9999 || !n3 && r3 > 3 && a3 == 4999) : s4 = ((n3 || r3 < 4) && a3 + 1 == o4 || !n3 && r3 > 3 && a3 + 1 == o4 / 2) && (e2[i3 + 1] / o4 / 1e3 | 0) == H2(10, t2 - 3) - 1, s4;
    }
    function yr(e2, t2, r3) {
      for (var n3, i3 = [0], o4, s4 = 0, a3 = e2.length; s4 < a3; ) {
        for (o4 = i3.length; o4--; )
          i3[o4] *= t2;
        for (i3[0] += En.indexOf(e2.charAt(s4++)), n3 = 0; n3 < i3.length; n3++)
          i3[n3] > r3 - 1 && (i3[n3 + 1] === void 0 && (i3[n3 + 1] = 0), i3[n3 + 1] += i3[n3] / r3 | 0, i3[n3] %= r3);
      }
      return i3.reverse();
    }
    function hu(e2, t2) {
      var r3, n3, i3;
      if (t2.isZero())
        return t2;
      n3 = t2.d.length, n3 < 32 ? (r3 = Math.ceil(n3 / 3), i3 = (1 / vr(4, r3)).toString()) : (r3 = 16, i3 = "2.3283064365386962890625e-10"), e2.precision += r3, t2 = pt(e2, 1, t2.times(i3), new e2(1));
      for (var o4 = r3; o4--; ) {
        var s4 = t2.times(t2);
        t2 = s4.times(s4).minus(s4).times(8).plus(1);
      }
      return e2.precision -= r3, t2;
    }
    var q = /* @__PURE__ */ function() {
      function e2(n3, i3, o4) {
        var s4, a3 = 0, u3 = n3.length;
        for (n3 = n3.slice(); u3--; )
          s4 = n3[u3] * i3 + a3, n3[u3] = s4 % o4 | 0, a3 = s4 / o4 | 0;
        return a3 && n3.unshift(a3), n3;
      }
      function t2(n3, i3, o4, s4) {
        var a3, u3;
        if (o4 != s4)
          u3 = o4 > s4 ? 1 : -1;
        else
          for (a3 = u3 = 0; a3 < o4; a3++)
            if (n3[a3] != i3[a3]) {
              u3 = n3[a3] > i3[a3] ? 1 : -1;
              break;
            }
        return u3;
      }
      function r3(n3, i3, o4, s4) {
        for (var a3 = 0; o4--; )
          n3[o4] -= a3, a3 = n3[o4] < i3[o4] ? 1 : 0, n3[o4] = a3 * s4 + n3[o4] - i3[o4];
        for (; !n3[0] && n3.length > 1; )
          n3.shift();
      }
      return function(n3, i3, o4, s4, a3, u3) {
        var l3, g3, h2, v3, S2, A2, R, D, M2, B, I2, L2, ee, F, Ze, $e, fe, qe, Q, Se, Ue = n3.constructor, Xe = n3.s == i3.s ? 1 : -1, te = n3.d, U = i3.d;
        if (!te || !te[0] || !U || !U[0])
          return new Ue(!n3.s || !i3.s || (te ? U && te[0] == U[0] : !U) ? NaN : te && te[0] == 0 || !U ? Xe * 0 : Xe / 0);
        for (u3 ? (S2 = 1, g3 = n3.e - i3.e) : (u3 = pe, S2 = O3, g3 = re(n3.e / S2) - re(i3.e / S2)), Q = U.length, fe = te.length, M2 = new Ue(Xe), B = M2.d = [], h2 = 0; U[h2] == (te[h2] || 0); h2++)
          ;
        if (U[h2] > (te[h2] || 0) && g3--, o4 == null ? (F = o4 = Ue.precision, s4 = Ue.rounding) : a3 ? F = o4 + (n3.e - i3.e) + 1 : F = o4, F < 0)
          B.push(1), A2 = true;
        else {
          if (F = F / S2 + 2 | 0, h2 = 0, Q == 1) {
            for (v3 = 0, U = U[0], F++; (h2 < fe || v3) && F--; h2++)
              Ze = v3 * u3 + (te[h2] || 0), B[h2] = Ze / U | 0, v3 = Ze % U | 0;
            A2 = v3 || h2 < fe;
          } else {
            for (v3 = u3 / (U[0] + 1) | 0, v3 > 1 && (U = e2(U, v3, u3), te = e2(te, v3, u3), Q = U.length, fe = te.length), $e = Q, I2 = te.slice(0, Q), L2 = I2.length; L2 < Q; )
              I2[L2++] = 0;
            Se = U.slice(), Se.unshift(0), qe = U[0], U[1] >= u3 / 2 && ++qe;
            do
              v3 = 0, l3 = t2(U, I2, Q, L2), l3 < 0 ? (ee = I2[0], Q != L2 && (ee = ee * u3 + (I2[1] || 0)), v3 = ee / qe | 0, v3 > 1 ? (v3 >= u3 && (v3 = u3 - 1), R = e2(U, v3, u3), D = R.length, L2 = I2.length, l3 = t2(R, I2, D, L2), l3 == 1 && (v3--, r3(R, Q < D ? Se : U, D, u3))) : (v3 == 0 && (l3 = v3 = 1), R = U.slice()), D = R.length, D < L2 && R.unshift(0), r3(I2, R, L2, u3), l3 == -1 && (L2 = I2.length, l3 = t2(U, I2, Q, L2), l3 < 1 && (v3++, r3(I2, Q < L2 ? Se : U, L2, u3))), L2 = I2.length) : l3 === 0 && (v3++, I2 = [0]), B[h2++] = v3, l3 && I2[0] ? I2[L2++] = te[$e] || 0 : (I2 = [te[$e]], L2 = 1);
            while (($e++ < fe || I2[0] !== void 0) && F--);
            A2 = I2[0] !== void 0;
          }
          B[0] || B.shift();
        }
        if (S2 == 1)
          M2.e = g3, go = A2;
        else {
          for (h2 = 1, v3 = B[0]; v3 >= 10; v3 /= 10)
            h2++;
          M2.e = h2 + g3 * S2 - 1, k3(M2, a3 ? o4 + M2.e + 1 : o4, s4, A2);
        }
        return M2;
      };
    }();
    function k3(e2, t2, r3, n3) {
      var i3, o4, s4, a3, u3, l3, g3, h2, v3, S2 = e2.constructor;
      e:
        if (t2 != null) {
          if (h2 = e2.d, !h2)
            return e2;
          for (i3 = 1, a3 = h2[0]; a3 >= 10; a3 /= 10)
            i3++;
          if (o4 = t2 - i3, o4 < 0)
            o4 += O3, s4 = t2, g3 = h2[v3 = 0], u3 = g3 / H2(10, i3 - s4 - 1) % 10 | 0;
          else if (v3 = Math.ceil((o4 + 1) / O3), a3 = h2.length, v3 >= a3)
            if (n3) {
              for (; a3++ <= v3; )
                h2.push(0);
              g3 = u3 = 0, i3 = 1, o4 %= O3, s4 = o4 - O3 + 1;
            } else
              break e;
          else {
            for (g3 = a3 = h2[v3], i3 = 1; a3 >= 10; a3 /= 10)
              i3++;
            o4 %= O3, s4 = o4 - O3 + i3, u3 = s4 < 0 ? 0 : g3 / H2(10, i3 - s4 - 1) % 10 | 0;
          }
          if (n3 = n3 || t2 < 0 || h2[v3 + 1] !== void 0 || (s4 < 0 ? g3 : g3 % H2(10, i3 - s4 - 1)), l3 = r3 < 4 ? (u3 || n3) && (r3 == 0 || r3 == (e2.s < 0 ? 3 : 2)) : u3 > 5 || u3 == 5 && (r3 == 4 || n3 || r3 == 6 && (o4 > 0 ? s4 > 0 ? g3 / H2(10, i3 - s4) : 0 : h2[v3 - 1]) % 10 & 1 || r3 == (e2.s < 0 ? 8 : 7)), t2 < 1 || !h2[0])
            return h2.length = 0, l3 ? (t2 -= e2.e + 1, h2[0] = H2(10, (O3 - t2 % O3) % O3), e2.e = -t2 || 0) : h2[0] = e2.e = 0, e2;
          if (o4 == 0 ? (h2.length = v3, a3 = 1, v3--) : (h2.length = v3 + 1, a3 = H2(10, O3 - o4), h2[v3] = s4 > 0 ? (g3 / H2(10, i3 - s4) % H2(10, s4) | 0) * a3 : 0), l3)
            for (; ; )
              if (v3 == 0) {
                for (o4 = 1, s4 = h2[0]; s4 >= 10; s4 /= 10)
                  o4++;
                for (s4 = h2[0] += a3, a3 = 1; s4 >= 10; s4 /= 10)
                  a3++;
                o4 != a3 && (e2.e++, h2[0] == pe && (h2[0] = 1));
                break;
              } else {
                if (h2[v3] += a3, h2[v3] != pe)
                  break;
                h2[v3--] = 0, a3 = 1;
              }
          for (o4 = h2.length; h2[--o4] === 0; )
            h2.pop();
        }
      return _4 && (e2.e > S2.maxE ? (e2.d = null, e2.e = NaN) : e2.e < S2.minE && (e2.e = 0, e2.d = [0])), e2;
    }
    function he(e2, t2, r3) {
      if (!e2.isFinite())
        return vo(e2);
      var n3, i3 = e2.e, o4 = X(e2.d), s4 = o4.length;
      return t2 ? (r3 && (n3 = r3 - s4) > 0 ? o4 = o4.charAt(0) + "." + o4.slice(1) + Me(n3) : s4 > 1 && (o4 = o4.charAt(0) + "." + o4.slice(1)), o4 = o4 + (e2.e < 0 ? "e" : "e+") + e2.e) : i3 < 0 ? (o4 = "0." + Me(-i3 - 1) + o4, r3 && (n3 = r3 - s4) > 0 && (o4 += Me(n3))) : i3 >= s4 ? (o4 += Me(i3 + 1 - s4), r3 && (n3 = r3 - i3 - 1) > 0 && (o4 = o4 + "." + Me(n3))) : ((n3 = i3 + 1) < s4 && (o4 = o4.slice(0, n3) + "." + o4.slice(n3)), r3 && (n3 = r3 - s4) > 0 && (i3 + 1 === s4 && (o4 += "."), o4 += Me(n3))), o4;
    }
    function Pr(e2, t2) {
      var r3 = e2[0];
      for (t2 *= O3; r3 >= 10; r3 /= 10)
        t2++;
      return t2;
    }
    function br(e2, t2, r3) {
      if (t2 > gu)
        throw _4 = true, r3 && (e2.precision = r3), Error(ho);
      return k3(new e2(wr), t2, 1, true);
    }
    function ce(e2, t2, r3) {
      if (t2 > xn)
        throw Error(ho);
      return k3(new e2(Er), t2, r3, true);
    }
    function bo(e2) {
      var t2 = e2.length - 1, r3 = t2 * O3 + 1;
      if (t2 = e2[t2], t2) {
        for (; t2 % 10 == 0; t2 /= 10)
          r3--;
        for (t2 = e2[0]; t2 >= 10; t2 /= 10)
          r3++;
      }
      return r3;
    }
    function Me(e2) {
      for (var t2 = ""; e2--; )
        t2 += "0";
      return t2;
    }
    function xo(e2, t2, r3, n3) {
      var i3, o4 = new e2(1), s4 = Math.ceil(n3 / O3 + 4);
      for (_4 = false; ; ) {
        if (r3 % 2 && (o4 = o4.times(t2), fo(o4.d, s4) && (i3 = true)), r3 = re(r3 / 2), r3 === 0) {
          r3 = o4.d.length - 1, i3 && o4.d[r3] === 0 && ++o4.d[r3];
          break;
        }
        t2 = t2.times(t2), fo(t2.d, s4);
      }
      return _4 = true, o4;
    }
    function po(e2) {
      return e2.d[e2.d.length - 1] & 1;
    }
    function Po(e2, t2, r3) {
      for (var n3, i3 = new e2(t2[0]), o4 = 0; ++o4 < t2.length; )
        if (n3 = new e2(t2[o4]), n3.s)
          i3[r3](n3) && (i3 = n3);
        else {
          i3 = n3;
          break;
        }
      return i3;
    }
    function Pn(e2, t2) {
      var r3, n3, i3, o4, s4, a3, u3, l3 = 0, g3 = 0, h2 = 0, v3 = e2.constructor, S2 = v3.rounding, A2 = v3.precision;
      if (!e2.d || !e2.d[0] || e2.e > 17)
        return new v3(e2.d ? e2.d[0] ? e2.s < 0 ? 0 : 1 / 0 : 1 : e2.s ? e2.s < 0 ? 0 : e2 : NaN);
      for (t2 == null ? (_4 = false, u3 = A2) : u3 = t2, a3 = new v3(0.03125); e2.e > -2; )
        e2 = e2.times(a3), h2 += 5;
      for (n3 = Math.log(H2(2, h2)) / Math.LN10 * 2 + 5 | 0, u3 += n3, r3 = o4 = s4 = new v3(1), v3.precision = u3; ; ) {
        if (o4 = k3(o4.times(e2), u3, 1), r3 = r3.times(++g3), a3 = s4.plus(q(o4, r3, u3, 1)), X(a3.d).slice(0, u3) === X(s4.d).slice(0, u3)) {
          for (i3 = h2; i3--; )
            s4 = k3(s4.times(s4), u3, 1);
          if (t2 == null)
            if (l3 < 3 && Bt(s4.d, u3 - n3, S2, l3))
              v3.precision = u3 += 10, r3 = o4 = a3 = new v3(1), g3 = 0, l3++;
            else
              return k3(s4, v3.precision = A2, S2, _4 = true);
          else
            return v3.precision = A2, s4;
        }
        s4 = a3;
      }
    }
    function Oe(e2, t2) {
      var r3, n3, i3, o4, s4, a3, u3, l3, g3, h2, v3, S2 = 1, A2 = 10, R = e2, D = R.d, M2 = R.constructor, B = M2.rounding, I2 = M2.precision;
      if (R.s < 0 || !D || !D[0] || !R.e && D[0] == 1 && D.length == 1)
        return new M2(D && !D[0] ? -1 / 0 : R.s != 1 ? NaN : D ? 0 : R);
      if (t2 == null ? (_4 = false, g3 = I2) : g3 = t2, M2.precision = g3 += A2, r3 = X(D), n3 = r3.charAt(0), Math.abs(o4 = R.e) < 15e14) {
        for (; n3 < 7 && n3 != 1 || n3 == 1 && r3.charAt(1) > 3; )
          R = R.times(e2), r3 = X(R.d), n3 = r3.charAt(0), S2++;
        o4 = R.e, n3 > 1 ? (R = new M2("0." + r3), o4++) : R = new M2(n3 + "." + r3.slice(1));
      } else
        return l3 = br(M2, g3 + 2, I2).times(o4 + ""), R = Oe(new M2(n3 + "." + r3.slice(1)), g3 - A2).plus(l3), M2.precision = I2, t2 == null ? k3(R, I2, B, _4 = true) : R;
      for (h2 = R, u3 = s4 = R = q(R.minus(1), R.plus(1), g3, 1), v3 = k3(R.times(R), g3, 1), i3 = 3; ; ) {
        if (s4 = k3(s4.times(v3), g3, 1), l3 = u3.plus(q(s4, new M2(i3), g3, 1)), X(l3.d).slice(0, g3) === X(u3.d).slice(0, g3))
          if (u3 = u3.times(2), o4 !== 0 && (u3 = u3.plus(br(M2, g3 + 2, I2).times(o4 + ""))), u3 = q(u3, new M2(S2), g3, 1), t2 == null)
            if (Bt(u3.d, g3 - A2, B, a3))
              M2.precision = g3 += A2, l3 = s4 = R = q(h2.minus(1), h2.plus(1), g3, 1), v3 = k3(R.times(R), g3, 1), i3 = a3 = 1;
            else
              return k3(u3, M2.precision = I2, B, _4 = true);
          else
            return M2.precision = I2, u3;
        u3 = l3, i3 += 2;
      }
    }
    function vo(e2) {
      return String(e2.s * e2.s / 0);
    }
    function vn(e2, t2) {
      var r3, n3, i3;
      for ((r3 = t2.indexOf(".")) > -1 && (t2 = t2.replace(".", "")), (n3 = t2.search(/e/i)) > 0 ? (r3 < 0 && (r3 = n3), r3 += +t2.slice(n3 + 1), t2 = t2.substring(0, n3)) : r3 < 0 && (r3 = t2.length), n3 = 0; t2.charCodeAt(n3) === 48; n3++)
        ;
      for (i3 = t2.length; t2.charCodeAt(i3 - 1) === 48; --i3)
        ;
      if (t2 = t2.slice(n3, i3), t2) {
        if (i3 -= n3, e2.e = r3 = r3 - n3 - 1, e2.d = [], n3 = (r3 + 1) % O3, r3 < 0 && (n3 += O3), n3 < i3) {
          for (n3 && e2.d.push(+t2.slice(0, n3)), i3 -= O3; n3 < i3; )
            e2.d.push(+t2.slice(n3, n3 += O3));
          t2 = t2.slice(n3), n3 = O3 - t2.length;
        } else
          n3 -= i3;
        for (; n3--; )
          t2 += "0";
        e2.d.push(+t2), _4 && (e2.e > e2.constructor.maxE ? (e2.d = null, e2.e = NaN) : e2.e < e2.constructor.minE && (e2.e = 0, e2.d = [0]));
      } else
        e2.e = 0, e2.d = [0];
      return e2;
    }
    function yu(e2, t2) {
      var r3, n3, i3, o4, s4, a3, u3, l3, g3;
      if (t2.indexOf("_") > -1) {
        if (t2 = t2.replace(/(\d)_(?=\d)/g, "$1"), Eo.test(t2))
          return vn(e2, t2);
      } else if (t2 === "Infinity" || t2 === "NaN")
        return +t2 || (e2.s = NaN), e2.e = NaN, e2.d = null, e2;
      if (fu.test(t2))
        r3 = 16, t2 = t2.toLowerCase();
      else if (pu.test(t2))
        r3 = 2;
      else if (mu.test(t2))
        r3 = 8;
      else
        throw Error(Ne + t2);
      for (o4 = t2.search(/p/i), o4 > 0 ? (u3 = +t2.slice(o4 + 1), t2 = t2.substring(2, o4)) : t2 = t2.slice(2), o4 = t2.indexOf("."), s4 = o4 >= 0, n3 = e2.constructor, s4 && (t2 = t2.replace(".", ""), a3 = t2.length, o4 = a3 - o4, i3 = xo(n3, new n3(r3), o4, o4 * 2)), l3 = yr(t2, r3, pe), g3 = l3.length - 1, o4 = g3; l3[o4] === 0; --o4)
        l3.pop();
      return o4 < 0 ? new n3(e2.s * 0) : (e2.e = Pr(l3, g3), e2.d = l3, _4 = false, s4 && (e2 = q(e2, i3, a3 * 4)), u3 && (e2 = e2.times(Math.abs(u3) < 54 ? H2(2, u3) : He.pow(2, u3))), _4 = true, e2);
    }
    function wu(e2, t2) {
      var r3, n3 = t2.d.length;
      if (n3 < 3)
        return t2.isZero() ? t2 : pt(e2, 2, t2, t2);
      r3 = 1.4 * Math.sqrt(n3), r3 = r3 > 16 ? 16 : r3 | 0, t2 = t2.times(1 / vr(5, r3)), t2 = pt(e2, 2, t2, t2);
      for (var i3, o4 = new e2(5), s4 = new e2(16), a3 = new e2(20); r3--; )
        i3 = t2.times(t2), t2 = t2.times(o4.plus(i3.times(s4.times(i3).minus(a3))));
      return t2;
    }
    function pt(e2, t2, r3, n3, i3) {
      var o4, s4, a3, u3, l3 = 1, g3 = e2.precision, h2 = Math.ceil(g3 / O3);
      for (_4 = false, u3 = r3.times(r3), a3 = new e2(n3); ; ) {
        if (s4 = q(a3.times(u3), new e2(t2++ * t2++), g3, 1), a3 = i3 ? n3.plus(s4) : n3.minus(s4), n3 = q(s4.times(u3), new e2(t2++ * t2++), g3, 1), s4 = a3.plus(n3), s4.d[h2] !== void 0) {
          for (o4 = h2; s4.d[o4] === a3.d[o4] && o4--; )
            ;
          if (o4 == -1)
            break;
        }
        o4 = a3, a3 = n3, n3 = s4, s4 = o4, l3++;
      }
      return _4 = true, s4.d.length = h2 + 1, s4;
    }
    function vr(e2, t2) {
      for (var r3 = e2; --t2; )
        r3 *= e2;
      return r3;
    }
    function To(e2, t2) {
      var r3, n3 = t2.s < 0, i3 = ce(e2, e2.precision, 1), o4 = i3.times(0.5);
      if (t2 = t2.abs(), t2.lte(o4))
        return Ce = n3 ? 4 : 1, t2;
      if (r3 = t2.divToInt(i3), r3.isZero())
        Ce = n3 ? 3 : 2;
      else {
        if (t2 = t2.minus(r3.times(i3)), t2.lte(o4))
          return Ce = po(r3) ? n3 ? 2 : 3 : n3 ? 4 : 1, t2;
        Ce = po(r3) ? n3 ? 1 : 4 : n3 ? 3 : 2;
      }
      return t2.minus(i3).abs();
    }
    function Tn(e2, t2, r3, n3) {
      var i3, o4, s4, a3, u3, l3, g3, h2, v3, S2 = e2.constructor, A2 = r3 !== void 0;
      if (A2 ? (ue(r3, 1, _e), n3 === void 0 ? n3 = S2.rounding : ue(n3, 0, 8)) : (r3 = S2.precision, n3 = S2.rounding), !e2.isFinite())
        g3 = vo(e2);
      else {
        for (g3 = he(e2), s4 = g3.indexOf("."), A2 ? (i3 = 2, t2 == 16 ? r3 = r3 * 4 - 3 : t2 == 8 && (r3 = r3 * 3 - 2)) : i3 = t2, s4 >= 0 && (g3 = g3.replace(".", ""), v3 = new S2(1), v3.e = g3.length - s4, v3.d = yr(he(v3), 10, i3), v3.e = v3.d.length), h2 = yr(g3, 10, i3), o4 = u3 = h2.length; h2[--u3] == 0; )
          h2.pop();
        if (!h2[0])
          g3 = A2 ? "0p+0" : "0";
        else {
          if (s4 < 0 ? o4-- : (e2 = new S2(e2), e2.d = h2, e2.e = o4, e2 = q(e2, v3, r3, n3, 0, i3), h2 = e2.d, o4 = e2.e, l3 = go), s4 = h2[r3], a3 = i3 / 2, l3 = l3 || h2[r3 + 1] !== void 0, l3 = n3 < 4 ? (s4 !== void 0 || l3) && (n3 === 0 || n3 === (e2.s < 0 ? 3 : 2)) : s4 > a3 || s4 === a3 && (n3 === 4 || l3 || n3 === 6 && h2[r3 - 1] & 1 || n3 === (e2.s < 0 ? 8 : 7)), h2.length = r3, l3)
            for (; ++h2[--r3] > i3 - 1; )
              h2[r3] = 0, r3 || (++o4, h2.unshift(1));
          for (u3 = h2.length; !h2[u3 - 1]; --u3)
            ;
          for (s4 = 0, g3 = ""; s4 < u3; s4++)
            g3 += En.charAt(h2[s4]);
          if (A2) {
            if (u3 > 1)
              if (t2 == 16 || t2 == 8) {
                for (s4 = t2 == 16 ? 4 : 3, --u3; u3 % s4; u3++)
                  g3 += "0";
                for (h2 = yr(g3, i3, t2), u3 = h2.length; !h2[u3 - 1]; --u3)
                  ;
                for (s4 = 1, g3 = "1."; s4 < u3; s4++)
                  g3 += En.charAt(h2[s4]);
              } else
                g3 = g3.charAt(0) + "." + g3.slice(1);
            g3 = g3 + (o4 < 0 ? "p" : "p+") + o4;
          } else if (o4 < 0) {
            for (; ++o4; )
              g3 = "0" + g3;
            g3 = "0." + g3;
          } else if (++o4 > u3)
            for (o4 -= u3; o4--; )
              g3 += "0";
          else
            o4 < u3 && (g3 = g3.slice(0, o4) + "." + g3.slice(o4));
        }
        g3 = (t2 == 16 ? "0x" : t2 == 2 ? "0b" : t2 == 8 ? "0o" : "") + g3;
      }
      return e2.s < 0 ? "-" + g3 : g3;
    }
    function fo(e2, t2) {
      if (e2.length > t2)
        return e2.length = t2, true;
    }
    function Eu(e2) {
      return new this(e2).abs();
    }
    function bu(e2) {
      return new this(e2).acos();
    }
    function xu(e2) {
      return new this(e2).acosh();
    }
    function Pu(e2, t2) {
      return new this(e2).plus(t2);
    }
    function vu(e2) {
      return new this(e2).asin();
    }
    function Tu(e2) {
      return new this(e2).asinh();
    }
    function Cu(e2) {
      return new this(e2).atan();
    }
    function Au(e2) {
      return new this(e2).atanh();
    }
    function Ru(e2, t2) {
      e2 = new this(e2), t2 = new this(t2);
      var r3, n3 = this.precision, i3 = this.rounding, o4 = n3 + 4;
      return !e2.s || !t2.s ? r3 = new this(NaN) : !e2.d && !t2.d ? (r3 = ce(this, o4, 1).times(t2.s > 0 ? 0.25 : 0.75), r3.s = e2.s) : !t2.d || e2.isZero() ? (r3 = t2.s < 0 ? ce(this, n3, i3) : new this(0), r3.s = e2.s) : !e2.d || t2.isZero() ? (r3 = ce(this, o4, 1).times(0.5), r3.s = e2.s) : t2.s < 0 ? (this.precision = o4, this.rounding = 1, r3 = this.atan(q(e2, t2, o4, 1)), t2 = ce(this, o4, 1), this.precision = n3, this.rounding = i3, r3 = e2.s < 0 ? r3.minus(t2) : r3.plus(t2)) : r3 = this.atan(q(e2, t2, o4, 1)), r3;
    }
    function Su(e2) {
      return new this(e2).cbrt();
    }
    function Iu(e2) {
      return k3(e2 = new this(e2), e2.e + 1, 2);
    }
    function ku(e2, t2, r3) {
      return new this(e2).clamp(t2, r3);
    }
    function Du(e2) {
      if (!e2 || typeof e2 != "object")
        throw Error(xr + "Object expected");
      var t2, r3, n3, i3 = e2.defaults === true, o4 = ["precision", 1, _e, "rounding", 0, 8, "toExpNeg", -ct, 0, "toExpPos", 0, ct, "maxE", 0, ct, "minE", -ct, 0, "modulo", 0, 9];
      for (t2 = 0; t2 < o4.length; t2 += 3)
        if (r3 = o4[t2], i3 && (this[r3] = bn[r3]), (n3 = e2[r3]) !== void 0)
          if (re(n3) === n3 && n3 >= o4[t2 + 1] && n3 <= o4[t2 + 2])
            this[r3] = n3;
          else
            throw Error(Ne + r3 + ": " + n3);
      if (r3 = "crypto", i3 && (this[r3] = bn[r3]), (n3 = e2[r3]) !== void 0)
        if (n3 === true || n3 === false || n3 === 0 || n3 === 1)
          if (n3)
            if (typeof crypto != "undefined" && crypto && (crypto.getRandomValues || crypto.randomBytes))
              this[r3] = true;
            else
              throw Error(yo);
          else
            this[r3] = false;
        else
          throw Error(Ne + r3 + ": " + n3);
      return this;
    }
    function Mu(e2) {
      return new this(e2).cos();
    }
    function Ou(e2) {
      return new this(e2).cosh();
    }
    function Co(e2) {
      var t2, r3, n3;
      function i3(o4) {
        var s4, a3, u3, l3 = this;
        if (!(l3 instanceof i3))
          return new i3(o4);
        if (l3.constructor = i3, mo(o4)) {
          l3.s = o4.s, _4 ? !o4.d || o4.e > i3.maxE ? (l3.e = NaN, l3.d = null) : o4.e < i3.minE ? (l3.e = 0, l3.d = [0]) : (l3.e = o4.e, l3.d = o4.d.slice()) : (l3.e = o4.e, l3.d = o4.d ? o4.d.slice() : o4.d);
          return;
        }
        if (u3 = typeof o4, u3 === "number") {
          if (o4 === 0) {
            l3.s = 1 / o4 < 0 ? -1 : 1, l3.e = 0, l3.d = [0];
            return;
          }
          if (o4 < 0 ? (o4 = -o4, l3.s = -1) : l3.s = 1, o4 === ~~o4 && o4 < 1e7) {
            for (s4 = 0, a3 = o4; a3 >= 10; a3 /= 10)
              s4++;
            _4 ? s4 > i3.maxE ? (l3.e = NaN, l3.d = null) : s4 < i3.minE ? (l3.e = 0, l3.d = [0]) : (l3.e = s4, l3.d = [o4]) : (l3.e = s4, l3.d = [o4]);
            return;
          } else if (o4 * 0 !== 0) {
            o4 || (l3.s = NaN), l3.e = NaN, l3.d = null;
            return;
          }
          return vn(l3, o4.toString());
        } else if (u3 !== "string")
          throw Error(Ne + o4);
        return (a3 = o4.charCodeAt(0)) === 45 ? (o4 = o4.slice(1), l3.s = -1) : (a3 === 43 && (o4 = o4.slice(1)), l3.s = 1), Eo.test(o4) ? vn(l3, o4) : yu(l3, o4);
      }
      if (i3.prototype = C3, i3.ROUND_UP = 0, i3.ROUND_DOWN = 1, i3.ROUND_CEIL = 2, i3.ROUND_FLOOR = 3, i3.ROUND_HALF_UP = 4, i3.ROUND_HALF_DOWN = 5, i3.ROUND_HALF_EVEN = 6, i3.ROUND_HALF_CEIL = 7, i3.ROUND_HALF_FLOOR = 8, i3.EUCLID = 9, i3.config = i3.set = Du, i3.clone = Co, i3.isDecimal = mo, i3.abs = Eu, i3.acos = bu, i3.acosh = xu, i3.add = Pu, i3.asin = vu, i3.asinh = Tu, i3.atan = Cu, i3.atanh = Au, i3.atan2 = Ru, i3.cbrt = Su, i3.ceil = Iu, i3.clamp = ku, i3.cos = Mu, i3.cosh = Ou, i3.div = Nu, i3.exp = _u, i3.floor = Lu, i3.hypot = Fu, i3.ln = Bu, i3.log = $u, i3.log10 = Uu, i3.log2 = qu, i3.max = Vu, i3.min = ju, i3.mod = Ju, i3.mul = Qu, i3.pow = Gu, i3.random = Hu, i3.round = Wu, i3.sign = Ku, i3.sin = zu, i3.sinh = Yu, i3.sqrt = Zu, i3.sub = Xu, i3.sum = el, i3.tan = tl, i3.tanh = rl, i3.trunc = nl, e2 === void 0 && (e2 = {}), e2 && e2.defaults !== true)
        for (n3 = ["precision", "rounding", "toExpNeg", "toExpPos", "maxE", "minE", "modulo", "crypto"], t2 = 0; t2 < n3.length; )
          e2.hasOwnProperty(r3 = n3[t2++]) || (e2[r3] = this[r3]);
      return i3.config(e2), i3;
    }
    function Nu(e2, t2) {
      return new this(e2).div(t2);
    }
    function _u(e2) {
      return new this(e2).exp();
    }
    function Lu(e2) {
      return k3(e2 = new this(e2), e2.e + 1, 3);
    }
    function Fu() {
      var e2, t2, r3 = new this(0);
      for (_4 = false, e2 = 0; e2 < arguments.length; )
        if (t2 = new this(arguments[e2++]), t2.d)
          r3.d && (r3 = r3.plus(t2.times(t2)));
        else {
          if (t2.s)
            return _4 = true, new this(1 / 0);
          r3 = t2;
        }
      return _4 = true, r3.sqrt();
    }
    function mo(e2) {
      return e2 instanceof He || e2 && e2.toStringTag === wo || false;
    }
    function Bu(e2) {
      return new this(e2).ln();
    }
    function $u(e2, t2) {
      return new this(e2).log(t2);
    }
    function qu(e2) {
      return new this(e2).log(2);
    }
    function Uu(e2) {
      return new this(e2).log(10);
    }
    function Vu() {
      return Po(this, arguments, "lt");
    }
    function ju() {
      return Po(this, arguments, "gt");
    }
    function Ju(e2, t2) {
      return new this(e2).mod(t2);
    }
    function Qu(e2, t2) {
      return new this(e2).mul(t2);
    }
    function Gu(e2, t2) {
      return new this(e2).pow(t2);
    }
    function Hu(e2) {
      var t2, r3, n3, i3, o4 = 0, s4 = new this(1), a3 = [];
      if (e2 === void 0 ? e2 = this.precision : ue(e2, 1, _e), n3 = Math.ceil(e2 / O3), this.crypto)
        if (crypto.getRandomValues)
          for (t2 = crypto.getRandomValues(new Uint32Array(n3)); o4 < n3; )
            i3 = t2[o4], i3 >= 429e7 ? t2[o4] = crypto.getRandomValues(new Uint32Array(1))[0] : a3[o4++] = i3 % 1e7;
        else if (crypto.randomBytes) {
          for (t2 = crypto.randomBytes(n3 *= 4); o4 < n3; )
            i3 = t2[o4] + (t2[o4 + 1] << 8) + (t2[o4 + 2] << 16) + ((t2[o4 + 3] & 127) << 24), i3 >= 214e7 ? crypto.randomBytes(4).copy(t2, o4) : (a3.push(i3 % 1e7), o4 += 4);
          o4 = n3 / 4;
        } else
          throw Error(yo);
      else
        for (; o4 < n3; )
          a3[o4++] = Math.random() * 1e7 | 0;
      for (n3 = a3[--o4], e2 %= O3, n3 && e2 && (i3 = H2(10, O3 - e2), a3[o4] = (n3 / i3 | 0) * i3); a3[o4] === 0; o4--)
        a3.pop();
      if (o4 < 0)
        r3 = 0, a3 = [0];
      else {
        for (r3 = -1; a3[0] === 0; r3 -= O3)
          a3.shift();
        for (n3 = 1, i3 = a3[0]; i3 >= 10; i3 /= 10)
          n3++;
        n3 < O3 && (r3 -= O3 - n3);
      }
      return s4.e = r3, s4.d = a3, s4;
    }
    function Wu(e2) {
      return k3(e2 = new this(e2), e2.e + 1, this.rounding);
    }
    function Ku(e2) {
      return e2 = new this(e2), e2.d ? e2.d[0] ? e2.s : 0 * e2.s : e2.s || NaN;
    }
    function zu(e2) {
      return new this(e2).sin();
    }
    function Yu(e2) {
      return new this(e2).sinh();
    }
    function Zu(e2) {
      return new this(e2).sqrt();
    }
    function Xu(e2, t2) {
      return new this(e2).sub(t2);
    }
    function el() {
      var e2 = 0, t2 = arguments, r3 = new this(t2[e2]);
      for (_4 = false; r3.s && ++e2 < t2.length; )
        r3 = r3.plus(t2[e2]);
      return _4 = true, k3(r3, this.precision, this.rounding);
    }
    function tl(e2) {
      return new this(e2).tan();
    }
    function rl(e2) {
      return new this(e2).tanh();
    }
    function nl(e2) {
      return k3(e2 = new this(e2), e2.e + 1, 1);
    }
    C3[Symbol.for("nodejs.util.inspect.custom")] = C3.toString;
    C3[Symbol.toStringTag] = "Decimal";
    var He = C3.constructor = Co(bn);
    wr = new He(wr);
    Er = new He(Er);
    var ye = He;
    function ft(e2) {
      return He.isDecimal(e2) ? true : e2 !== null && typeof e2 == "object" && typeof e2.s == "number" && typeof e2.e == "number" && typeof e2.toFixed == "function" && Array.isArray(e2.d);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var $t = class {
      constructor(t2, r3, n3, i3, o4) {
        this.modelName = t2, this.name = r3, this.typeName = n3, this.isList = i3, this.isEnum = o4;
      }
      _toGraphQLInputType() {
        let t2 = this.isList ? "List" : "", r3 = this.isEnum ? "Enum" : "";
        return `${t2}${r3}${this.typeName}FieldRefInput<${this.modelName}>`;
      }
    };
    function mt(e2) {
      return e2 instanceof $t;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var Tr = class {
      constructor(t2) {
        this.value = t2;
      }
      write(t2) {
        t2.write(this.value);
      }
      markAsError() {
        this.value.markAsError();
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var Cr = (e2) => e2;
    var Ar = { bold: Cr, red: Cr, green: Cr, dim: Cr, enabled: false };
    var Ao = { bold: ar, red: it, green: Ri, dim: ur, enabled: true };
    var dt = { write(e2) {
      e2.writeLine(",");
    } };
    d3();
    c3();
    p3();
    f3();
    m3();
    var we = class {
      constructor(t2) {
        this.contents = t2;
        this.isUnderlined = false;
        this.color = (t3) => t3;
      }
      underline() {
        return this.isUnderlined = true, this;
      }
      setColor(t2) {
        return this.color = t2, this;
      }
      write(t2) {
        let r3 = t2.getCurrentLineLength();
        t2.write(this.color(this.contents)), this.isUnderlined && t2.afterNextNewline(() => {
          t2.write(" ".repeat(r3)).writeLine(this.color("~".repeat(this.contents.length)));
        });
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var Le = class {
      constructor() {
        this.hasError = false;
      }
      markAsError() {
        return this.hasError = true, this;
      }
    };
    var gt = class extends Le {
      constructor() {
        super(...arguments);
        this.items = [];
      }
      addItem(r3) {
        return this.items.push(new Tr(r3)), this;
      }
      getField(r3) {
        return this.items[r3];
      }
      getPrintWidth() {
        return this.items.length === 0 ? 2 : Math.max(...this.items.map((n3) => n3.value.getPrintWidth())) + 2;
      }
      write(r3) {
        if (this.items.length === 0) {
          this.writeEmpty(r3);
          return;
        }
        this.writeWithItems(r3);
      }
      writeEmpty(r3) {
        let n3 = new we("[]");
        this.hasError && n3.setColor(r3.context.colors.red).underline(), r3.write(n3);
      }
      writeWithItems(r3) {
        let { colors: n3 } = r3.context;
        r3.writeLine("[").withIndent(() => r3.writeJoined(dt, this.items).newLine()).write("]"), this.hasError && r3.afterNextNewline(() => {
          r3.writeLine(n3.red("~".repeat(this.getPrintWidth())));
        });
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var Ro = ": ";
    var Rr = class {
      constructor(t2, r3) {
        this.name = t2;
        this.value = r3;
        this.hasError = false;
      }
      markAsError() {
        this.hasError = true;
      }
      getPrintWidth() {
        return this.name.length + this.value.getPrintWidth() + Ro.length;
      }
      write(t2) {
        let r3 = new we(this.name);
        this.hasError && r3.underline().setColor(t2.context.colors.red), t2.write(r3).write(Ro).write(this.value);
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var z2 = class e2 extends Le {
      constructor() {
        super(...arguments);
        this.fields = {};
        this.suggestions = [];
      }
      addField(r3) {
        this.fields[r3.name] = r3;
      }
      addSuggestion(r3) {
        this.suggestions.push(r3);
      }
      getField(r3) {
        return this.fields[r3];
      }
      getDeepField(r3) {
        let [n3, ...i3] = r3, o4 = this.getField(n3);
        if (!o4)
          return;
        let s4 = o4;
        for (let a3 of i3) {
          let u3;
          if (s4.value instanceof e2 ? u3 = s4.value.getField(a3) : s4.value instanceof gt && (u3 = s4.value.getField(Number(a3))), !u3)
            return;
          s4 = u3;
        }
        return s4;
      }
      getDeepFieldValue(r3) {
        var n3;
        return r3.length === 0 ? this : (n3 = this.getDeepField(r3)) == null ? void 0 : n3.value;
      }
      hasField(r3) {
        return !!this.getField(r3);
      }
      removeAllFields() {
        this.fields = {};
      }
      removeField(r3) {
        delete this.fields[r3];
      }
      getFields() {
        return this.fields;
      }
      isEmpty() {
        return Object.keys(this.fields).length === 0;
      }
      getFieldValue(r3) {
        var n3;
        return (n3 = this.getField(r3)) == null ? void 0 : n3.value;
      }
      getDeepSubSelectionValue(r3) {
        let n3 = this;
        for (let i3 of r3) {
          if (!(n3 instanceof e2))
            return;
          let o4 = n3.getSubSelectionValue(i3);
          if (!o4)
            return;
          n3 = o4;
        }
        return n3;
      }
      getDeepSelectionParent(r3) {
        let n3 = this.getSelectionParent();
        if (!n3)
          return;
        let i3 = n3;
        for (let o4 of r3) {
          let s4 = i3.value.getFieldValue(o4);
          if (!s4 || !(s4 instanceof e2))
            return;
          let a3 = s4.getSelectionParent();
          if (!a3)
            return;
          i3 = a3;
        }
        return i3;
      }
      getSelectionParent() {
        let r3 = this.getField("select");
        if ((r3 == null ? void 0 : r3.value) instanceof e2)
          return { kind: "select", value: r3.value };
        let n3 = this.getField("include");
        if ((n3 == null ? void 0 : n3.value) instanceof e2)
          return { kind: "include", value: n3.value };
      }
      getSubSelectionValue(r3) {
        var n3;
        return (n3 = this.getSelectionParent()) == null ? void 0 : n3.value.fields[r3].value;
      }
      getPrintWidth() {
        let r3 = Object.values(this.fields);
        return r3.length == 0 ? 2 : Math.max(...r3.map((i3) => i3.getPrintWidth())) + 2;
      }
      write(r3) {
        let n3 = Object.values(this.fields);
        if (n3.length === 0 && this.suggestions.length === 0) {
          this.writeEmpty(r3);
          return;
        }
        this.writeWithContents(r3, n3);
      }
      writeEmpty(r3) {
        let n3 = new we("{}");
        this.hasError && n3.setColor(r3.context.colors.red).underline(), r3.write(n3);
      }
      writeWithContents(r3, n3) {
        r3.writeLine("{").withIndent(() => {
          r3.writeJoined(dt, [...n3, ...this.suggestions]).newLine();
        }), r3.write("}"), this.hasError && r3.afterNextNewline(() => {
          r3.writeLine(r3.context.colors.red("~".repeat(this.getPrintWidth())));
        });
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var Y = class extends Le {
      constructor(r3) {
        super();
        this.text = r3;
      }
      getPrintWidth() {
        return this.text.length;
      }
      write(r3) {
        let n3 = new we(this.text);
        this.hasError && n3.underline().setColor(r3.context.colors.red), r3.write(n3);
      }
    };
    var Cn = class {
      constructor(t2) {
        this.errorMessages = [];
        this.arguments = t2;
      }
      write(t2) {
        t2.write(this.arguments);
      }
      addErrorMessage(t2) {
        this.errorMessages.push(t2);
      }
      renderAllMessages(t2) {
        return this.errorMessages.map((r3) => r3(t2)).join(`
`);
      }
    };
    function Sr(e2) {
      return new Cn(So(e2));
    }
    function So(e2) {
      let t2 = new z2();
      for (let [r3, n3] of Object.entries(e2)) {
        let i3 = new Rr(r3, Io(n3));
        t2.addField(i3);
      }
      return t2;
    }
    function Io(e2) {
      if (typeof e2 == "string")
        return new Y(JSON.stringify(e2));
      if (typeof e2 == "number" || typeof e2 == "boolean")
        return new Y(String(e2));
      if (typeof e2 == "bigint")
        return new Y(`${e2}n`);
      if (e2 === null)
        return new Y("null");
      if (e2 === void 0)
        return new Y("undefined");
      if (ft(e2))
        return new Y(`new Prisma.Decimal("${e2.toFixed()}")`);
      if (e2 instanceof Uint8Array)
        return w3.Buffer.isBuffer(e2) ? new Y(`Buffer.alloc(${e2.byteLength})`) : new Y(`new Uint8Array(${e2.byteLength})`);
      if (e2 instanceof Date) {
        let t2 = hr(e2) ? e2.toISOString() : "Invalid Date";
        return new Y(`new Date("${t2}")`);
      }
      return e2 instanceof Te ? new Y(`Prisma.${e2._getName()}`) : mt(e2) ? new Y(`prisma.${co(e2.modelName)}.$fields.${e2.name}`) : Array.isArray(e2) ? ol(e2) : typeof e2 == "object" ? So(e2) : new Y(Object.prototype.toString.call(e2));
    }
    function ol(e2) {
      let t2 = new gt();
      for (let r3 of e2)
        t2.addItem(Io(r3));
      return t2;
    }
    function ko(e2) {
      if (e2 === void 0)
        return "";
      let t2 = Sr(e2);
      return new ut(0, { colors: Ar }).write(t2).toString();
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var sl = "P2037";
    function qt({ error: e2, user_facing_error: t2 }, r3, n3) {
      return t2.error_code ? new K(al(t2, n3), { code: t2.error_code, clientVersion: r3, meta: t2.meta, batchRequestIdx: t2.batch_request_idx }) : new se(e2, { clientVersion: r3, batchRequestIdx: t2.batch_request_idx });
    }
    function al(e2, t2) {
      let r3 = e2.message;
      return (t2 === "postgresql" || t2 === "postgres" || t2 === "mysql") && e2.error_code === sl && (r3 += `
Prisma Accelerate has built-in connection pooling to prevent such errors: https://pris.ly/client/error-accelerate`), r3;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var An = class {
      getLocation() {
        return null;
      }
    };
    function Fe(e2) {
      return typeof $EnabledCallSite == "function" && e2 !== "minimal" ? new $EnabledCallSite() : new An();
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var Do = { _avg: true, _count: true, _sum: true, _min: true, _max: true };
    function ht(e2 = {}) {
      let t2 = ll(e2);
      return Object.entries(t2).reduce((n3, [i3, o4]) => (Do[i3] !== void 0 ? n3.select[i3] = { select: o4 } : n3[i3] = o4, n3), { select: {} });
    }
    function ll(e2 = {}) {
      return typeof e2._count == "boolean" ? { ...e2, _count: { _all: e2._count } } : e2;
    }
    function Ir(e2 = {}) {
      return (t2) => (typeof e2._count == "boolean" && (t2._count = t2._count._all), t2);
    }
    function Mo(e2, t2) {
      let r3 = Ir(e2);
      return t2({ action: "aggregate", unpacker: r3, argsMapper: ht })(e2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function cl(e2 = {}) {
      let { select: t2, ...r3 } = e2;
      return typeof t2 == "object" ? ht({ ...r3, _count: t2 }) : ht({ ...r3, _count: { _all: true } });
    }
    function pl(e2 = {}) {
      return typeof e2.select == "object" ? (t2) => Ir(e2)(t2)._count : (t2) => Ir(e2)(t2)._count._all;
    }
    function Oo(e2, t2) {
      return t2({ action: "count", unpacker: pl(e2), argsMapper: cl })(e2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function fl(e2 = {}) {
      let t2 = ht(e2);
      if (Array.isArray(t2.by))
        for (let r3 of t2.by)
          typeof r3 == "string" && (t2.select[r3] = true);
      else
        typeof t2.by == "string" && (t2.select[t2.by] = true);
      return t2;
    }
    function ml(e2 = {}) {
      return (t2) => (typeof (e2 == null ? void 0 : e2._count) == "boolean" && t2.forEach((r3) => {
        r3._count = r3._count._all;
      }), t2);
    }
    function No(e2, t2) {
      return t2({ action: "groupBy", unpacker: ml(e2), argsMapper: fl })(e2);
    }
    function _o(e2, t2, r3) {
      if (t2 === "aggregate")
        return (n3) => Mo(n3, r3);
      if (t2 === "count")
        return (n3) => Oo(n3, r3);
      if (t2 === "groupBy")
        return (n3) => No(n3, r3);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function Lo(e2, t2) {
      let r3 = t2.fields.filter((i3) => !i3.relationName), n3 = cn(r3, (i3) => i3.name);
      return new Proxy({}, { get(i3, o4) {
        if (o4 in i3 || typeof o4 == "symbol")
          return i3[o4];
        let s4 = n3[o4];
        if (s4)
          return new $t(e2, o4, s4.type, s4.isList, s4.kind === "enum");
      }, ...dr(Object.keys(n3)) });
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var Fo = (e2) => Array.isArray(e2) ? e2 : e2.split(".");
    var Rn = (e2, t2) => Fo(t2).reduce((r3, n3) => r3 && r3[n3], e2);
    var Bo = (e2, t2, r3) => Fo(t2).reduceRight((n3, i3, o4, s4) => Object.assign({}, Rn(e2, s4.slice(0, o4)), { [i3]: n3 }), r3);
    function dl(e2, t2) {
      return e2 === void 0 || t2 === void 0 ? [] : [...t2, "select", e2];
    }
    function gl(e2, t2, r3) {
      return t2 === void 0 ? e2 != null ? e2 : {} : Bo(t2, r3, e2 || true);
    }
    function Sn(e2, t2, r3, n3, i3, o4) {
      let a3 = e2._runtimeDataModel.models[t2].fields.reduce((u3, l3) => ({ ...u3, [l3.name]: l3 }), {});
      return (u3) => {
        let l3 = Fe(e2._errorFormat), g3 = dl(n3, i3), h2 = gl(u3, o4, g3), v3 = r3({ dataPath: g3, callsite: l3 })(h2), S2 = hl(e2, t2);
        return new Proxy(v3, { get(A2, R) {
          if (!S2.includes(R))
            return A2[R];
          let M2 = [a3[R].type, r3, R], B = [g3, h2];
          return Sn(e2, ...M2, ...B);
        }, ...dr([...S2, ...Object.getOwnPropertyNames(v3)]) });
      };
    }
    function hl(e2, t2) {
      return e2._runtimeDataModel.models[t2].fields.filter((r3) => r3.kind === "object").map((r3) => r3.name);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var yl = Ve(Ki());
    var wl = { red: it, gray: Di, dim: ur, bold: ar, underline: Ai, highlightSource: (e2) => e2.highlight() };
    var El = { red: (e2) => e2, gray: (e2) => e2, dim: (e2) => e2, bold: (e2) => e2, underline: (e2) => e2, highlightSource: (e2) => e2 };
    function bl({ message: e2, originalMethod: t2, isPanic: r3, callArguments: n3 }) {
      return { functionName: `prisma.${t2}()`, message: e2, isPanic: r3 != null ? r3 : false, callArguments: n3 };
    }
    function xl({ functionName: e2, location: t2, message: r3, isPanic: n3, contextLines: i3, callArguments: o4 }, s4) {
      let a3 = [""], u3 = t2 ? " in" : ":";
      if (n3 ? (a3.push(s4.red(`Oops, an unknown error occurred! This is ${s4.bold("on us")}, you did nothing wrong.`)), a3.push(s4.red(`It occurred in the ${s4.bold(`\`${e2}\``)} invocation${u3}`))) : a3.push(s4.red(`Invalid ${s4.bold(`\`${e2}\``)} invocation${u3}`)), t2 && a3.push(s4.underline(Pl(t2))), i3) {
        a3.push("");
        let l3 = [i3.toString()];
        o4 && (l3.push(o4), l3.push(s4.dim(")"))), a3.push(l3.join("")), o4 && a3.push("");
      } else
        a3.push(""), o4 && a3.push(o4), a3.push("");
      return a3.push(r3), a3.join(`
`);
    }
    function Pl(e2) {
      let t2 = [e2.fileName];
      return e2.lineNumber && t2.push(String(e2.lineNumber)), e2.columnNumber && t2.push(String(e2.columnNumber)), t2.join(":");
    }
    function yt(e2) {
      let t2 = e2.showColors ? wl : El, r3;
      return typeof $getTemplateParameters != "undefined" ? r3 = $getTemplateParameters(e2, t2) : r3 = bl(e2), xl(r3, t2);
    }
    function $o(e2, t2, r3, n3) {
      return e2 === De.ModelAction.findFirstOrThrow || e2 === De.ModelAction.findUniqueOrThrow ? vl(t2, r3, n3) : n3;
    }
    function vl(e2, t2, r3) {
      return async (n3) => {
        if ("rejectOnNotFound" in n3.args) {
          let o4 = yt({ originalMethod: n3.clientMethod, callsite: n3.callsite, message: "'rejectOnNotFound' option is not supported" });
          throw new Z(o4, { clientVersion: t2 });
        }
        return await r3(n3).catch((o4) => {
          throw o4 instanceof K && o4.code === "P2025" ? new Pe(`No ${e2} found`, t2) : o4;
        });
      };
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function Ee(e2) {
      return e2.replace(/^./, (t2) => t2.toLowerCase());
    }
    var Tl = ["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "create", "update", "upsert", "delete"];
    var Cl = ["aggregate", "count", "groupBy"];
    function In(e2, t2) {
      var i3;
      let r3 = (i3 = e2._extensions.getAllModelExtensions(t2)) != null ? i3 : {}, n3 = [Al(e2, t2), Sl(e2, t2), Lt(r3), ie("name", () => t2), ie("$name", () => t2), ie("$parent", () => e2._appliedParent)];
      return ge({}, n3);
    }
    function Al(e2, t2) {
      let r3 = Ee(t2), n3 = Object.keys(De.ModelAction).concat("count");
      return { getKeys() {
        return n3;
      }, getPropertyValue(i3) {
        let o4 = i3, s4 = (u3) => e2._request(u3);
        s4 = $o(o4, t2, e2._clientVersion, s4);
        let a3 = (u3) => (l3) => {
          let g3 = Fe(e2._errorFormat);
          return e2._createPrismaPromise((h2) => {
            let v3 = { args: l3, dataPath: [], action: o4, model: t2, clientMethod: `${r3}.${i3}`, jsModelName: r3, transaction: h2, callsite: g3 };
            return s4({ ...v3, ...u3 });
          });
        };
        return Tl.includes(o4) ? Sn(e2, t2, a3) : Rl(i3) ? _o(e2, i3, a3) : a3({});
      } };
    }
    function Rl(e2) {
      return Cl.includes(e2);
    }
    function Sl(e2, t2) {
      return Ge(ie("fields", () => {
        let r3 = e2._runtimeDataModel.models[t2];
        return Lo(t2, r3);
      }));
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function qo(e2) {
      return e2.replace(/^./, (t2) => t2.toUpperCase());
    }
    var kn = Symbol();
    function Ut(e2) {
      let t2 = [Il(e2), ie(kn, () => e2), ie("$parent", () => e2._appliedParent)], r3 = e2._extensions.getAllClientExtensions();
      return r3 && t2.push(Lt(r3)), ge(e2, t2);
    }
    function Il(e2) {
      let t2 = Object.keys(e2._runtimeDataModel.models), r3 = t2.map(Ee), n3 = [...new Set(t2.concat(r3))];
      return Ge({ getKeys() {
        return n3;
      }, getPropertyValue(i3) {
        let o4 = qo(i3);
        if (e2._runtimeDataModel.models[o4] !== void 0)
          return In(e2, o4);
        if (e2._runtimeDataModel.models[i3] !== void 0)
          return In(e2, i3);
      }, getPropertyDescriptor(i3) {
        if (!r3.includes(i3))
          return { enumerable: false };
      } });
    }
    function Uo(e2) {
      return e2[kn] ? e2[kn] : e2;
    }
    function Vo(e2) {
      var r3;
      if (typeof e2 == "function")
        return e2(this);
      if ((r3 = e2.client) != null && r3.__AccelerateEngine) {
        let n3 = e2.client.__AccelerateEngine;
        this._originalClient._engine = new n3(this._originalClient._accelerateEngineConfig);
      }
      let t2 = Object.create(this._originalClient, { _extensions: { value: this._extensions.append(e2) }, _appliedParent: { value: this, configurable: true }, $use: { value: void 0 }, $on: { value: void 0 } });
      return Ut(t2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function jo({ result: e2, modelName: t2, select: r3, extensions: n3 }) {
      let i3 = n3.getAllComputedFields(t2);
      if (!i3)
        return e2;
      let o4 = [], s4 = [];
      for (let a3 of Object.values(i3)) {
        if (r3) {
          if (!r3[a3.name])
            continue;
          let u3 = a3.needs.filter((l3) => !r3[l3]);
          u3.length > 0 && s4.push(Ft(u3));
        }
        kl(e2, a3.needs) && o4.push(Dl(a3, ge(e2, o4)));
      }
      return o4.length > 0 || s4.length > 0 ? ge(e2, [...o4, ...s4]) : e2;
    }
    function kl(e2, t2) {
      return t2.every((r3) => ln(e2, r3));
    }
    function Dl(e2, t2) {
      return Ge(ie(e2.name, () => e2.compute(t2)));
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function kr({ visitor: e2, result: t2, args: r3, runtimeDataModel: n3, modelName: i3 }) {
      var s4;
      if (Array.isArray(t2)) {
        for (let a3 = 0; a3 < t2.length; a3++)
          t2[a3] = kr({ result: t2[a3], args: r3, modelName: i3, runtimeDataModel: n3, visitor: e2 });
        return t2;
      }
      let o4 = (s4 = e2(t2, i3, r3)) != null ? s4 : t2;
      return r3.include && Jo({ includeOrSelect: r3.include, result: o4, parentModelName: i3, runtimeDataModel: n3, visitor: e2 }), r3.select && Jo({ includeOrSelect: r3.select, result: o4, parentModelName: i3, runtimeDataModel: n3, visitor: e2 }), o4;
    }
    function Jo({ includeOrSelect: e2, result: t2, parentModelName: r3, runtimeDataModel: n3, visitor: i3 }) {
      for (let [o4, s4] of Object.entries(e2)) {
        if (!s4 || t2[o4] == null)
          continue;
        let u3 = n3.models[r3].fields.find((g3) => g3.name === o4);
        if (!u3 || u3.kind !== "object" || !u3.relationName)
          continue;
        let l3 = typeof s4 == "object" ? s4 : {};
        t2[o4] = kr({ visitor: i3, result: t2[o4], args: l3, modelName: u3.type, runtimeDataModel: n3 });
      }
    }
    function Qo({ result: e2, modelName: t2, args: r3, extensions: n3, runtimeDataModel: i3 }) {
      return n3.isEmpty() || e2 == null || typeof e2 != "object" || !i3.models[t2] ? e2 : kr({ result: e2, args: r3 != null ? r3 : {}, modelName: t2, runtimeDataModel: i3, visitor: (s4, a3, u3) => jo({ result: s4, modelName: Ee(a3), select: u3.select, extensions: n3 }) });
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function Go(e2) {
      if (e2 instanceof ae)
        return Ml(e2);
      if (Array.isArray(e2)) {
        let r3 = [e2[0]];
        for (let n3 = 1; n3 < e2.length; n3++)
          r3[n3] = Vt(e2[n3]);
        return r3;
      }
      let t2 = {};
      for (let r3 in e2)
        t2[r3] = Vt(e2[r3]);
      return t2;
    }
    function Ml(e2) {
      return new ae(e2.strings, e2.values);
    }
    function Vt(e2) {
      if (typeof e2 != "object" || e2 == null || e2 instanceof Te || mt(e2))
        return e2;
      if (ft(e2))
        return new ye(e2.toFixed());
      if (lt(e2))
        return /* @__PURE__ */ new Date(+e2);
      if (ArrayBuffer.isView(e2))
        return e2.slice(0);
      if (Array.isArray(e2)) {
        let t2 = e2.length, r3;
        for (r3 = Array(t2); t2--; )
          r3[t2] = Vt(e2[t2]);
        return r3;
      }
      if (typeof e2 == "object") {
        let t2 = {};
        for (let r3 in e2)
          r3 === "__proto__" ? Object.defineProperty(t2, r3, { value: Vt(e2[r3]), configurable: true, enumerable: true, writable: true }) : t2[r3] = Vt(e2[r3]);
        return t2;
      }
      Je(e2, "Unknown value");
    }
    function Wo(e2, t2, r3, n3 = 0) {
      return e2._createPrismaPromise((i3) => {
        var s4, a3;
        let o4 = t2.customDataProxyFetch;
        return "transaction" in t2 && i3 !== void 0 && (((s4 = t2.transaction) == null ? void 0 : s4.kind) === "batch" && t2.transaction.lock.then(), t2.transaction = i3), n3 === r3.length ? e2._executeRequest(t2) : r3[n3]({ model: t2.model, operation: t2.model ? t2.action : t2.clientMethod, args: Go((a3 = t2.args) != null ? a3 : {}), __internalParams: t2, query: (u3, l3 = t2) => {
          let g3 = l3.customDataProxyFetch;
          return l3.customDataProxyFetch = Zo(o4, g3), l3.args = u3, Wo(e2, l3, r3, n3 + 1);
        } });
      });
    }
    function Ko(e2, t2) {
      let { jsModelName: r3, action: n3, clientMethod: i3 } = t2, o4 = r3 ? n3 : i3;
      if (e2._extensions.isEmpty())
        return e2._executeRequest(t2);
      let s4 = e2._extensions.getAllQueryCallbacks(r3 != null ? r3 : "$none", o4);
      return Wo(e2, t2, s4);
    }
    function zo(e2) {
      return (t2) => {
        let r3 = { requests: t2 }, n3 = t2[0].extensions.getAllBatchQueryCallbacks();
        return n3.length ? Yo(r3, n3, 0, e2) : e2(r3);
      };
    }
    function Yo(e2, t2, r3, n3) {
      if (r3 === t2.length)
        return n3(e2);
      let i3 = e2.customDataProxyFetch, o4 = e2.requests[0].transaction;
      return t2[r3]({ args: { queries: e2.requests.map((s4) => ({ model: s4.modelName, operation: s4.action, args: s4.args })), transaction: o4 ? { isolationLevel: o4.kind === "batch" ? o4.isolationLevel : void 0 } : void 0 }, __internalParams: e2, query(s4, a3 = e2) {
        let u3 = a3.customDataProxyFetch;
        return a3.customDataProxyFetch = Zo(i3, u3), Yo(a3, t2, r3 + 1, n3);
      } });
    }
    var Ho = (e2) => e2;
    function Zo(e2 = Ho, t2 = Ho) {
      return (r3) => e2(t2(r3));
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function es(e2, t2, r3) {
      let n3 = Ee(r3);
      return !t2.result || !(t2.result.$allModels || t2.result[n3]) ? e2 : Ol({ ...e2, ...Xo(t2.name, e2, t2.result.$allModels), ...Xo(t2.name, e2, t2.result[n3]) });
    }
    function Ol(e2) {
      let t2 = new de(), r3 = (n3, i3) => t2.getOrCreate(n3, () => i3.has(n3) ? [n3] : (i3.add(n3), e2[n3] ? e2[n3].needs.flatMap((o4) => r3(o4, i3)) : [n3]));
      return st(e2, (n3) => ({ ...n3, needs: r3(n3.name, /* @__PURE__ */ new Set()) }));
    }
    function Xo(e2, t2, r3) {
      return r3 ? st(r3, ({ needs: n3, compute: i3 }, o4) => ({ name: o4, needs: n3 ? Object.keys(n3).filter((s4) => n3[s4]) : [], compute: Nl(t2, o4, i3) })) : {};
    }
    function Nl(e2, t2, r3) {
      var i3;
      let n3 = (i3 = e2 == null ? void 0 : e2[t2]) == null ? void 0 : i3.compute;
      return n3 ? (o4) => r3({ ...o4, [t2]: n3(o4) }) : r3;
    }
    function ts(e2, t2) {
      if (!t2)
        return e2;
      let r3 = { ...e2 };
      for (let n3 of Object.values(t2))
        if (e2[n3.name])
          for (let i3 of n3.needs)
            r3[i3] = true;
      return r3;
    }
    var Dr = class {
      constructor(t2, r3) {
        this.extension = t2;
        this.previous = r3;
        this.computedFieldsCache = new de();
        this.modelExtensionsCache = new de();
        this.queryCallbacksCache = new de();
        this.clientExtensions = kt(() => {
          var t3, r4;
          return this.extension.client ? { ...(r4 = this.previous) == null ? void 0 : r4.getAllClientExtensions(), ...this.extension.client } : (t3 = this.previous) == null ? void 0 : t3.getAllClientExtensions();
        });
        this.batchCallbacks = kt(() => {
          var n3, i3, o4;
          let t3 = (i3 = (n3 = this.previous) == null ? void 0 : n3.getAllBatchQueryCallbacks()) != null ? i3 : [], r4 = (o4 = this.extension.query) == null ? void 0 : o4.$__internalBatch;
          return r4 ? t3.concat(r4) : t3;
        });
      }
      getAllComputedFields(t2) {
        return this.computedFieldsCache.getOrCreate(t2, () => {
          var r3;
          return es((r3 = this.previous) == null ? void 0 : r3.getAllComputedFields(t2), this.extension, t2);
        });
      }
      getAllClientExtensions() {
        return this.clientExtensions.get();
      }
      getAllModelExtensions(t2) {
        return this.modelExtensionsCache.getOrCreate(t2, () => {
          var n3, i3;
          let r3 = Ee(t2);
          return !this.extension.model || !(this.extension.model[r3] || this.extension.model.$allModels) ? (n3 = this.previous) == null ? void 0 : n3.getAllModelExtensions(t2) : { ...(i3 = this.previous) == null ? void 0 : i3.getAllModelExtensions(t2), ...this.extension.model.$allModels, ...this.extension.model[r3] };
        });
      }
      getAllQueryCallbacks(t2, r3) {
        return this.queryCallbacksCache.getOrCreate(`${t2}:${r3}`, () => {
          var s4, a3;
          let n3 = (a3 = (s4 = this.previous) == null ? void 0 : s4.getAllQueryCallbacks(t2, r3)) != null ? a3 : [], i3 = [], o4 = this.extension.query;
          return !o4 || !(o4[t2] || o4.$allModels || o4[r3] || o4.$allOperations) ? n3 : (o4[t2] !== void 0 && (o4[t2][r3] !== void 0 && i3.push(o4[t2][r3]), o4[t2].$allOperations !== void 0 && i3.push(o4[t2].$allOperations)), t2 !== "$none" && o4.$allModels !== void 0 && (o4.$allModels[r3] !== void 0 && i3.push(o4.$allModels[r3]), o4.$allModels.$allOperations !== void 0 && i3.push(o4.$allModels.$allOperations)), o4[r3] !== void 0 && i3.push(o4[r3]), o4.$allOperations !== void 0 && i3.push(o4.$allOperations), n3.concat(i3));
        });
      }
      getAllBatchQueryCallbacks() {
        return this.batchCallbacks.get();
      }
    };
    var Mr = class e2 {
      constructor(t2) {
        this.head = t2;
      }
      static empty() {
        return new e2();
      }
      static single(t2) {
        return new e2(new Dr(t2));
      }
      isEmpty() {
        return this.head === void 0;
      }
      append(t2) {
        return new e2(new Dr(t2, this.head));
      }
      getAllComputedFields(t2) {
        var r3;
        return (r3 = this.head) == null ? void 0 : r3.getAllComputedFields(t2);
      }
      getAllClientExtensions() {
        var t2;
        return (t2 = this.head) == null ? void 0 : t2.getAllClientExtensions();
      }
      getAllModelExtensions(t2) {
        var r3;
        return (r3 = this.head) == null ? void 0 : r3.getAllModelExtensions(t2);
      }
      getAllQueryCallbacks(t2, r3) {
        var n3, i3;
        return (i3 = (n3 = this.head) == null ? void 0 : n3.getAllQueryCallbacks(t2, r3)) != null ? i3 : [];
      }
      getAllBatchQueryCallbacks() {
        var t2, r3;
        return (r3 = (t2 = this.head) == null ? void 0 : t2.getAllBatchQueryCallbacks()) != null ? r3 : [];
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var rs = ne("prisma:client");
    var ns = { Vercel: "vercel", "Netlify CI": "netlify" };
    function is({ postinstall: e2, ciName: t2, clientVersion: r3 }) {
      if (rs("checkPlatformCaching:postinstall", e2), rs("checkPlatformCaching:ciName", t2), e2 === true && t2 && t2 in ns) {
        let n3 = `Prisma has detected that this project was built on ${t2}, which caches dependencies. This leads to an outdated Prisma Client because Prisma's auto-generation isn't triggered. To fix this, make sure to run the \`prisma generate\` command during the build process.

Learn how: https://pris.ly/d/${ns[t2]}-build`;
        throw console.error(n3), new G(n3, r3);
      }
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function os(e2, t2) {
      return e2 ? e2.datasources ? e2.datasources : e2.datasourceUrl ? { [t2[0]]: { url: e2.datasourceUrl } } : {} : {};
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var _l = "Cloudflare-Workers";
    var Ll = "node";
    function ss() {
      var e2, t2, r3;
      return typeof Netlify == "object" ? "netlify" : typeof EdgeRuntime == "string" ? "edge-light" : ((e2 = globalThis.navigator) == null ? void 0 : e2.userAgent) === _l ? "workerd" : globalThis.Deno ? "deno" : globalThis.__lagon__ ? "lagon" : ((r3 = (t2 = globalThis.process) == null ? void 0 : t2.release) == null ? void 0 : r3.name) === Ll ? "node" : globalThis.Bun ? "bun" : globalThis.fastly ? "fastly" : "unknown";
    }
    var Fl = { node: "Node.js", workerd: "Cloudflare Workers", deno: "Deno and Deno Deploy", netlify: "Netlify Edge Functions", "edge-light": "Vercel Edge Functions or Edge Middleware" };
    function Or() {
      let e2 = ss();
      return { id: e2, prettyName: Fl[e2] || e2, isEdge: ["workerd", "deno", "netlify", "edge-light"].includes(e2) };
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function wt({ inlineDatasources: e2, overrideDatasources: t2, env: r3, clientVersion: n3 }) {
      var u3, l3;
      let i3, o4 = Object.keys(e2)[0], s4 = (u3 = e2[o4]) == null ? void 0 : u3.url, a3 = (l3 = t2[o4]) == null ? void 0 : l3.url;
      if (o4 === void 0 ? i3 = void 0 : a3 ? i3 = a3 : s4 != null && s4.value ? i3 = s4.value : s4 != null && s4.fromEnvVar && (i3 = r3[s4.fromEnvVar]), (s4 == null ? void 0 : s4.fromEnvVar) !== void 0 && i3 === void 0)
        throw Or().id === "workerd" ? new G(`error: Environment variable not found: ${s4.fromEnvVar}.

In Cloudflare module Workers, environment variables are available only in the Worker's \`env\` parameter of \`fetch\`.
To solve this, provide the connection string directly: https://pris.ly/d/cloudflare-datasource-url`, n3) : new G(`error: Environment variable not found: ${s4.fromEnvVar}.`, n3);
      if (i3 === void 0)
        throw new G("error: Missing URL environment variable, value, or override.", n3);
      return i3;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var Nr = class extends Error {
      constructor(t2, r3) {
        super(t2), this.clientVersion = r3.clientVersion, this.cause = r3.cause;
      }
      get [Symbol.toStringTag]() {
        return this.name;
      }
    };
    var le = class extends Nr {
      constructor(t2, r3) {
        var n3;
        super(t2, r3), this.isRetryable = (n3 = r3.isRetryable) != null ? n3 : true;
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    function $2(e2, t2) {
      return { ...e2, isRetryable: t2 };
    }
    var Et = class extends le {
      constructor(r3) {
        super("This request must be retried", $2(r3, true));
        this.name = "ForcedRetryError";
        this.code = "P5001";
      }
    };
    N2(Et, "ForcedRetryError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var We = class extends le {
      constructor(r3, n3) {
        super(r3, $2(n3, false));
        this.name = "InvalidDatasourceError";
        this.code = "P6001";
      }
    };
    N2(We, "InvalidDatasourceError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Ke = class extends le {
      constructor(r3, n3) {
        super(r3, $2(n3, false));
        this.name = "NotImplementedYetError";
        this.code = "P5004";
      }
    };
    N2(Ke, "NotImplementedYetError");
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var j3 = class extends le {
      constructor(t2, r3) {
        super(t2, r3), this.response = r3.response;
        let n3 = this.response.headers.get("prisma-request-id");
        if (n3) {
          let i3 = `(The request id was: ${n3})`;
          this.message = this.message + " " + i3;
        }
      }
    };
    var ze = class extends j3 {
      constructor(r3) {
        super("Schema needs to be uploaded", $2(r3, true));
        this.name = "SchemaMissingError";
        this.code = "P5005";
      }
    };
    N2(ze, "SchemaMissingError");
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var Dn = "This request could not be understood by the server";
    var jt = class extends j3 {
      constructor(r3, n3, i3) {
        super(n3 || Dn, $2(r3, false));
        this.name = "BadRequestError";
        this.code = "P5000";
        i3 && (this.code = i3);
      }
    };
    N2(jt, "BadRequestError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Jt = class extends j3 {
      constructor(r3, n3) {
        super("Engine not started: healthcheck timeout", $2(r3, true));
        this.name = "HealthcheckTimeoutError";
        this.code = "P5013";
        this.logs = n3;
      }
    };
    N2(Jt, "HealthcheckTimeoutError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Qt = class extends j3 {
      constructor(r3, n3, i3) {
        super(n3, $2(r3, true));
        this.name = "EngineStartupError";
        this.code = "P5014";
        this.logs = i3;
      }
    };
    N2(Qt, "EngineStartupError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Gt = class extends j3 {
      constructor(r3) {
        super("Engine version is not supported", $2(r3, false));
        this.name = "EngineVersionNotSupportedError";
        this.code = "P5012";
      }
    };
    N2(Gt, "EngineVersionNotSupportedError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Mn = "Request timed out";
    var Ht = class extends j3 {
      constructor(r3, n3 = Mn) {
        super(n3, $2(r3, false));
        this.name = "GatewayTimeoutError";
        this.code = "P5009";
      }
    };
    N2(Ht, "GatewayTimeoutError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Bl = "Interactive transaction error";
    var Wt = class extends j3 {
      constructor(r3, n3 = Bl) {
        super(n3, $2(r3, false));
        this.name = "InteractiveTransactionError";
        this.code = "P5015";
      }
    };
    N2(Wt, "InteractiveTransactionError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var $l = "Request parameters are invalid";
    var Kt = class extends j3 {
      constructor(r3, n3 = $l) {
        super(n3, $2(r3, false));
        this.name = "InvalidRequestError";
        this.code = "P5011";
      }
    };
    N2(Kt, "InvalidRequestError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var On = "Requested resource does not exist";
    var zt = class extends j3 {
      constructor(r3, n3 = On) {
        super(n3, $2(r3, false));
        this.name = "NotFoundError";
        this.code = "P5003";
      }
    };
    N2(zt, "NotFoundError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Nn = "Unknown server error";
    var bt = class extends j3 {
      constructor(r3, n3, i3) {
        super(n3 || Nn, $2(r3, true));
        this.name = "ServerError";
        this.code = "P5006";
        this.logs = i3;
      }
    };
    N2(bt, "ServerError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var _n = "Unauthorized, check your connection string";
    var Yt = class extends j3 {
      constructor(r3, n3 = _n) {
        super(n3, $2(r3, false));
        this.name = "UnauthorizedError";
        this.code = "P5007";
      }
    };
    N2(Yt, "UnauthorizedError");
    d3();
    c3();
    p3();
    f3();
    m3();
    var Ln = "Usage exceeded, retry again later";
    var Zt = class extends j3 {
      constructor(r3, n3 = Ln) {
        super(n3, $2(r3, true));
        this.name = "UsageExceededError";
        this.code = "P5008";
      }
    };
    N2(Zt, "UsageExceededError");
    async function ql(e2) {
      let t2;
      try {
        t2 = await e2.text();
      } catch (r3) {
        return { type: "EmptyError" };
      }
      try {
        let r3 = JSON.parse(t2);
        if (typeof r3 == "string")
          switch (r3) {
            case "InternalDataProxyError":
              return { type: "DataProxyError", body: r3 };
            default:
              return { type: "UnknownTextError", body: r3 };
          }
        if (typeof r3 == "object" && r3 !== null) {
          if ("is_panic" in r3 && "message" in r3 && "error_code" in r3)
            return { type: "QueryEngineError", body: r3 };
          if ("EngineNotStarted" in r3 || "InteractiveTransactionMisrouted" in r3 || "InvalidRequestError" in r3) {
            let n3 = Object.values(r3)[0].reason;
            return typeof n3 == "string" && !["SchemaMissing", "EngineVersionNotSupported"].includes(n3) ? { type: "UnknownJsonError", body: r3 } : { type: "DataProxyError", body: r3 };
          }
        }
        return { type: "UnknownJsonError", body: r3 };
      } catch (r3) {
        return t2 === "" ? { type: "EmptyError" } : { type: "UnknownTextError", body: t2 };
      }
    }
    async function Xt(e2, t2) {
      if (e2.ok)
        return;
      let r3 = { clientVersion: t2, response: e2 }, n3 = await ql(e2);
      if (n3.type === "QueryEngineError")
        throw new K(n3.body.message, { code: n3.body.error_code, clientVersion: t2 });
      if (n3.type === "DataProxyError") {
        if (n3.body === "InternalDataProxyError")
          throw new bt(r3, "Internal Data Proxy error");
        if ("EngineNotStarted" in n3.body) {
          if (n3.body.EngineNotStarted.reason === "SchemaMissing")
            return new ze(r3);
          if (n3.body.EngineNotStarted.reason === "EngineVersionNotSupported")
            throw new Gt(r3);
          if ("EngineStartupError" in n3.body.EngineNotStarted.reason) {
            let { msg: i3, logs: o4 } = n3.body.EngineNotStarted.reason.EngineStartupError;
            throw new Qt(r3, i3, o4);
          }
          if ("KnownEngineStartupError" in n3.body.EngineNotStarted.reason) {
            let { msg: i3, error_code: o4 } = n3.body.EngineNotStarted.reason.KnownEngineStartupError;
            throw new G(i3, t2, o4);
          }
          if ("HealthcheckTimeout" in n3.body.EngineNotStarted.reason) {
            let { logs: i3 } = n3.body.EngineNotStarted.reason.HealthcheckTimeout;
            throw new Jt(r3, i3);
          }
        }
        if ("InteractiveTransactionMisrouted" in n3.body) {
          let i3 = { IDParseError: "Could not parse interactive transaction ID", NoQueryEngineFoundError: "Could not find Query Engine for the specified host and transaction ID", TransactionStartError: "Could not start interactive transaction" };
          throw new Wt(r3, i3[n3.body.InteractiveTransactionMisrouted.reason]);
        }
        if ("InvalidRequestError" in n3.body)
          throw new Kt(r3, n3.body.InvalidRequestError.reason);
      }
      if (e2.status === 401 || e2.status === 403)
        throw new Yt(r3, xt(_n, n3));
      if (e2.status === 404)
        return new zt(r3, xt(On, n3));
      if (e2.status === 429)
        throw new Zt(r3, xt(Ln, n3));
      if (e2.status === 504)
        throw new Ht(r3, xt(Mn, n3));
      if (e2.status >= 500)
        throw new bt(r3, xt(Nn, n3));
      if (e2.status >= 400)
        throw new jt(r3, xt(Dn, n3));
    }
    function xt(e2, t2) {
      return t2.type === "EmptyError" ? e2 : `${e2}: ${JSON.stringify(t2)}`;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function as(e2) {
      let t2 = Math.pow(2, e2) * 50, r3 = Math.ceil(Math.random() * t2) - Math.ceil(t2 / 2), n3 = t2 + r3;
      return new Promise((i3) => setTimeout(() => i3(n3), n3));
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var Ae = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    function us(e2) {
      let t2 = new TextEncoder().encode(e2), r3 = "", n3 = t2.byteLength, i3 = n3 % 3, o4 = n3 - i3, s4, a3, u3, l3, g3;
      for (let h2 = 0; h2 < o4; h2 = h2 + 3)
        g3 = t2[h2] << 16 | t2[h2 + 1] << 8 | t2[h2 + 2], s4 = (g3 & 16515072) >> 18, a3 = (g3 & 258048) >> 12, u3 = (g3 & 4032) >> 6, l3 = g3 & 63, r3 += Ae[s4] + Ae[a3] + Ae[u3] + Ae[l3];
      return i3 == 1 ? (g3 = t2[o4], s4 = (g3 & 252) >> 2, a3 = (g3 & 3) << 4, r3 += Ae[s4] + Ae[a3] + "==") : i3 == 2 && (g3 = t2[o4] << 8 | t2[o4 + 1], s4 = (g3 & 64512) >> 10, a3 = (g3 & 1008) >> 4, u3 = (g3 & 15) << 2, r3 += Ae[s4] + Ae[a3] + Ae[u3] + "="), r3;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function ls(e2) {
      var r3;
      if (!!((r3 = e2.generator) != null && r3.previewFeatures.some((n3) => n3.toLowerCase().includes("metrics"))))
        throw new G("The `metrics` preview feature is not yet available with Accelerate.\nPlease remove `metrics` from the `previewFeatures` in your schema.\n\nMore information about Accelerate: https://pris.ly/d/accelerate", e2.clientVersion);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function Ul(e2) {
      return e2[0] * 1e3 + e2[1] / 1e6;
    }
    function cs(e2) {
      return new Date(Ul(e2));
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var ps = { "@prisma/debug": "workspace:*", "@prisma/engines-version": "5.11.0-15.efd2449663b3d73d637ea1fd226bafbcf45b3102", "@prisma/fetch-engine": "workspace:*", "@prisma/get-platform": "workspace:*" };
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var er = class extends le {
      constructor(r3, n3) {
        super(`Cannot fetch data from service:
${r3}`, $2(n3, true));
        this.name = "RequestError";
        this.code = "P5010";
      }
    };
    N2(er, "RequestError");
    async function Ye(e2, t2, r3 = (n3) => n3) {
      var i3;
      let n3 = t2.clientVersion;
      try {
        return typeof fetch == "function" ? await r3(fetch)(e2, t2) : await r3(Fn)(e2, t2);
      } catch (o4) {
        let s4 = (i3 = o4.message) != null ? i3 : "Unknown error";
        throw new er(s4, { clientVersion: n3 });
      }
    }
    function jl(e2) {
      return { ...e2.headers, "Content-Type": "application/json" };
    }
    function Jl(e2) {
      return { method: e2.method, headers: jl(e2) };
    }
    function Ql(e2, t2) {
      return { text: () => Promise.resolve(w3.Buffer.concat(e2).toString()), json: () => Promise.resolve().then(() => JSON.parse(w3.Buffer.concat(e2).toString())), ok: t2.statusCode >= 200 && t2.statusCode <= 299, status: t2.statusCode, url: t2.url, headers: new Bn(t2.headers) };
    }
    async function Fn(e2, t2 = {}) {
      let r3 = Gl("https"), n3 = Jl(t2), i3 = [], { origin: o4 } = new URL(e2);
      return new Promise((s4, a3) => {
        var l3;
        let u3 = r3.request(e2, n3, (g3) => {
          let { statusCode: h2, headers: { location: v3 } } = g3;
          h2 >= 301 && h2 <= 399 && v3 && (v3.startsWith("http") === false ? s4(Fn(`${o4}${v3}`, t2)) : s4(Fn(v3, t2))), g3.on("data", (S2) => i3.push(S2)), g3.on("end", () => s4(Ql(i3, g3))), g3.on("error", a3);
        });
        u3.on("error", a3), u3.end((l3 = t2.body) != null ? l3 : "");
      });
    }
    var Gl = typeof __require != "undefined" ? __require : () => {
    };
    var Bn = class {
      constructor(t2 = {}) {
        this.headers = /* @__PURE__ */ new Map();
        for (let [r3, n3] of Object.entries(t2))
          if (typeof n3 == "string")
            this.headers.set(r3, n3);
          else if (Array.isArray(n3))
            for (let i3 of n3)
              this.headers.set(r3, i3);
      }
      append(t2, r3) {
        this.headers.set(t2, r3);
      }
      delete(t2) {
        this.headers.delete(t2);
      }
      get(t2) {
        var r3;
        return (r3 = this.headers.get(t2)) != null ? r3 : null;
      }
      has(t2) {
        return this.headers.has(t2);
      }
      set(t2, r3) {
        this.headers.set(t2, r3);
      }
      forEach(t2, r3) {
        for (let [n3, i3] of this.headers)
          t2.call(r3, i3, n3, this);
      }
    };
    var Hl = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;
    var fs = ne("prisma:client:dataproxyEngine");
    async function Wl(e2, t2) {
      var s4, a3, u3;
      let r3 = ps["@prisma/engines-version"], n3 = (s4 = t2.clientVersion) != null ? s4 : "unknown";
      if (y2.env.PRISMA_CLIENT_DATA_PROXY_CLIENT_VERSION)
        return y2.env.PRISMA_CLIENT_DATA_PROXY_CLIENT_VERSION;
      if (e2.includes("accelerate") && n3 !== "0.0.0" && n3 !== "in-memory")
        return n3;
      let [i3, o4] = (a3 = n3 == null ? void 0 : n3.split("-")) != null ? a3 : [];
      if (o4 === void 0 && Hl.test(i3))
        return i3;
      if (o4 !== void 0 || n3 === "0.0.0" || n3 === "in-memory") {
        if (e2.startsWith("localhost") || e2.startsWith("127.0.0.1"))
          return "0.0.0";
        let [l3] = (u3 = r3.split("-")) != null ? u3 : [], [g3, h2, v3] = l3.split("."), S2 = Kl(`<=${g3}.${h2}.${v3}`), A2 = await Ye(S2, { clientVersion: n3 });
        if (!A2.ok)
          throw new Error(`Failed to fetch stable Prisma version, unpkg.com status ${A2.status} ${A2.statusText}, response body: ${await A2.text() || "<empty body>"}`);
        let R = await A2.text();
        fs("length of body fetched from unpkg.com", R.length);
        let D;
        try {
          D = JSON.parse(R);
        } catch (M2) {
          throw console.error("JSON.parse error: body fetched from unpkg.com: ", R), M2;
        }
        return D.version;
      }
      throw new Ke("Only `major.minor.patch` versions are supported by Accelerate.", { clientVersion: n3 });
    }
    async function ms(e2, t2) {
      let r3 = await Wl(e2, t2);
      return fs("version", r3), r3;
    }
    function Kl(e2) {
      return encodeURI(`https://unpkg.com/prisma@${e2}/package.json`);
    }
    var ds = 3;
    var $n = ne("prisma:client:dataproxyEngine");
    var qn = class {
      constructor({ apiKey: t2, tracingHelper: r3, logLevel: n3, logQueries: i3, engineHash: o4 }) {
        this.apiKey = t2, this.tracingHelper = r3, this.logLevel = n3, this.logQueries = i3, this.engineHash = o4;
      }
      build({ traceparent: t2, interactiveTransaction: r3 } = {}) {
        let n3 = { Authorization: `Bearer ${this.apiKey}`, "Prisma-Engine-Hash": this.engineHash };
        this.tracingHelper.isEnabled() && (n3.traceparent = t2 != null ? t2 : this.tracingHelper.getTraceParent()), r3 && (n3["X-transaction-id"] = r3.id);
        let i3 = this.buildCaptureSettings();
        return i3.length > 0 && (n3["X-capture-telemetry"] = i3.join(", ")), n3;
      }
      buildCaptureSettings() {
        let t2 = [];
        return this.tracingHelper.isEnabled() && t2.push("tracing"), this.logLevel && t2.push(this.logLevel), this.logQueries && t2.push("query"), t2;
      }
    };
    var tr = class {
      constructor(t2) {
        this.name = "DataProxyEngine";
        ls(t2), this.config = t2, this.env = { ...t2.env, ...typeof y2 != "undefined" ? y2.env : {} }, this.inlineSchema = us(t2.inlineSchema), this.inlineDatasources = t2.inlineDatasources, this.inlineSchemaHash = t2.inlineSchemaHash, this.clientVersion = t2.clientVersion, this.engineHash = t2.engineVersion, this.logEmitter = t2.logEmitter, this.tracingHelper = t2.tracingHelper;
      }
      apiKey() {
        return this.headerBuilder.apiKey;
      }
      version() {
        return this.engineHash;
      }
      async start() {
        this.startPromise !== void 0 && await this.startPromise, this.startPromise = (async () => {
          let [t2, r3] = this.extractHostAndApiKey();
          this.host = t2, this.headerBuilder = new qn({ apiKey: r3, tracingHelper: this.tracingHelper, logLevel: this.config.logLevel, logQueries: this.config.logQueries, engineHash: this.engineHash }), this.remoteClientVersion = await ms(t2, this.config), $n("host", this.host);
        })(), await this.startPromise;
      }
      async stop() {
      }
      propagateResponseExtensions(t2) {
        var r3, n3;
        (r3 = t2 == null ? void 0 : t2.logs) != null && r3.length && t2.logs.forEach((i3) => {
          switch (i3.level) {
            case "debug":
            case "error":
            case "trace":
            case "warn":
            case "info":
              break;
            case "query": {
              let o4 = typeof i3.attributes.query == "string" ? i3.attributes.query : "";
              if (!this.tracingHelper.isEnabled()) {
                let [s4] = o4.split("/* traceparent");
                o4 = s4;
              }
              this.logEmitter.emit("query", { query: o4, timestamp: cs(i3.timestamp), duration: Number(i3.attributes.duration_ms), params: i3.attributes.params, target: i3.attributes.target });
            }
          }
        }), (n3 = t2 == null ? void 0 : t2.traces) != null && n3.length && this.tracingHelper.createEngineSpan({ span: true, spans: t2.traces });
      }
      onBeforeExit() {
        throw new Error('"beforeExit" hook is not applicable to the remote query engine');
      }
      async url(t2) {
        return await this.start(), `https://${this.host}/${this.remoteClientVersion}/${this.inlineSchemaHash}/${t2}`;
      }
      async uploadSchema() {
        let t2 = { name: "schemaUpload", internal: true };
        return this.tracingHelper.runInChildSpan(t2, async () => {
          let r3 = await Ye(await this.url("schema"), { method: "PUT", headers: this.headerBuilder.build(), body: this.inlineSchema, clientVersion: this.clientVersion });
          r3.ok || $n("schema response status", r3.status);
          let n3 = await Xt(r3, this.clientVersion);
          if (n3)
            throw this.logEmitter.emit("warn", { message: `Error while uploading schema: ${n3.message}`, timestamp: /* @__PURE__ */ new Date(), target: "" }), n3;
          this.logEmitter.emit("info", { message: `Schema (re)uploaded (hash: ${this.inlineSchemaHash})`, timestamp: /* @__PURE__ */ new Date(), target: "" });
        });
      }
      request(t2, { traceparent: r3, interactiveTransaction: n3, customDataProxyFetch: i3 }) {
        return this.requestInternal({ body: t2, traceparent: r3, interactiveTransaction: n3, customDataProxyFetch: i3 });
      }
      async requestBatch(t2, { traceparent: r3, transaction: n3, customDataProxyFetch: i3 }) {
        let o4 = (n3 == null ? void 0 : n3.kind) === "itx" ? n3.options : void 0, s4 = gr(t2, n3), { batchResult: a3, elapsed: u3 } = await this.requestInternal({ body: s4, customDataProxyFetch: i3, interactiveTransaction: o4, traceparent: r3 });
        return a3.map((l3) => "errors" in l3 && l3.errors.length > 0 ? qt(l3.errors[0], this.clientVersion, this.config.activeProvider) : { data: l3, elapsed: u3 });
      }
      requestInternal({ body: t2, traceparent: r3, customDataProxyFetch: n3, interactiveTransaction: i3 }) {
        return this.withRetry({ actionGerund: "querying", callback: async ({ logHttpCall: o4 }) => {
          let s4 = i3 ? `${i3.payload.endpoint}/graphql` : await this.url("graphql");
          o4(s4);
          let a3 = await Ye(s4, { method: "POST", headers: this.headerBuilder.build({ traceparent: r3, interactiveTransaction: i3 }), body: JSON.stringify(t2), clientVersion: this.clientVersion }, n3);
          a3.ok || $n("graphql response status", a3.status), await this.handleError(await Xt(a3, this.clientVersion));
          let u3 = await a3.json(), l3 = u3.extensions;
          if (l3 && this.propagateResponseExtensions(l3), u3.errors)
            throw u3.errors.length === 1 ? qt(u3.errors[0], this.config.clientVersion, this.config.activeProvider) : new se(u3.errors, { clientVersion: this.config.clientVersion });
          return u3;
        } });
      }
      async transaction(t2, r3, n3) {
        let i3 = { start: "starting", commit: "committing", rollback: "rolling back" };
        return this.withRetry({ actionGerund: `${i3[t2]} transaction`, callback: async ({ logHttpCall: o4 }) => {
          if (t2 === "start") {
            let s4 = JSON.stringify({ max_wait: n3.maxWait, timeout: n3.timeout, isolation_level: n3.isolationLevel }), a3 = await this.url("transaction/start");
            o4(a3);
            let u3 = await Ye(a3, { method: "POST", headers: this.headerBuilder.build({ traceparent: r3.traceparent }), body: s4, clientVersion: this.clientVersion });
            await this.handleError(await Xt(u3, this.clientVersion));
            let l3 = await u3.json(), g3 = l3.extensions;
            g3 && this.propagateResponseExtensions(g3);
            let h2 = l3.id, v3 = l3["data-proxy"].endpoint;
            return { id: h2, payload: { endpoint: v3 } };
          } else {
            let s4 = `${n3.payload.endpoint}/${t2}`;
            o4(s4);
            let a3 = await Ye(s4, { method: "POST", headers: this.headerBuilder.build({ traceparent: r3.traceparent }), clientVersion: this.clientVersion });
            await this.handleError(await Xt(a3, this.clientVersion));
            let l3 = (await a3.json()).extensions;
            l3 && this.propagateResponseExtensions(l3);
            return;
          }
        } });
      }
      extractHostAndApiKey() {
        let t2 = { clientVersion: this.clientVersion }, r3 = Object.keys(this.inlineDatasources)[0], n3 = wt({ inlineDatasources: this.inlineDatasources, overrideDatasources: this.config.overrideDatasources, clientVersion: this.clientVersion, env: this.env }), i3;
        try {
          i3 = new URL(n3);
        } catch (l3) {
          throw new We(`Error validating datasource \`${r3}\`: the URL must start with the protocol \`prisma://\``, t2);
        }
        let { protocol: o4, host: s4, searchParams: a3 } = i3;
        if (o4 !== "prisma:")
          throw new We(`Error validating datasource \`${r3}\`: the URL must start with the protocol \`prisma://\``, t2);
        let u3 = a3.get("api_key");
        if (u3 === null || u3.length < 1)
          throw new We(`Error validating datasource \`${r3}\`: the URL must contain a valid API key`, t2);
        return [s4, u3];
      }
      metrics() {
        throw new Ke("Metrics are not yet supported for Accelerate", { clientVersion: this.clientVersion });
      }
      async withRetry(t2) {
        var r3;
        for (let n3 = 0; ; n3++) {
          let i3 = (o4) => {
            this.logEmitter.emit("info", { message: `Calling ${o4} (n=${n3})`, timestamp: /* @__PURE__ */ new Date(), target: "" });
          };
          try {
            return await t2.callback({ logHttpCall: i3 });
          } catch (o4) {
            if (!(o4 instanceof le) || !o4.isRetryable)
              throw o4;
            if (n3 >= ds)
              throw o4 instanceof Et ? o4.cause : o4;
            this.logEmitter.emit("warn", { message: `Attempt ${n3 + 1}/${ds} failed for ${t2.actionGerund}: ${(r3 = o4.message) != null ? r3 : "(unknown)"}`, timestamp: /* @__PURE__ */ new Date(), target: "" });
            let s4 = await as(n3);
            this.logEmitter.emit("warn", { message: `Retrying after ${s4}ms`, timestamp: /* @__PURE__ */ new Date(), target: "" });
          }
        }
      }
      async handleError(t2) {
        if (t2 instanceof ze)
          throw await this.uploadSchema(), new Et({ clientVersion: this.clientVersion, cause: t2 });
        if (t2)
          throw t2;
      }
    };
    function gs({ copyEngine: e2 = true }, t2) {
      let r3;
      try {
        r3 = wt({ inlineDatasources: t2.inlineDatasources, overrideDatasources: t2.overrideDatasources, env: { ...t2.env, ...y2.env }, clientVersion: t2.clientVersion });
      } catch (u3) {
      }
      e2 && (r3 != null && r3.startsWith("prisma://")) && It("recommend--no-engine", "In production, we recommend using `prisma generate --no-engine` (See: `prisma generate --help`)");
      let n3 = Rt(t2.generator), i3 = !!(r3 != null && r3.startsWith("prisma://") || !e2), o4 = !!t2.adapter, s4 = n3 === "library", a3 = n3 === "binary";
      if (i3 && o4 || o4) {
        let u3;
        throw u3 = ["Prisma Client was configured to use the `adapter` option but it was imported via its `/edge` endpoint.", "Please either remove the `/edge` endpoint or remove the `adapter` from the Prisma Client constructor."], new Z(u3.join(`
`), { clientVersion: t2.clientVersion });
      }
      if (i3)
        return new tr(t2);
      throw new Z("Invalid client engine type, please use `library` or `binary`", { clientVersion: t2.clientVersion });
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function _r({ generator: e2 }) {
      var t2;
      return (t2 = e2 == null ? void 0 : e2.previewFeatures) != null ? t2 : [];
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var xs = Ve(Un());
    d3();
    c3();
    p3();
    f3();
    m3();
    function Es(e2, t2) {
      let r3 = bs(e2), n3 = zl(r3), i3 = Zl(n3);
      i3 ? Lr(i3, t2) : t2.addErrorMessage(() => "Unknown error");
    }
    function bs(e2) {
      return e2.errors.flatMap((t2) => t2.kind === "Union" ? bs(t2) : [t2]);
    }
    function zl(e2) {
      let t2 = /* @__PURE__ */ new Map(), r3 = [];
      for (let n3 of e2) {
        if (n3.kind !== "InvalidArgumentType") {
          r3.push(n3);
          continue;
        }
        let i3 = `${n3.selectionPath.join(".")}:${n3.argumentPath.join(".")}`, o4 = t2.get(i3);
        o4 ? t2.set(i3, { ...n3, argument: { ...n3.argument, typeNames: Yl(o4.argument.typeNames, n3.argument.typeNames) } }) : t2.set(i3, n3);
      }
      return r3.push(...t2.values()), r3;
    }
    function Yl(e2, t2) {
      return [...new Set(e2.concat(t2))];
    }
    function Zl(e2) {
      return pn(e2, (t2, r3) => {
        let n3 = ys(t2), i3 = ys(r3);
        return n3 !== i3 ? n3 - i3 : ws(t2) - ws(r3);
      });
    }
    function ys(e2) {
      let t2 = 0;
      return Array.isArray(e2.selectionPath) && (t2 += e2.selectionPath.length), Array.isArray(e2.argumentPath) && (t2 += e2.argumentPath.length), t2;
    }
    function ws(e2) {
      switch (e2.kind) {
        case "InvalidArgumentValue":
        case "ValueTooLarge":
          return 20;
        case "InvalidArgumentType":
          return 10;
        case "RequiredArgumentMissing":
          return -10;
        default:
          return 0;
      }
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var Re = class {
      constructor(t2, r3) {
        this.name = t2;
        this.value = r3;
        this.isRequired = false;
      }
      makeRequired() {
        return this.isRequired = true, this;
      }
      write(t2) {
        let { colors: { green: r3 } } = t2.context;
        t2.addMarginSymbol(r3(this.isRequired ? "+" : "?")), t2.write(r3(this.name)), this.isRequired || t2.write(r3("?")), t2.write(r3(": ")), typeof this.value == "string" ? t2.write(r3(this.value)) : t2.write(this.value);
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var Fr = class {
      constructor() {
        this.fields = [];
      }
      addField(t2, r3) {
        return this.fields.push({ write(n3) {
          let { green: i3, dim: o4 } = n3.context.colors;
          n3.write(i3(o4(`${t2}: ${r3}`))).addMarginSymbol(i3(o4("+")));
        } }), this;
      }
      write(t2) {
        let { colors: { green: r3 } } = t2.context;
        t2.writeLine(r3("{")).withIndent(() => {
          t2.writeJoined(dt, this.fields).newLine();
        }).write(r3("}")).addMarginSymbol(r3("+"));
      }
    };
    function Lr(e2, t2) {
      switch (e2.kind) {
        case "IncludeAndSelect":
          Xl(e2, t2);
          break;
        case "IncludeOnScalar":
          ec(e2, t2);
          break;
        case "EmptySelection":
          tc(e2, t2);
          break;
        case "UnknownSelectionField":
          rc(e2, t2);
          break;
        case "UnknownArgument":
          nc(e2, t2);
          break;
        case "UnknownInputField":
          ic(e2, t2);
          break;
        case "RequiredArgumentMissing":
          oc(e2, t2);
          break;
        case "InvalidArgumentType":
          sc(e2, t2);
          break;
        case "InvalidArgumentValue":
          ac(e2, t2);
          break;
        case "ValueTooLarge":
          uc(e2, t2);
          break;
        case "SomeFieldsMissing":
          lc(e2, t2);
          break;
        case "TooManyFieldsGiven":
          cc(e2, t2);
          break;
        case "Union":
          Es(e2, t2);
          break;
        default:
          throw new Error("not implemented: " + e2.kind);
      }
    }
    function Xl(e2, t2) {
      var n3, i3;
      let r3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath);
      r3 && r3 instanceof z2 && ((n3 = r3.getField("include")) == null || n3.markAsError(), (i3 = r3.getField("select")) == null || i3.markAsError()), t2.addErrorMessage((o4) => `Please ${o4.bold("either")} use ${o4.green("`include`")} or ${o4.green("`select`")}, but ${o4.red("not both")} at the same time.`);
    }
    function ec(e2, t2) {
      var s4, a3;
      let [r3, n3] = Br(e2.selectionPath), i3 = e2.outputType, o4 = (s4 = t2.arguments.getDeepSelectionParent(r3)) == null ? void 0 : s4.value;
      if (o4 && ((a3 = o4.getField(n3)) == null || a3.markAsError(), i3))
        for (let u3 of i3.fields)
          u3.isRelation && o4.addSuggestion(new Re(u3.name, "true"));
      t2.addErrorMessage((u3) => {
        let l3 = `Invalid scalar field ${u3.red(`\`${n3}\``)} for ${u3.bold("include")} statement`;
        return i3 ? l3 += ` on model ${u3.bold(i3.name)}. ${rr(u3)}` : l3 += ".", l3 += `
Note that ${u3.bold("include")} statements only accept relation fields.`, l3;
      });
    }
    function tc(e2, t2) {
      var o4, s4;
      let r3 = e2.outputType, n3 = (o4 = t2.arguments.getDeepSelectionParent(e2.selectionPath)) == null ? void 0 : o4.value, i3 = (s4 = n3 == null ? void 0 : n3.isEmpty()) != null ? s4 : false;
      n3 && (n3.removeAllFields(), Ts(n3, r3)), t2.addErrorMessage((a3) => i3 ? `The ${a3.red("`select`")} statement for type ${a3.bold(r3.name)} must not be empty. ${rr(a3)}` : `The ${a3.red("`select`")} statement for type ${a3.bold(r3.name)} needs ${a3.bold("at least one truthy value")}.`);
    }
    function rc(e2, t2) {
      var o4;
      let [r3, n3] = Br(e2.selectionPath), i3 = t2.arguments.getDeepSelectionParent(r3);
      i3 && ((o4 = i3.value.getField(n3)) == null || o4.markAsError(), Ts(i3.value, e2.outputType)), t2.addErrorMessage((s4) => {
        let a3 = [`Unknown field ${s4.red(`\`${n3}\``)}`];
        return i3 && a3.push(`for ${s4.bold(i3.kind)} statement`), a3.push(`on model ${s4.bold(`\`${e2.outputType.name}\``)}.`), a3.push(rr(s4)), a3.join(" ");
      });
    }
    function nc(e2, t2) {
      var i3;
      let r3 = e2.argumentPath[0], n3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath);
      n3 instanceof z2 && ((i3 = n3.getField(r3)) == null || i3.markAsError(), pc(n3, e2.arguments)), t2.addErrorMessage((o4) => Ps(o4, r3, e2.arguments.map((s4) => s4.name)));
    }
    function ic(e2, t2) {
      var o4;
      let [r3, n3] = Br(e2.argumentPath), i3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath);
      if (i3 instanceof z2) {
        (o4 = i3.getDeepField(e2.argumentPath)) == null || o4.markAsError();
        let s4 = i3.getDeepFieldValue(r3);
        s4 instanceof z2 && Cs(s4, e2.inputType);
      }
      t2.addErrorMessage((s4) => Ps(s4, n3, e2.inputType.fields.map((a3) => a3.name)));
    }
    function Ps(e2, t2, r3) {
      let n3 = [`Unknown argument \`${e2.red(t2)}\`.`], i3 = mc(t2, r3);
      return i3 && n3.push(`Did you mean \`${e2.green(i3)}\`?`), r3.length > 0 && n3.push(rr(e2)), n3.join(" ");
    }
    function oc(e2, t2) {
      let r3;
      t2.addErrorMessage((u3) => (r3 == null ? void 0 : r3.value) instanceof Y && r3.value.text === "null" ? `Argument \`${u3.green(o4)}\` must not be ${u3.red("null")}.` : `Argument \`${u3.green(o4)}\` is missing.`);
      let n3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath);
      if (!(n3 instanceof z2))
        return;
      let [i3, o4] = Br(e2.argumentPath), s4 = new Fr(), a3 = n3.getDeepFieldValue(i3);
      if (a3 instanceof z2)
        if (r3 = a3.getField(o4), r3 && a3.removeField(o4), e2.inputTypes.length === 1 && e2.inputTypes[0].kind === "object") {
          for (let u3 of e2.inputTypes[0].fields)
            s4.addField(u3.name, u3.typeNames.join(" | "));
          a3.addSuggestion(new Re(o4, s4).makeRequired());
        } else {
          let u3 = e2.inputTypes.map(vs).join(" | ");
          a3.addSuggestion(new Re(o4, u3).makeRequired());
        }
    }
    function vs(e2) {
      return e2.kind === "list" ? `${vs(e2.elementType)}[]` : e2.name;
    }
    function sc(e2, t2) {
      var i3;
      let r3 = e2.argument.name, n3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath);
      n3 instanceof z2 && ((i3 = n3.getDeepFieldValue(e2.argumentPath)) == null || i3.markAsError()), t2.addErrorMessage((o4) => {
        let s4 = $r("or", e2.argument.typeNames.map((a3) => o4.green(a3)));
        return `Argument \`${o4.bold(r3)}\`: Invalid value provided. Expected ${s4}, provided ${o4.red(e2.inferredType)}.`;
      });
    }
    function ac(e2, t2) {
      var i3;
      let r3 = e2.argument.name, n3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath);
      n3 instanceof z2 && ((i3 = n3.getDeepFieldValue(e2.argumentPath)) == null || i3.markAsError()), t2.addErrorMessage((o4) => {
        let s4 = [`Invalid value for argument \`${o4.bold(r3)}\``];
        if (e2.underlyingError && s4.push(`: ${e2.underlyingError}`), s4.push("."), e2.argument.typeNames.length > 0) {
          let a3 = $r("or", e2.argument.typeNames.map((u3) => o4.green(u3)));
          s4.push(` Expected ${a3}.`);
        }
        return s4.join("");
      });
    }
    function uc(e2, t2) {
      let r3 = e2.argument.name, n3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath), i3;
      if (n3 instanceof z2) {
        let o4 = n3.getDeepField(e2.argumentPath), s4 = o4 == null ? void 0 : o4.value;
        s4 == null || s4.markAsError(), s4 instanceof Y && (i3 = s4.text);
      }
      t2.addErrorMessage((o4) => {
        let s4 = ["Unable to fit value"];
        return i3 && s4.push(o4.red(i3)), s4.push(`into a 64-bit signed integer for field \`${o4.bold(r3)}\``), s4.join(" ");
      });
    }
    function lc(e2, t2) {
      let r3 = e2.argumentPath[e2.argumentPath.length - 1], n3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath);
      if (n3 instanceof z2) {
        let i3 = n3.getDeepFieldValue(e2.argumentPath);
        i3 instanceof z2 && Cs(i3, e2.inputType);
      }
      t2.addErrorMessage((i3) => {
        let o4 = [`Argument \`${i3.bold(r3)}\` of type ${i3.bold(e2.inputType.name)} needs`];
        return e2.constraints.minFieldCount === 1 ? e2.constraints.requiredFields ? o4.push(`${i3.green("at least one of")} ${$r("or", e2.constraints.requiredFields.map((s4) => `\`${i3.bold(s4)}\``))} arguments.`) : o4.push(`${i3.green("at least one")} argument.`) : o4.push(`${i3.green(`at least ${e2.constraints.minFieldCount}`)} arguments.`), o4.push(rr(i3)), o4.join(" ");
      });
    }
    function cc(e2, t2) {
      let r3 = e2.argumentPath[e2.argumentPath.length - 1], n3 = t2.arguments.getDeepSubSelectionValue(e2.selectionPath), i3 = [];
      if (n3 instanceof z2) {
        let o4 = n3.getDeepFieldValue(e2.argumentPath);
        o4 instanceof z2 && (o4.markAsError(), i3 = Object.keys(o4.getFields()));
      }
      t2.addErrorMessage((o4) => {
        let s4 = [`Argument \`${o4.bold(r3)}\` of type ${o4.bold(e2.inputType.name)} needs`];
        return e2.constraints.minFieldCount === 1 && e2.constraints.maxFieldCount == 1 ? s4.push(`${o4.green("exactly one")} argument,`) : e2.constraints.maxFieldCount == 1 ? s4.push(`${o4.green("at most one")} argument,`) : s4.push(`${o4.green(`at most ${e2.constraints.maxFieldCount}`)} arguments,`), s4.push(`but you provided ${$r("and", i3.map((a3) => o4.red(a3)))}. Please choose`), e2.constraints.maxFieldCount === 1 ? s4.push("one.") : s4.push(`${e2.constraints.maxFieldCount}.`), s4.join(" ");
      });
    }
    function Ts(e2, t2) {
      for (let r3 of t2.fields)
        e2.hasField(r3.name) || e2.addSuggestion(new Re(r3.name, "true"));
    }
    function pc(e2, t2) {
      for (let r3 of t2)
        e2.hasField(r3.name) || e2.addSuggestion(new Re(r3.name, r3.typeNames.join(" | ")));
    }
    function Cs(e2, t2) {
      if (t2.kind === "object")
        for (let r3 of t2.fields)
          e2.hasField(r3.name) || e2.addSuggestion(new Re(r3.name, r3.typeNames.join(" | ")));
    }
    function Br(e2) {
      let t2 = [...e2], r3 = t2.pop();
      if (!r3)
        throw new Error("unexpected empty path");
      return [t2, r3];
    }
    function rr({ green: e2, enabled: t2 }) {
      return "Available options are " + (t2 ? `listed in ${e2("green")}` : "marked with ?") + ".";
    }
    function $r(e2, t2) {
      if (t2.length === 1)
        return t2[0];
      let r3 = [...t2], n3 = r3.pop();
      return `${r3.join(", ")} ${e2} ${n3}`;
    }
    var fc = 3;
    function mc(e2, t2) {
      let r3 = 1 / 0, n3;
      for (let i3 of t2) {
        let o4 = (0, xs.default)(e2, i3);
        o4 > fc || o4 < r3 && (r3 = o4, n3 = i3);
      }
      return n3;
    }
    function qr({ args: e2, errors: t2, errorFormat: r3, callsite: n3, originalMethod: i3, clientVersion: o4 }) {
      let s4 = Sr(e2);
      for (let h2 of t2)
        Lr(h2, s4);
      let a3 = r3 === "pretty" ? Ao : Ar, u3 = s4.renderAllMessages(a3), l3 = new ut(0, { colors: a3 }).write(s4).toString(), g3 = yt({ message: u3, callsite: n3, originalMethod: i3, showColors: r3 === "pretty", callArguments: l3 });
      throw new Z(g3, { clientVersion: o4 });
    }
    var dc = { findUnique: "findUnique", findUniqueOrThrow: "findUniqueOrThrow", findFirst: "findFirst", findFirstOrThrow: "findFirstOrThrow", findMany: "findMany", count: "aggregate", create: "createOne", createMany: "createMany", update: "updateOne", updateMany: "updateMany", upsert: "upsertOne", delete: "deleteOne", deleteMany: "deleteMany", executeRaw: "executeRaw", queryRaw: "queryRaw", aggregate: "aggregate", groupBy: "groupBy", runCommandRaw: "runCommandRaw", findRaw: "findRaw", aggregateRaw: "aggregateRaw" };
    function As({ modelName: e2, action: t2, args: r3, runtimeDataModel: n3, extensions: i3, callsite: o4, clientMethod: s4, errorFormat: a3, clientVersion: u3 }) {
      let l3 = new Vn({ runtimeDataModel: n3, modelName: e2, action: t2, rootArgs: r3, callsite: o4, extensions: i3, selectionPath: [], argumentPath: [], originalMethod: s4, errorFormat: a3, clientVersion: u3 });
      return { modelName: e2, action: dc[t2], query: jn(r3, l3) };
    }
    function jn({ select: e2, include: t2, ...r3 } = {}, n3) {
      return { arguments: Ss(r3, n3), selection: gc(e2, t2, n3) };
    }
    function gc(e2, t2, r3) {
      return e2 && t2 && r3.throwValidationError({ kind: "IncludeAndSelect", selectionPath: r3.getSelectionPath() }), e2 ? wc(e2, r3) : hc(r3, t2);
    }
    function hc(e2, t2) {
      let r3 = {};
      return e2.model && !e2.isRawAction() && (r3.$composites = true, r3.$scalars = true), t2 && yc(r3, t2, e2), r3;
    }
    function yc(e2, t2, r3) {
      for (let [n3, i3] of Object.entries(t2)) {
        let o4 = r3.findField(n3);
        o4 && (o4 == null ? void 0 : o4.kind) !== "object" && r3.throwValidationError({ kind: "IncludeOnScalar", selectionPath: r3.getSelectionPath().concat(n3), outputType: r3.getOutputTypeDescription() }), i3 === true ? e2[n3] = true : typeof i3 == "object" && (e2[n3] = jn(i3, r3.nestSelection(n3)));
      }
    }
    function wc(e2, t2) {
      let r3 = {}, n3 = t2.getComputedFields(), i3 = ts(e2, n3);
      for (let [o4, s4] of Object.entries(i3)) {
        let a3 = t2.findField(o4);
        n3 != null && n3[o4] && !a3 || (s4 === true ? r3[o4] = true : typeof s4 == "object" && (r3[o4] = jn(s4, t2.nestSelection(o4))));
      }
      return r3;
    }
    function Rs(e2, t2) {
      if (e2 === null)
        return null;
      if (typeof e2 == "string" || typeof e2 == "number" || typeof e2 == "boolean")
        return e2;
      if (typeof e2 == "bigint")
        return { $type: "BigInt", value: String(e2) };
      if (lt(e2)) {
        if (hr(e2))
          return { $type: "DateTime", value: e2.toISOString() };
        t2.throwValidationError({ kind: "InvalidArgumentValue", selectionPath: t2.getSelectionPath(), argumentPath: t2.getArgumentPath(), argument: { name: t2.getArgumentName(), typeNames: ["Date"] }, underlyingError: "Provided Date object is invalid" });
      }
      if (mt(e2))
        return { $type: "FieldRef", value: { _ref: e2.name, _container: e2.modelName } };
      if (Array.isArray(e2))
        return Ec(e2, t2);
      if (ArrayBuffer.isView(e2))
        return { $type: "Bytes", value: w3.Buffer.from(e2).toString("base64") };
      if (bc(e2))
        return e2.values;
      if (ft(e2))
        return { $type: "Decimal", value: e2.toFixed() };
      if (e2 instanceof Te) {
        if (e2 !== fr.instances[e2._getName()])
          throw new Error("Invalid ObjectEnumValue");
        return { $type: "Enum", value: e2._getName() };
      }
      if (xc(e2))
        return e2.toJSON();
      if (typeof e2 == "object")
        return Ss(e2, t2);
      t2.throwValidationError({ kind: "InvalidArgumentValue", selectionPath: t2.getSelectionPath(), argumentPath: t2.getArgumentPath(), argument: { name: t2.getArgumentName(), typeNames: [] }, underlyingError: `We could not serialize ${Object.prototype.toString.call(e2)} value. Serialize the object to JSON or implement a ".toJSON()" method on it` });
    }
    function Ss(e2, t2) {
      if (e2.$type)
        return { $type: "Raw", value: e2 };
      let r3 = {};
      for (let n3 in e2) {
        let i3 = e2[n3];
        i3 !== void 0 && (r3[n3] = Rs(i3, t2.nestArgument(n3)));
      }
      return r3;
    }
    function Ec(e2, t2) {
      let r3 = [];
      for (let n3 = 0; n3 < e2.length; n3++) {
        let i3 = t2.nestArgument(String(n3)), o4 = e2[n3];
        o4 === void 0 && t2.throwValidationError({ kind: "InvalidArgumentValue", selectionPath: i3.getSelectionPath(), argumentPath: i3.getArgumentPath(), argument: { name: `${t2.getArgumentName()}[${n3}]`, typeNames: [] }, underlyingError: "Can not use `undefined` value within array. Use `null` or filter out `undefined` values" }), r3.push(Rs(o4, i3));
      }
      return r3;
    }
    function bc(e2) {
      return typeof e2 == "object" && e2 !== null && e2.__prismaRawParameters__ === true;
    }
    function xc(e2) {
      return typeof e2 == "object" && e2 !== null && typeof e2.toJSON == "function";
    }
    var Vn = class e2 {
      constructor(t2) {
        this.params = t2;
        this.params.modelName && (this.model = this.params.runtimeDataModel.models[this.params.modelName]);
      }
      throwValidationError(t2) {
        var r3;
        qr({ errors: [t2], originalMethod: this.params.originalMethod, args: (r3 = this.params.rootArgs) != null ? r3 : {}, callsite: this.params.callsite, errorFormat: this.params.errorFormat, clientVersion: this.params.clientVersion });
      }
      getSelectionPath() {
        return this.params.selectionPath;
      }
      getArgumentPath() {
        return this.params.argumentPath;
      }
      getArgumentName() {
        return this.params.argumentPath[this.params.argumentPath.length - 1];
      }
      getOutputTypeDescription() {
        if (!(!this.params.modelName || !this.model))
          return { name: this.params.modelName, fields: this.model.fields.map((t2) => ({ name: t2.name, typeName: "boolean", isRelation: t2.kind === "object" })) };
      }
      isRawAction() {
        return ["executeRaw", "queryRaw", "runCommandRaw", "findRaw", "aggregateRaw"].includes(this.params.action);
      }
      getComputedFields() {
        if (this.params.modelName)
          return this.params.extensions.getAllComputedFields(this.params.modelName);
      }
      findField(t2) {
        var r3;
        return (r3 = this.model) == null ? void 0 : r3.fields.find((n3) => n3.name === t2);
      }
      nestSelection(t2) {
        let r3 = this.findField(t2), n3 = (r3 == null ? void 0 : r3.kind) === "object" ? r3.type : void 0;
        return new e2({ ...this.params, modelName: n3, selectionPath: this.params.selectionPath.concat(t2) });
      }
      nestArgument(t2) {
        return new e2({ ...this.params, argumentPath: this.params.argumentPath.concat(t2) });
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var Is = (e2) => ({ command: e2 });
    d3();
    c3();
    p3();
    f3();
    m3();
    d3();
    c3();
    p3();
    f3();
    m3();
    var ks = (e2) => e2.strings.reduce((t2, r3, n3) => `${t2}@P${n3}${r3}`);
    d3();
    c3();
    p3();
    f3();
    m3();
    function nr(e2) {
      try {
        return Ds(e2, "fast");
      } catch (t2) {
        return Ds(e2, "slow");
      }
    }
    function Ds(e2, t2) {
      return JSON.stringify(e2.map((r3) => Pc(r3, t2)));
    }
    function Pc(e2, t2) {
      return typeof e2 == "bigint" ? { prisma__type: "bigint", prisma__value: e2.toString() } : lt(e2) ? { prisma__type: "date", prisma__value: e2.toJSON() } : ye.isDecimal(e2) ? { prisma__type: "decimal", prisma__value: e2.toJSON() } : w3.Buffer.isBuffer(e2) ? { prisma__type: "bytes", prisma__value: e2.toString("base64") } : vc(e2) || ArrayBuffer.isView(e2) ? { prisma__type: "bytes", prisma__value: w3.Buffer.from(e2).toString("base64") } : typeof e2 == "object" && t2 === "slow" ? Os(e2) : e2;
    }
    function vc(e2) {
      return e2 instanceof ArrayBuffer || e2 instanceof SharedArrayBuffer ? true : typeof e2 == "object" && e2 !== null ? e2[Symbol.toStringTag] === "ArrayBuffer" || e2[Symbol.toStringTag] === "SharedArrayBuffer" : false;
    }
    function Os(e2) {
      if (typeof e2 != "object" || e2 === null)
        return e2;
      if (typeof e2.toJSON == "function")
        return e2.toJSON();
      if (Array.isArray(e2))
        return e2.map(Ms);
      let t2 = {};
      for (let r3 of Object.keys(e2))
        t2[r3] = Ms(e2[r3]);
      return t2;
    }
    function Ms(e2) {
      return typeof e2 == "bigint" ? e2.toString() : Os(e2);
    }
    var Tc = /^(\s*alter\s)/i;
    var Ns = ne("prisma:client");
    function Jn(e2, t2, r3, n3) {
      if (!(e2 !== "postgresql" && e2 !== "cockroachdb") && r3.length > 0 && Tc.exec(t2))
        throw new Error(`Running ALTER using ${n3} is not supported
Using the example below you can still execute your query with Prisma, but please note that it is vulnerable to SQL injection attacks and requires you to take care of input sanitization.

Example:
  await prisma.$executeRawUnsafe(\`ALTER USER prisma WITH PASSWORD '\${password}'\`)

More Information: https://pris.ly/d/execute-raw
`);
    }
    var Qn = ({ clientMethod: e2, activeProvider: t2 }) => (r3) => {
      let n3 = "", i3;
      if (Array.isArray(r3)) {
        let [o4, ...s4] = r3;
        n3 = o4, i3 = { values: nr(s4 || []), __prismaRawParameters__: true };
      } else
        switch (t2) {
          case "sqlite":
          case "mysql": {
            n3 = r3.sql, i3 = { values: nr(r3.values), __prismaRawParameters__: true };
            break;
          }
          case "cockroachdb":
          case "postgresql":
          case "postgres": {
            n3 = r3.text, i3 = { values: nr(r3.values), __prismaRawParameters__: true };
            break;
          }
          case "sqlserver": {
            n3 = ks(r3), i3 = { values: nr(r3.values), __prismaRawParameters__: true };
            break;
          }
          default:
            throw new Error(`The ${t2} provider does not support ${e2}`);
        }
      return i3 != null && i3.values ? Ns(`prisma.${e2}(${n3}, ${i3.values})`) : Ns(`prisma.${e2}(${n3})`), { query: n3, parameters: i3 };
    };
    var _s = { requestArgsToMiddlewareArgs(e2) {
      return [e2.strings, ...e2.values];
    }, middlewareArgsToRequestArgs(e2) {
      let [t2, ...r3] = e2;
      return new ae(t2, r3);
    } };
    var Ls = { requestArgsToMiddlewareArgs(e2) {
      return [e2];
    }, middlewareArgsToRequestArgs(e2) {
      return e2[0];
    } };
    d3();
    c3();
    p3();
    f3();
    m3();
    function Gn(e2) {
      return function(r3) {
        let n3, i3 = (o4 = e2) => {
          try {
            return o4 === void 0 || (o4 == null ? void 0 : o4.kind) === "itx" ? n3 != null ? n3 : n3 = Fs(r3(o4)) : Fs(r3(o4));
          } catch (s4) {
            return Promise.reject(s4);
          }
        };
        return { then(o4, s4) {
          return i3().then(o4, s4);
        }, catch(o4) {
          return i3().catch(o4);
        }, finally(o4) {
          return i3().finally(o4);
        }, requestTransaction(o4) {
          let s4 = i3(o4);
          return s4.requestTransaction ? s4.requestTransaction(o4) : s4;
        }, [Symbol.toStringTag]: "PrismaPromise" };
      };
    }
    function Fs(e2) {
      return typeof e2.then == "function" ? e2 : Promise.resolve(e2);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var Bs = { isEnabled() {
      return false;
    }, getTraceParent() {
      return "00-10-10-00";
    }, async createEngineSpan() {
    }, getActiveContext() {
    }, runInChildSpan(e2, t2) {
      return t2();
    } };
    var Hn = class {
      isEnabled() {
        return this.getGlobalTracingHelper().isEnabled();
      }
      getTraceParent(t2) {
        return this.getGlobalTracingHelper().getTraceParent(t2);
      }
      createEngineSpan(t2) {
        return this.getGlobalTracingHelper().createEngineSpan(t2);
      }
      getActiveContext() {
        return this.getGlobalTracingHelper().getActiveContext();
      }
      runInChildSpan(t2, r3) {
        return this.getGlobalTracingHelper().runInChildSpan(t2, r3);
      }
      getGlobalTracingHelper() {
        var t2, r3;
        return (r3 = (t2 = globalThis.PRISMA_INSTRUMENTATION) == null ? void 0 : t2.helper) != null ? r3 : Bs;
      }
    };
    function $s(e2) {
      return e2.includes("tracing") ? new Hn() : Bs;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function qs(e2, t2 = () => {
    }) {
      let r3, n3 = new Promise((i3) => r3 = i3);
      return { then(i3) {
        return --e2 === 0 && r3(t2()), i3 == null ? void 0 : i3(n3);
      } };
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var Cc = ["$connect", "$disconnect", "$on", "$transaction", "$use", "$extends"];
    var Us = Cc;
    d3();
    c3();
    p3();
    f3();
    m3();
    function Vs(e2) {
      return typeof e2 == "string" ? e2 : e2.reduce((t2, r3) => {
        let n3 = typeof r3 == "string" ? r3 : r3.level;
        return n3 === "query" ? t2 : t2 && (r3 === "info" || t2 === "info") ? "info" : n3;
      }, void 0);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var Ur = class {
      constructor() {
        this._middlewares = [];
      }
      use(t2) {
        this._middlewares.push(t2);
      }
      get(t2) {
        return this._middlewares[t2];
      }
      has(t2) {
        return !!this._middlewares[t2];
      }
      length() {
        return this._middlewares.length;
      }
    };
    d3();
    c3();
    p3();
    f3();
    m3();
    var Js = Ve(eo());
    d3();
    c3();
    p3();
    f3();
    m3();
    function Vr(e2) {
      return typeof e2.batchRequestIdx == "number";
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function jr(e2) {
      return e2 === null ? e2 : Array.isArray(e2) ? e2.map(jr) : typeof e2 == "object" ? Ac(e2) ? Rc(e2) : st(e2, jr) : e2;
    }
    function Ac(e2) {
      return e2 !== null && typeof e2 == "object" && typeof e2.$type == "string";
    }
    function Rc({ $type: e2, value: t2 }) {
      switch (e2) {
        case "BigInt":
          return BigInt(t2);
        case "Bytes":
          return w3.Buffer.from(t2, "base64");
        case "DateTime":
          return new Date(t2);
        case "Decimal":
          return new ye(t2);
        case "Json":
          return JSON.parse(t2);
        default:
          Je(t2, "Unknown tagged value");
      }
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function js(e2) {
      if (e2.action !== "findUnique" && e2.action !== "findUniqueOrThrow")
        return;
      let t2 = [];
      return e2.modelName && t2.push(e2.modelName), e2.query.arguments && t2.push(Wn(e2.query.arguments)), t2.push(Wn(e2.query.selection)), t2.join("");
    }
    function Wn(e2) {
      return `(${Object.keys(e2).sort().map((r3) => {
        let n3 = e2[r3];
        return typeof n3 == "object" && n3 !== null ? `(${r3} ${Wn(n3)})` : r3;
      }).join(" ")})`;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var Sc = { aggregate: false, aggregateRaw: false, createMany: true, createOne: true, deleteMany: true, deleteOne: true, executeRaw: true, findFirst: false, findFirstOrThrow: false, findMany: false, findRaw: false, findUnique: false, findUniqueOrThrow: false, groupBy: false, queryRaw: false, runCommandRaw: true, updateMany: true, updateOne: true, upsertOne: true };
    function Kn(e2) {
      return Sc[e2];
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var Jr = class {
      constructor(t2) {
        this.options = t2;
        this.tickActive = false;
        this.batches = {};
      }
      request(t2) {
        let r3 = this.options.batchBy(t2);
        return r3 ? (this.batches[r3] || (this.batches[r3] = [], this.tickActive || (this.tickActive = true, y2.nextTick(() => {
          this.dispatchBatches(), this.tickActive = false;
        }))), new Promise((n3, i3) => {
          this.batches[r3].push({ request: t2, resolve: n3, reject: i3 });
        })) : this.options.singleLoader(t2);
      }
      dispatchBatches() {
        for (let t2 in this.batches) {
          let r3 = this.batches[t2];
          delete this.batches[t2], r3.length === 1 ? this.options.singleLoader(r3[0].request).then((n3) => {
            n3 instanceof Error ? r3[0].reject(n3) : r3[0].resolve(n3);
          }).catch((n3) => {
            r3[0].reject(n3);
          }) : (r3.sort((n3, i3) => this.options.batchOrder(n3.request, i3.request)), this.options.batchLoader(r3.map((n3) => n3.request)).then((n3) => {
            if (n3 instanceof Error)
              for (let i3 = 0; i3 < r3.length; i3++)
                r3[i3].reject(n3);
            else
              for (let i3 = 0; i3 < r3.length; i3++) {
                let o4 = n3[i3];
                o4 instanceof Error ? r3[i3].reject(o4) : r3[i3].resolve(o4);
              }
          }).catch((n3) => {
            for (let i3 = 0; i3 < r3.length; i3++)
              r3[i3].reject(n3);
          }));
        }
      }
      get [Symbol.toStringTag]() {
        return "DataLoader";
      }
    };
    var Ic = ne("prisma:client:request_handler");
    var Qr = class {
      constructor(t2, r3) {
        this.logEmitter = r3, this.client = t2, this.dataloader = new Jr({ batchLoader: zo(async ({ requests: n3, customDataProxyFetch: i3 }) => {
          let { transaction: o4, otelParentCtx: s4 } = n3[0], a3 = n3.map((h2) => h2.protocolQuery), u3 = this.client._tracingHelper.getTraceParent(s4), l3 = n3.some((h2) => Kn(h2.protocolQuery.action));
          return (await this.client._engine.requestBatch(a3, { traceparent: u3, transaction: kc(o4), containsWrite: l3, customDataProxyFetch: i3 })).map((h2, v3) => {
            if (h2 instanceof Error)
              return h2;
            try {
              return this.mapQueryEngineResult(n3[v3], h2);
            } catch (S2) {
              return S2;
            }
          });
        }), singleLoader: async (n3) => {
          var s4;
          let i3 = ((s4 = n3.transaction) == null ? void 0 : s4.kind) === "itx" ? Qs(n3.transaction) : void 0, o4 = await this.client._engine.request(n3.protocolQuery, { traceparent: this.client._tracingHelper.getTraceParent(), interactiveTransaction: i3, isWrite: Kn(n3.protocolQuery.action), customDataProxyFetch: n3.customDataProxyFetch });
          return this.mapQueryEngineResult(n3, o4);
        }, batchBy: (n3) => {
          var i3;
          return (i3 = n3.transaction) != null && i3.id ? `transaction-${n3.transaction.id}` : js(n3.protocolQuery);
        }, batchOrder(n3, i3) {
          var o4, s4;
          return ((o4 = n3.transaction) == null ? void 0 : o4.kind) === "batch" && ((s4 = i3.transaction) == null ? void 0 : s4.kind) === "batch" ? n3.transaction.index - i3.transaction.index : 0;
        } });
      }
      async request(t2) {
        try {
          return await this.dataloader.request(t2);
        } catch (r3) {
          let { clientMethod: n3, callsite: i3, transaction: o4, args: s4, modelName: a3 } = t2;
          this.handleAndLogRequestError({ error: r3, clientMethod: n3, callsite: i3, transaction: o4, args: s4, modelName: a3 });
        }
      }
      mapQueryEngineResult({ dataPath: t2, unpacker: r3 }, n3) {
        let i3 = n3 == null ? void 0 : n3.data, o4 = n3 == null ? void 0 : n3.elapsed, s4 = this.unpack(i3, t2, r3);
        return y2.env.PRISMA_CLIENT_GET_TIME ? { data: s4, elapsed: o4 } : s4;
      }
      handleAndLogRequestError(t2) {
        try {
          this.handleRequestError(t2);
        } catch (r3) {
          throw this.logEmitter && this.logEmitter.emit("error", { message: r3.message, target: t2.clientMethod, timestamp: /* @__PURE__ */ new Date() }), r3;
        }
      }
      handleRequestError({ error: t2, clientMethod: r3, callsite: n3, transaction: i3, args: o4, modelName: s4 }) {
        if (Ic(t2), Dc(t2, i3) || t2 instanceof Pe)
          throw t2;
        if (t2 instanceof K && Mc(t2)) {
          let u3 = Gs(t2.meta);
          qr({ args: o4, errors: [u3], callsite: n3, errorFormat: this.client._errorFormat, originalMethod: r3, clientVersion: this.client._clientVersion });
        }
        let a3 = t2.message;
        if (n3 && (a3 = yt({ callsite: n3, originalMethod: r3, isPanic: t2.isPanic, showColors: this.client._errorFormat === "pretty", message: a3 })), a3 = this.sanitizeMessage(a3), t2.code) {
          let u3 = s4 ? { modelName: s4, ...t2.meta } : t2.meta;
          throw new K(a3, { code: t2.code, clientVersion: this.client._clientVersion, meta: u3, batchRequestIdx: t2.batchRequestIdx });
        } else {
          if (t2.isPanic)
            throw new ve(a3, this.client._clientVersion);
          if (t2 instanceof se)
            throw new se(a3, { clientVersion: this.client._clientVersion, batchRequestIdx: t2.batchRequestIdx });
          if (t2 instanceof G)
            throw new G(a3, this.client._clientVersion);
          if (t2 instanceof ve)
            throw new ve(a3, this.client._clientVersion);
        }
        throw t2.clientVersion = this.client._clientVersion, t2;
      }
      sanitizeMessage(t2) {
        return this.client._errorFormat && this.client._errorFormat !== "pretty" ? (0, Js.default)(t2) : t2;
      }
      unpack(t2, r3, n3) {
        if (!t2 || (t2.data && (t2 = t2.data), !t2))
          return t2;
        let i3 = Object.values(t2)[0], o4 = r3.filter((a3) => a3 !== "select" && a3 !== "include"), s4 = jr(Rn(i3, o4));
        return n3 ? n3(s4) : s4;
      }
      get [Symbol.toStringTag]() {
        return "RequestHandler";
      }
    };
    function kc(e2) {
      if (e2) {
        if (e2.kind === "batch")
          return { kind: "batch", options: { isolationLevel: e2.isolationLevel } };
        if (e2.kind === "itx")
          return { kind: "itx", options: Qs(e2) };
        Je(e2, "Unknown transaction kind");
      }
    }
    function Qs(e2) {
      return { id: e2.id, payload: e2.payload };
    }
    function Dc(e2, t2) {
      return Vr(e2) && (t2 == null ? void 0 : t2.kind) === "batch" && e2.batchRequestIdx !== t2.index;
    }
    function Mc(e2) {
      return e2.code === "P2009" || e2.code === "P2012";
    }
    function Gs(e2) {
      if (e2.kind === "Union")
        return { kind: "Union", errors: e2.errors.map(Gs) };
      if (Array.isArray(e2.selectionPath)) {
        let [, ...t2] = e2.selectionPath;
        return { ...e2, selectionPath: t2 };
      }
      return e2;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var Hs = "5.11.0";
    var Ws = Hs;
    d3();
    c3();
    p3();
    f3();
    m3();
    function Ks(e2) {
      return e2.map((t2) => {
        let r3 = {};
        for (let n3 of Object.keys(t2))
          r3[n3] = zs(t2[n3]);
        return r3;
      });
    }
    function zs({ prisma__type: e2, prisma__value: t2 }) {
      switch (e2) {
        case "bigint":
          return BigInt(t2);
        case "bytes":
          return w3.Buffer.from(t2, "base64");
        case "decimal":
          return new ye(t2);
        case "datetime":
        case "date":
          return new Date(t2);
        case "time":
          return /* @__PURE__ */ new Date(`1970-01-01T${t2}Z`);
        case "array":
          return t2.map(zs);
        default:
          return t2;
      }
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var ea = Ve(Un());
    d3();
    c3();
    p3();
    f3();
    m3();
    var J = class extends Error {
      constructor(t2) {
        super(t2 + `
Read more at https://pris.ly/d/client-constructor`), this.name = "PrismaClientConstructorValidationError";
      }
      get [Symbol.toStringTag]() {
        return "PrismaClientConstructorValidationError";
      }
    };
    N2(J, "PrismaClientConstructorValidationError");
    var Ys = ["datasources", "datasourceUrl", "errorFormat", "adapter", "log", "transactionOptions", "__internal"];
    var Zs = ["pretty", "colorless", "minimal"];
    var Xs = ["info", "query", "warn", "error"];
    var Nc = { datasources: (e2, { datasourceNames: t2 }) => {
      if (e2) {
        if (typeof e2 != "object" || Array.isArray(e2))
          throw new J(`Invalid value ${JSON.stringify(e2)} for "datasources" provided to PrismaClient constructor`);
        for (let [r3, n3] of Object.entries(e2)) {
          if (!t2.includes(r3)) {
            let i3 = Pt(r3, t2) || ` Available datasources: ${t2.join(", ")}`;
            throw new J(`Unknown datasource ${r3} provided to PrismaClient constructor.${i3}`);
          }
          if (typeof n3 != "object" || Array.isArray(n3))
            throw new J(`Invalid value ${JSON.stringify(e2)} for datasource "${r3}" provided to PrismaClient constructor.
It should have this form: { url: "CONNECTION_STRING" }`);
          if (n3 && typeof n3 == "object")
            for (let [i3, o4] of Object.entries(n3)) {
              if (i3 !== "url")
                throw new J(`Invalid value ${JSON.stringify(e2)} for datasource "${r3}" provided to PrismaClient constructor.
It should have this form: { url: "CONNECTION_STRING" }`);
              if (typeof o4 != "string")
                throw new J(`Invalid value ${JSON.stringify(o4)} for datasource "${r3}" provided to PrismaClient constructor.
It should have this form: { url: "CONNECTION_STRING" }`);
            }
        }
      }
    }, adapter: (e2, t2) => {
      if (e2 === null)
        return;
      if (e2 === void 0)
        throw new J('"adapter" property must not be undefined, use null to conditionally disable driver adapters.');
      if (!_r(t2).includes("driverAdapters"))
        throw new J('"adapter" property can only be provided to PrismaClient constructor when "driverAdapters" preview feature is enabled.');
      if (Rt() === "binary")
        throw new J('Cannot use a driver adapter with the "binary" Query Engine. Please use the "library" Query Engine.');
    }, datasourceUrl: (e2) => {
      if (typeof e2 != "undefined" && typeof e2 != "string")
        throw new J(`Invalid value ${JSON.stringify(e2)} for "datasourceUrl" provided to PrismaClient constructor.
Expected string or undefined.`);
    }, errorFormat: (e2) => {
      if (e2) {
        if (typeof e2 != "string")
          throw new J(`Invalid value ${JSON.stringify(e2)} for "errorFormat" provided to PrismaClient constructor.`);
        if (!Zs.includes(e2)) {
          let t2 = Pt(e2, Zs);
          throw new J(`Invalid errorFormat ${e2} provided to PrismaClient constructor.${t2}`);
        }
      }
    }, log: (e2) => {
      if (!e2)
        return;
      if (!Array.isArray(e2))
        throw new J(`Invalid value ${JSON.stringify(e2)} for "log" provided to PrismaClient constructor.`);
      function t2(r3) {
        if (typeof r3 == "string" && !Xs.includes(r3)) {
          let n3 = Pt(r3, Xs);
          throw new J(`Invalid log level "${r3}" provided to PrismaClient constructor.${n3}`);
        }
      }
      for (let r3 of e2) {
        t2(r3);
        let n3 = { level: t2, emit: (i3) => {
          let o4 = ["stdout", "event"];
          if (!o4.includes(i3)) {
            let s4 = Pt(i3, o4);
            throw new J(`Invalid value ${JSON.stringify(i3)} for "emit" in logLevel provided to PrismaClient constructor.${s4}`);
          }
        } };
        if (r3 && typeof r3 == "object")
          for (let [i3, o4] of Object.entries(r3))
            if (n3[i3])
              n3[i3](o4);
            else
              throw new J(`Invalid property ${i3} for "log" provided to PrismaClient constructor`);
      }
    }, transactionOptions: (e2) => {
      if (!e2)
        return;
      let t2 = e2.maxWait;
      if (t2 != null && t2 <= 0)
        throw new J(`Invalid value ${t2} for maxWait in "transactionOptions" provided to PrismaClient constructor. maxWait needs to be greater than 0`);
      let r3 = e2.timeout;
      if (r3 != null && r3 <= 0)
        throw new J(`Invalid value ${r3} for timeout in "transactionOptions" provided to PrismaClient constructor. timeout needs to be greater than 0`);
    }, __internal: (e2) => {
      if (!e2)
        return;
      let t2 = ["debug", "engine", "configOverride"];
      if (typeof e2 != "object")
        throw new J(`Invalid value ${JSON.stringify(e2)} for "__internal" to PrismaClient constructor`);
      for (let [r3] of Object.entries(e2))
        if (!t2.includes(r3)) {
          let n3 = Pt(r3, t2);
          throw new J(`Invalid property ${JSON.stringify(r3)} for "__internal" provided to PrismaClient constructor.${n3}`);
        }
    } };
    function ta(e2, t2) {
      for (let [r3, n3] of Object.entries(e2)) {
        if (!Ys.includes(r3)) {
          let i3 = Pt(r3, Ys);
          throw new J(`Unknown property ${r3} provided to PrismaClient constructor.${i3}`);
        }
        Nc[r3](n3, t2);
      }
      if (e2.datasourceUrl && e2.datasources)
        throw new J('Can not use "datasourceUrl" and "datasources" options at the same time. Pick one of them');
    }
    function Pt(e2, t2) {
      if (t2.length === 0 || typeof e2 != "string")
        return "";
      let r3 = _c(e2, t2);
      return r3 ? ` Did you mean "${r3}"?` : "";
    }
    function _c(e2, t2) {
      if (t2.length === 0)
        return null;
      let r3 = t2.map((i3) => ({ value: i3, distance: (0, ea.default)(e2, i3) }));
      r3.sort((i3, o4) => i3.distance < o4.distance ? -1 : 1);
      let n3 = r3[0];
      return n3.distance < 3 ? n3.value : null;
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    function ra(e2) {
      return e2.length === 0 ? Promise.resolve([]) : new Promise((t2, r3) => {
        let n3 = new Array(e2.length), i3 = null, o4 = false, s4 = 0, a3 = () => {
          o4 || (s4++, s4 === e2.length && (o4 = true, i3 ? r3(i3) : t2(n3)));
        }, u3 = (l3) => {
          o4 || (o4 = true, r3(l3));
        };
        for (let l3 = 0; l3 < e2.length; l3++)
          e2[l3].then((g3) => {
            n3[l3] = g3, a3();
          }, (g3) => {
            if (!Vr(g3)) {
              u3(g3);
              return;
            }
            g3.batchRequestIdx === l3 ? u3(g3) : (i3 || (i3 = g3), a3());
          });
      });
    }
    var Be = ne("prisma:client");
    typeof globalThis == "object" && (globalThis.NODE_CLIENT = true);
    var Lc = { requestArgsToMiddlewareArgs: (e2) => e2, middlewareArgsToRequestArgs: (e2) => e2 };
    var Fc = Symbol.for("prisma.client.transaction.id");
    var Bc = { id: 0, nextId() {
      return ++this.id;
    } };
    function oa(e2) {
      class t2 {
        constructor(n3) {
          this._originalClient = this;
          this._middlewares = new Ur();
          this._createPrismaPromise = Gn();
          this.$extends = Vo;
          var u3, l3, g3, h2, v3, S2, A2, R, D, M2, B, I2, L2, ee;
          e2 = (g3 = (l3 = (u3 = n3 == null ? void 0 : n3.__internal) == null ? void 0 : u3.configOverride) == null ? void 0 : l3.call(u3, e2)) != null ? g3 : e2, is(e2), n3 && ta(n3, e2);
          let i3 = n3 != null && n3.adapter ? hn(n3.adapter) : void 0, o4 = new cr().on("error", () => {
          });
          this._extensions = Mr.empty(), this._previewFeatures = _r(e2), this._clientVersion = (h2 = e2.clientVersion) != null ? h2 : Ws, this._activeProvider = e2.activeProvider, this._tracingHelper = $s(this._previewFeatures);
          let s4 = { rootEnvPath: e2.relativeEnvPaths.rootEnvPath && At.resolve(e2.dirname, e2.relativeEnvPaths.rootEnvPath), schemaEnvPath: e2.relativeEnvPaths.schemaEnvPath && At.resolve(e2.dirname, e2.relativeEnvPaths.schemaEnvPath) }, a3 = (v3 = e2.injectableEdgeEnv) == null ? void 0 : v3.call(e2);
          try {
            let F = n3 != null ? n3 : {}, Ze = (S2 = F.__internal) != null ? S2 : {}, $e = Ze.debug === true;
            $e && ne.enable("prisma:client");
            let fe = At.resolve(e2.dirname, e2.relativePath);
            bi.existsSync(fe) || (fe = e2.dirname), Be("dirname", e2.dirname), Be("relativePath", e2.relativePath), Be("cwd", fe);
            let qe = Ze.engine || {};
            if (F.errorFormat ? this._errorFormat = F.errorFormat : y2.env.NODE_ENV === "production" ? this._errorFormat = "minimal" : y2.env.NO_COLOR ? this._errorFormat = "colorless" : this._errorFormat = "colorless", this._runtimeDataModel = e2.runtimeDataModel, this._engineConfig = { cwd: fe, dirname: e2.dirname, enableDebugLogs: $e, allowTriggerPanic: qe.allowTriggerPanic, datamodelPath: At.join(e2.dirname, (A2 = e2.filename) != null ? A2 : "schema.prisma"), prismaPath: (R = qe.binaryPath) != null ? R : void 0, engineEndpoint: qe.endpoint, generator: e2.generator, showColors: this._errorFormat === "pretty", logLevel: F.log && Vs(F.log), logQueries: F.log && !!(typeof F.log == "string" ? F.log === "query" : F.log.find((Q) => typeof Q == "string" ? Q === "query" : Q.level === "query")), env: (D = a3 == null ? void 0 : a3.parsed) != null ? D : {}, flags: [], engineWasm: e2.engineWasm, clientVersion: e2.clientVersion, engineVersion: e2.engineVersion, previewFeatures: this._previewFeatures, activeProvider: e2.activeProvider, inlineSchema: e2.inlineSchema, overrideDatasources: os(F, e2.datasourceNames), inlineDatasources: e2.inlineDatasources, inlineSchemaHash: e2.inlineSchemaHash, tracingHelper: this._tracingHelper, transactionOptions: { maxWait: (B = (M2 = F.transactionOptions) == null ? void 0 : M2.maxWait) != null ? B : 2e3, timeout: (L2 = (I2 = F.transactionOptions) == null ? void 0 : I2.timeout) != null ? L2 : 5e3, isolationLevel: (ee = F.transactionOptions) == null ? void 0 : ee.isolationLevel }, logEmitter: o4, isBundled: e2.isBundled, adapter: i3 }, this._accelerateEngineConfig = { ...this._engineConfig, accelerateUtils: { resolveDatasourceUrl: wt, getBatchRequestPayload: gr, prismaGraphQLToJSError: qt, PrismaClientUnknownRequestError: se, PrismaClientInitializationError: G, PrismaClientKnownRequestError: K, debug: ne("prisma:client:accelerateEngine"), engineVersion: ia.version, clientVersion: e2.clientVersion } }, Be("clientVersion", e2.clientVersion), this._engine = gs(e2, this._engineConfig), this._requestHandler = new Qr(this, o4), F.log)
              for (let Q of F.log) {
                let Se = typeof Q == "string" ? Q : Q.emit === "stdout" ? Q.level : null;
                Se && this.$on(Se, (Ue) => {
                  var Xe;
                  ot.log(`${(Xe = ot.tags[Se]) != null ? Xe : ""}`, Ue.message || Ue.query);
                });
              }
            this._metrics = new at(this._engine);
          } catch (F) {
            throw F.clientVersion = this._clientVersion, F;
          }
          return this._appliedParent = Ut(this);
        }
        get [Symbol.toStringTag]() {
          return "PrismaClient";
        }
        $use(n3) {
          this._middlewares.use(n3);
        }
        $on(n3, i3) {
          n3 === "beforeExit" ? this._engine.onBeforeExit(i3) : n3 && this._engineConfig.logEmitter.on(n3, i3);
        }
        $connect() {
          try {
            return this._engine.start();
          } catch (n3) {
            throw n3.clientVersion = this._clientVersion, n3;
          }
        }
        async $disconnect() {
          try {
            await this._engine.stop();
          } catch (n3) {
            throw n3.clientVersion = this._clientVersion, n3;
          } finally {
            ji();
          }
        }
        $executeRawInternal(n3, i3, o4, s4) {
          let a3 = this._activeProvider;
          return this._request({ action: "executeRaw", args: o4, transaction: n3, clientMethod: i3, argsMapper: Qn({ clientMethod: i3, activeProvider: a3 }), callsite: Fe(this._errorFormat), dataPath: [], middlewareArgsMapper: s4 });
        }
        $executeRaw(n3, ...i3) {
          return this._createPrismaPromise((o4) => {
            if (n3.raw !== void 0 || n3.sql !== void 0) {
              let [s4, a3] = na(n3, i3);
              return Jn(this._activeProvider, s4.text, s4.values, Array.isArray(n3) ? "prisma.$executeRaw`<SQL>`" : "prisma.$executeRaw(sql`<SQL>`)"), this.$executeRawInternal(o4, "$executeRaw", s4, a3);
            }
            throw new Z("`$executeRaw` is a tag function, please use it like the following:\n```\nconst result = await prisma.$executeRaw`UPDATE User SET cool = ${true} WHERE email = ${'user@email.com'};`\n```\n\nOr read our docs at https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access#executeraw\n", { clientVersion: this._clientVersion });
          });
        }
        $executeRawUnsafe(n3, ...i3) {
          return this._createPrismaPromise((o4) => (Jn(this._activeProvider, n3, i3, "prisma.$executeRawUnsafe(<SQL>, [...values])"), this.$executeRawInternal(o4, "$executeRawUnsafe", [n3, ...i3])));
        }
        $runCommandRaw(n3) {
          if (e2.activeProvider !== "mongodb")
            throw new Z(`The ${e2.activeProvider} provider does not support $runCommandRaw. Use the mongodb provider.`, { clientVersion: this._clientVersion });
          return this._createPrismaPromise((i3) => this._request({ args: n3, clientMethod: "$runCommandRaw", dataPath: [], action: "runCommandRaw", argsMapper: Is, callsite: Fe(this._errorFormat), transaction: i3 }));
        }
        async $queryRawInternal(n3, i3, o4, s4) {
          let a3 = this._activeProvider;
          return this._request({ action: "queryRaw", args: o4, transaction: n3, clientMethod: i3, argsMapper: Qn({ clientMethod: i3, activeProvider: a3 }), callsite: Fe(this._errorFormat), dataPath: [], middlewareArgsMapper: s4 }).then(Ks);
        }
        $queryRaw(n3, ...i3) {
          return this._createPrismaPromise((o4) => {
            if (n3.raw !== void 0 || n3.sql !== void 0)
              return this.$queryRawInternal(o4, "$queryRaw", ...na(n3, i3));
            throw new Z("`$queryRaw` is a tag function, please use it like the following:\n```\nconst result = await prisma.$queryRaw`SELECT * FROM User WHERE id = ${1} OR email = ${'user@email.com'};`\n```\n\nOr read our docs at https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access#queryraw\n", { clientVersion: this._clientVersion });
          });
        }
        $queryRawUnsafe(n3, ...i3) {
          return this._createPrismaPromise((o4) => this.$queryRawInternal(o4, "$queryRawUnsafe", [n3, ...i3]));
        }
        _transactionWithArray({ promises: n3, options: i3 }) {
          let o4 = Bc.nextId(), s4 = qs(n3.length), a3 = n3.map((u3, l3) => {
            var v3, S2, A2;
            if ((u3 == null ? void 0 : u3[Symbol.toStringTag]) !== "PrismaPromise")
              throw new Error("All elements of the array need to be Prisma Client promises. Hint: Please make sure you are not awaiting the Prisma client calls you intended to pass in the $transaction function.");
            let g3 = (v3 = i3 == null ? void 0 : i3.isolationLevel) != null ? v3 : this._engineConfig.transactionOptions.isolationLevel, h2 = { kind: "batch", id: o4, index: l3, isolationLevel: g3, lock: s4 };
            return (A2 = (S2 = u3.requestTransaction) == null ? void 0 : S2.call(u3, h2)) != null ? A2 : u3;
          });
          return ra(a3);
        }
        async _transactionWithCallback({ callback: n3, options: i3 }) {
          var l3, g3, h2;
          let o4 = { traceparent: this._tracingHelper.getTraceParent() }, s4 = { maxWait: (l3 = i3 == null ? void 0 : i3.maxWait) != null ? l3 : this._engineConfig.transactionOptions.maxWait, timeout: (g3 = i3 == null ? void 0 : i3.timeout) != null ? g3 : this._engineConfig.transactionOptions.timeout, isolationLevel: (h2 = i3 == null ? void 0 : i3.isolationLevel) != null ? h2 : this._engineConfig.transactionOptions.isolationLevel }, a3 = await this._engine.transaction("start", o4, s4), u3;
          try {
            let v3 = { kind: "itx", ...a3 };
            u3 = await n3(this._createItxClient(v3)), await this._engine.transaction("commit", o4, a3);
          } catch (v3) {
            throw await this._engine.transaction("rollback", o4, a3).catch(() => {
            }), v3;
          }
          return u3;
        }
        _createItxClient(n3) {
          return Ut(ge(Uo(this), [ie("_appliedParent", () => this._appliedParent._createItxClient(n3)), ie("_createPrismaPromise", () => Gn(n3)), ie(Fc, () => n3.id), Ft(Us)]));
        }
        $transaction(n3, i3) {
          let o4;
          typeof n3 == "function" ? o4 = () => this._transactionWithCallback({ callback: n3, options: i3 }) : o4 = () => this._transactionWithArray({ promises: n3, options: i3 });
          let s4 = { name: "transaction", attributes: { method: "$transaction" } };
          return this._tracingHelper.runInChildSpan(s4, o4);
        }
        _request(n3) {
          var l3;
          n3.otelParentCtx = this._tracingHelper.getActiveContext();
          let i3 = (l3 = n3.middlewareArgsMapper) != null ? l3 : Lc, o4 = { args: i3.requestArgsToMiddlewareArgs(n3.args), dataPath: n3.dataPath, runInTransaction: !!n3.transaction, action: n3.action, model: n3.model }, s4 = { middleware: { name: "middleware", middleware: true, attributes: { method: "$use" }, active: false }, operation: { name: "operation", attributes: { method: o4.action, model: o4.model, name: o4.model ? `${o4.model}.${o4.action}` : o4.action } } }, a3 = -1, u3 = async (g3) => {
            let h2 = this._middlewares.get(++a3);
            if (h2)
              return this._tracingHelper.runInChildSpan(s4.middleware, (M2) => h2(g3, (B) => (M2 == null || M2.end(), u3(B))));
            let { runInTransaction: v3, args: S2, ...A2 } = g3, R = { ...n3, ...A2 };
            S2 && (R.args = i3.middlewareArgsToRequestArgs(S2)), n3.transaction !== void 0 && v3 === false && delete R.transaction;
            let D = await Ko(this, R);
            return R.model ? Qo({ result: D, modelName: R.model, args: R.args, extensions: this._extensions, runtimeDataModel: this._runtimeDataModel }) : D;
          };
          return this._tracingHelper.runInChildSpan(s4.operation, () => u3(o4));
        }
        async _executeRequest({ args: n3, clientMethod: i3, dataPath: o4, callsite: s4, action: a3, model: u3, argsMapper: l3, transaction: g3, unpacker: h2, otelParentCtx: v3, customDataProxyFetch: S2 }) {
          try {
            n3 = l3 ? l3(n3) : n3;
            let A2 = { name: "serialize" }, R = this._tracingHelper.runInChildSpan(A2, () => As({ modelName: u3, runtimeDataModel: this._runtimeDataModel, action: a3, args: n3, clientMethod: i3, callsite: s4, extensions: this._extensions, errorFormat: this._errorFormat, clientVersion: this._clientVersion }));
            return ne.enabled("prisma:client") && (Be("Prisma Client call:"), Be(`prisma.${i3}(${ko(n3)})`), Be("Generated request:"), Be(JSON.stringify(R, null, 2) + `
`)), (g3 == null ? void 0 : g3.kind) === "batch" && await g3.lock, this._requestHandler.request({ protocolQuery: R, modelName: u3, action: a3, clientMethod: i3, dataPath: o4, callsite: s4, args: n3, extensions: this._extensions, transaction: g3, unpacker: h2, otelParentCtx: v3, otelChildCtx: this._tracingHelper.getActiveContext(), customDataProxyFetch: S2 });
          } catch (A2) {
            throw A2.clientVersion = this._clientVersion, A2;
          }
        }
        get $metrics() {
          if (!this._hasPreviewFlag("metrics"))
            throw new Z("`metrics` preview feature must be enabled in order to access metrics API", { clientVersion: this._clientVersion });
          return this._metrics;
        }
        _hasPreviewFlag(n3) {
          var i3;
          return !!((i3 = this._engineConfig.previewFeatures) != null && i3.includes(n3));
        }
      }
      return t2;
    }
    function na(e2, t2) {
      return $c(e2) ? [new ae(e2, t2), _s] : [e2, Ls];
    }
    function $c(e2) {
      return Array.isArray(e2) && Array.isArray(e2.raw);
    }
    d3();
    c3();
    p3();
    f3();
    m3();
    var qc = /* @__PURE__ */ new Set(["toJSON", "$$typeof", "asymmetricMatch", Symbol.iterator, Symbol.toStringTag, Symbol.isConcatSpreadable, Symbol.toPrimitive]);
    function sa(e2) {
      return new Proxy(e2, { get(t2, r3) {
        if (r3 in t2)
          return t2[r3];
        if (!qc.has(r3))
          throw new TypeError(`Invalid enum value: ${String(r3)}`);
      } });
    }
    d3();
    c3();
    p3();
    f3();
    m3();
  }
});

// node_modules/.prisma/client/edge.js
var require_edge2 = __commonJS({
  "node_modules/.prisma/client/edge.js"(exports) {
    Object.defineProperty(exports, "__esModule", { value: true });
    var {
      PrismaClientKnownRequestError: PrismaClientKnownRequestError2,
      PrismaClientUnknownRequestError: PrismaClientUnknownRequestError2,
      PrismaClientRustPanicError: PrismaClientRustPanicError2,
      PrismaClientInitializationError: PrismaClientInitializationError2,
      PrismaClientValidationError: PrismaClientValidationError2,
      NotFoundError: NotFoundError2,
      getPrismaClient: getPrismaClient2,
      sqltag: sqltag2,
      empty: empty2,
      join: join2,
      raw: raw3,
      Decimal: Decimal2,
      Debug: Debug2,
      objectEnumValues: objectEnumValues2,
      makeStrictEnum: makeStrictEnum2,
      Extensions: Extensions2,
      warnOnce: warnOnce2,
      defineDmmfProperty: defineDmmfProperty2,
      Public: Public2,
      getRuntime: getRuntime2
    } = require_edge();
    var Prisma = {};
    exports.Prisma = Prisma;
    exports.$Enums = {};
    Prisma.prismaVersion = {
      client: "5.11.0",
      engine: "efd2449663b3d73d637ea1fd226bafbcf45b3102"
    };
    Prisma.PrismaClientKnownRequestError = PrismaClientKnownRequestError2;
    Prisma.PrismaClientUnknownRequestError = PrismaClientUnknownRequestError2;
    Prisma.PrismaClientRustPanicError = PrismaClientRustPanicError2;
    Prisma.PrismaClientInitializationError = PrismaClientInitializationError2;
    Prisma.PrismaClientValidationError = PrismaClientValidationError2;
    Prisma.NotFoundError = NotFoundError2;
    Prisma.Decimal = Decimal2;
    Prisma.sql = sqltag2;
    Prisma.empty = empty2;
    Prisma.join = join2;
    Prisma.raw = raw3;
    Prisma.validator = Public2.validator;
    Prisma.getExtensionContext = Extensions2.getExtensionContext;
    Prisma.defineExtension = Extensions2.defineExtension;
    Prisma.DbNull = objectEnumValues2.instances.DbNull;
    Prisma.JsonNull = objectEnumValues2.instances.JsonNull;
    Prisma.AnyNull = objectEnumValues2.instances.AnyNull;
    Prisma.NullTypes = {
      DbNull: objectEnumValues2.classes.DbNull,
      JsonNull: objectEnumValues2.classes.JsonNull,
      AnyNull: objectEnumValues2.classes.AnyNull
    };
    exports.Prisma.TransactionIsolationLevel = makeStrictEnum2({
      ReadUncommitted: "ReadUncommitted",
      ReadCommitted: "ReadCommitted",
      RepeatableRead: "RepeatableRead",
      Serializable: "Serializable"
    });
    exports.Prisma.UserScalarFieldEnum = {
      id: "id",
      name: "name",
      email: "email",
      emailVerified: "emailVerified",
      image: "image"
    };
    exports.Prisma.TodoScalarFieldEnum = {
      id: "id",
      text: "text",
      completed: "completed",
      image: "image",
      userId: "userId"
    };
    exports.Prisma.AccountScalarFieldEnum = {
      id: "id",
      userId: "userId",
      type: "type",
      provider: "provider",
      providerAccountId: "providerAccountId",
      refresh_token: "refresh_token",
      access_token: "access_token",
      expires_at: "expires_at",
      token_type: "token_type",
      scope: "scope",
      id_token: "id_token",
      session_state: "session_state"
    };
    exports.Prisma.SessionScalarFieldEnum = {
      id: "id",
      sessionToken: "sessionToken",
      userId: "userId",
      expires: "expires"
    };
    exports.Prisma.VerificationTokenScalarFieldEnum = {
      identifier: "identifier",
      token: "token",
      expires: "expires"
    };
    exports.Prisma.SortOrder = {
      asc: "asc",
      desc: "desc"
    };
    exports.Prisma.QueryMode = {
      default: "default",
      insensitive: "insensitive"
    };
    exports.Prisma.NullsOrder = {
      first: "first",
      last: "last"
    };
    exports.Prisma.ModelName = {
      User: "User",
      Todo: "Todo",
      Account: "Account",
      Session: "Session",
      VerificationToken: "VerificationToken"
    };
    var config4 = {
      "generator": {
        "name": "client",
        "provider": {
          "fromEnvVar": null,
          "value": "prisma-client-js"
        },
        "output": {
          "value": "F:\\todoapp\\todoapp\\node_modules\\@prisma\\client",
          "fromEnvVar": null
        },
        "config": {
          "engineType": "library"
        },
        "binaryTargets": [
          {
            "fromEnvVar": null,
            "value": "windows",
            "native": true
          }
        ],
        "previewFeatures": []
      },
      "relativeEnvPaths": {
        "rootEnvPath": null,
        "schemaEnvPath": "../../../.env"
      },
      "relativePath": "../../../prisma",
      "clientVersion": "5.11.0",
      "engineVersion": "efd2449663b3d73d637ea1fd226bafbcf45b3102",
      "datasourceNames": [
        "db"
      ],
      "activeProvider": "postgresql",
      "postinstall": false,
      "inlineDatasources": {
        "db": {
          "url": {
            "fromEnvVar": "DATABASE_URL",
            "value": null
          }
        }
      },
      "inlineSchema": '// This is your Prisma schema file,\n// learn more about it in the docs: https://pris.ly/d/prisma-schema\n\n// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?\n// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init\n\ngenerator client {\n  provider = "prisma-client-js"\n}\n\ndatasource db {\n  provider = "postgresql"\n  url      = env("DATABASE_URL")\n}\n\nmodel User {\n  id            String    @id @default(cuid())\n  name          String?\n  email         String?   @unique\n  emailVerified DateTime?\n  image         String?\n  accounts      Account[]\n  sessions      Session[]\n  todo Todo[]\n}\n\nmodel Todo{\n  id Int @id @default(autoincrement())\n  text String\n  completed Boolean @default(false)\n  image String\n  userId String\n  user User @relation( fields: [userId], references: [id])\n}\n\nmodel Account {\n  id                 String  @id @default(cuid())\n  userId             String\n  type               String\n  provider           String\n  providerAccountId  String\n  refresh_token      String?  @db.Text\n  access_token       String?  @db.Text\n  expires_at         Int?\n  token_type         String?\n  scope              String?\n  id_token           String?  @db.Text\n  session_state      String?\n\n  user User @relation(fields: [userId], references: [id], onDelete: Cascade)\n\n  @@unique([provider, providerAccountId])\n}\n\nmodel Session {\n  id           String   @id @default(cuid())\n  sessionToken String   @unique\n  userId       String\n  expires      DateTime\n  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)\n}\n\nmodel VerificationToken {\n  identifier String\n  token      String   @unique\n  expires    DateTime\n\n  @@unique([identifier, token])\n}',
      "inlineSchemaHash": "8dc860abbe90cc56e3c535c2a2d11d7918cd168d267f7234e14d7a1b4a6eb8df",
      "copyEngine": false
    };
    config4.dirname = "/";
    config4.runtimeDataModel = JSON.parse('{"models":{"User":{"dbName":null,"fields":[{"name":"id","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":true,"isReadOnly":false,"hasDefaultValue":true,"type":"String","default":{"name":"cuid","args":[]},"isGenerated":false,"isUpdatedAt":false},{"name":"name","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"email","kind":"scalar","isList":false,"isRequired":false,"isUnique":true,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"emailVerified","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"DateTime","isGenerated":false,"isUpdatedAt":false},{"name":"image","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"accounts","kind":"object","isList":true,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"Account","relationName":"AccountToUser","relationFromFields":[],"relationToFields":[],"isGenerated":false,"isUpdatedAt":false},{"name":"sessions","kind":"object","isList":true,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"Session","relationName":"SessionToUser","relationFromFields":[],"relationToFields":[],"isGenerated":false,"isUpdatedAt":false},{"name":"todo","kind":"object","isList":true,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"Todo","relationName":"TodoToUser","relationFromFields":[],"relationToFields":[],"isGenerated":false,"isUpdatedAt":false}],"primaryKey":null,"uniqueFields":[],"uniqueIndexes":[],"isGenerated":false},"Todo":{"dbName":null,"fields":[{"name":"id","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":true,"isReadOnly":false,"hasDefaultValue":true,"type":"Int","default":{"name":"autoincrement","args":[]},"isGenerated":false,"isUpdatedAt":false},{"name":"text","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"completed","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":true,"type":"Boolean","default":false,"isGenerated":false,"isUpdatedAt":false},{"name":"image","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"userId","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":true,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"user","kind":"object","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"User","relationName":"TodoToUser","relationFromFields":["userId"],"relationToFields":["id"],"isGenerated":false,"isUpdatedAt":false}],"primaryKey":null,"uniqueFields":[],"uniqueIndexes":[],"isGenerated":false},"Account":{"dbName":null,"fields":[{"name":"id","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":true,"isReadOnly":false,"hasDefaultValue":true,"type":"String","default":{"name":"cuid","args":[]},"isGenerated":false,"isUpdatedAt":false},{"name":"userId","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":true,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"type","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"provider","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"providerAccountId","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"refresh_token","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"access_token","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"expires_at","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"Int","isGenerated":false,"isUpdatedAt":false},{"name":"token_type","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"scope","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"id_token","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"session_state","kind":"scalar","isList":false,"isRequired":false,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"user","kind":"object","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"User","relationName":"AccountToUser","relationFromFields":["userId"],"relationToFields":["id"],"relationOnDelete":"Cascade","isGenerated":false,"isUpdatedAt":false}],"primaryKey":null,"uniqueFields":[["provider","providerAccountId"]],"uniqueIndexes":[{"name":null,"fields":["provider","providerAccountId"]}],"isGenerated":false},"Session":{"dbName":null,"fields":[{"name":"id","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":true,"isReadOnly":false,"hasDefaultValue":true,"type":"String","default":{"name":"cuid","args":[]},"isGenerated":false,"isUpdatedAt":false},{"name":"sessionToken","kind":"scalar","isList":false,"isRequired":true,"isUnique":true,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"userId","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":true,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"expires","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"DateTime","isGenerated":false,"isUpdatedAt":false},{"name":"user","kind":"object","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"User","relationName":"SessionToUser","relationFromFields":["userId"],"relationToFields":["id"],"relationOnDelete":"Cascade","isGenerated":false,"isUpdatedAt":false}],"primaryKey":null,"uniqueFields":[],"uniqueIndexes":[],"isGenerated":false},"VerificationToken":{"dbName":null,"fields":[{"name":"identifier","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"token","kind":"scalar","isList":false,"isRequired":true,"isUnique":true,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"String","isGenerated":false,"isUpdatedAt":false},{"name":"expires","kind":"scalar","isList":false,"isRequired":true,"isUnique":false,"isId":false,"isReadOnly":false,"hasDefaultValue":false,"type":"DateTime","isGenerated":false,"isUpdatedAt":false}],"primaryKey":null,"uniqueFields":[["identifier","token"]],"uniqueIndexes":[{"name":null,"fields":["identifier","token"]}],"isGenerated":false}},"enums":{},"types":{}}');
    defineDmmfProperty2(exports.Prisma, config4.runtimeDataModel);
    config4.engineWasm = void 0;
    config4.injectableEdgeEnv = () => ({
      parsed: {
        DATABASE_URL: typeof globalThis !== "undefined" && globalThis["DATABASE_URL"] || typeof process !== "undefined" && process.env && process.env.DATABASE_URL || void 0
      }
    });
    if (typeof globalThis !== "undefined" && globalThis["DEBUG"] || typeof process !== "undefined" && process.env && process.env.DEBUG || void 0) {
      Debug2.enable(typeof globalThis !== "undefined" && globalThis["DEBUG"] || typeof process !== "undefined" && process.env && process.env.DEBUG || void 0);
    }
    var PrismaClient2 = getPrismaClient2(config4);
    exports.PrismaClient = PrismaClient2;
    Object.assign(exports, Prisma);
  }
});

// node_modules/@prisma/client/edge.js
var require_edge3 = __commonJS({
  "node_modules/@prisma/client/edge.js"(exports, module) {
    module.exports = {
      // https://github.com/prisma/prisma/pull/12907
      ...require_edge2()
    };
  }
});

// .svelte-kit/output/server/chunks/prisma.js
var import_edge, prisma;
var init_prisma = __esm({
  ".svelte-kit/output/server/chunks/prisma.js"() {
    import_edge = __toESM(require_edge3(), 1);
    prisma = new import_edge.PrismaClient();
  }
});

// .svelte-kit/output/server/chunks/hooks.server.js
var hooks_server_exports = {};
__export(hooks_server_exports, {
  handle: () => handle,
  signIn: () => signIn2,
  signOut: () => signOut2
});
function setEnvDefaults2(envObject, config4) {
  if (building)
    return;
  setEnvDefaults(envObject, config4);
  config4.trustHost ?? (config4.trustHost = dev);
  config4.basePath = `${base}/auth`;
}
async function signIn$1(provider, options2 = {}, authorizationParams, config4, event) {
  const { request } = event;
  const headers2 = new Headers(request.headers);
  const { redirect: shouldRedirect = true, redirectTo, ...rest } = options2 instanceof FormData ? Object.fromEntries(options2) : options2;
  const callbackUrl = redirectTo?.toString() ?? headers2.get("Referer") ?? "/";
  const base2 = createActionURL2("signin", headers2, config4.basePath);
  if (!provider) {
    const url2 = `${base2}?${new URLSearchParams({ callbackUrl })}`;
    if (shouldRedirect)
      redirect(302, url2);
    return url2;
  }
  let url = `${base2}/${provider}?${new URLSearchParams(authorizationParams)}`;
  let foundProvider = void 0;
  for (const _provider of config4.providers) {
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
  headers2.set("Content-Type", "application/x-www-form-urlencoded");
  const body2 = new URLSearchParams({ ...rest, callbackUrl });
  const req = new Request(url, { method: "POST", headers: headers2, body: body2 });
  const res = await Auth(req, { ...config4, raw: raw2, skipCSRFCheck });
  for (const c3 of res?.cookies ?? []) {
    event.cookies.set(c3.name, c3.value, { path: "/", ...c3.options });
  }
  if (shouldRedirect) {
    return redirect(302, res.redirect);
  }
  return res.redirect;
}
async function signOut$1(options2, config4, event) {
  const { request } = event;
  const headers2 = new Headers(request.headers);
  headers2.set("Content-Type", "application/x-www-form-urlencoded");
  const url = createActionURL2("signout", headers2, config4.basePath);
  const callbackUrl = options2?.redirectTo ?? headers2.get("Referer") ?? "/";
  const body2 = new URLSearchParams({ callbackUrl });
  const req = new Request(url, { method: "POST", headers: headers2, body: body2 });
  const res = await Auth(req, { ...config4, raw: raw2, skipCSRFCheck });
  for (const c3 of res?.cookies ?? [])
    event.cookies.set(c3.name, c3.value, { path: "/", ...c3.options });
  if (options2?.redirect ?? true)
    return redirect(302, res.redirect);
  return res;
}
async function auth(event, config4) {
  setEnvDefaults2(private_env, config4);
  config4.trustHost ?? (config4.trustHost = true);
  const { request: req } = event;
  const sessionUrl = createActionURL2("session", req.headers, config4.basePath);
  const request = new Request(sessionUrl, {
    headers: { cookie: req.headers.get("cookie") ?? "" }
  });
  const response = await Auth(request, config4);
  const authCookies = (0, import_set_cookie_parser.parse)(response.headers.getSetCookie());
  for (const cookie of authCookies) {
    const { name, value, ...options2 } = cookie;
    event.cookies.set(name, value, { path: "/", ...options2 });
  }
  const { status = 200 } = response;
  const data = await response.json();
  if (!data || !Object.keys(data).length)
    return null;
  if (status === 200)
    return data;
  throw new Error(data.message);
}
function createActionURL2(action, headers2, basePath) {
  let url = private_env.AUTH_URL;
  if (!url) {
    const host = headers2.get("x-forwarded-host") ?? headers2.get("host");
    const proto = headers2.get("x-forwarded-proto");
    url = `${proto === "http" || dev ? "http" : "https"}://${host}${basePath}`;
  }
  return new URL(`${url.replace(/\/$/, "")}/${action}`);
}
function SvelteKitAuth(config4) {
  return {
    signIn: async (event) => {
      const { request } = event;
      const _config = typeof config4 === "object" ? config4 : await config4(event);
      setEnvDefaults2(private_env, _config);
      const formData = await request.formData();
      const { providerId: provider, ...options2 } = Object.fromEntries(formData);
      let authorizationParams = {};
      let _options2 = {};
      for (const key2 in options2) {
        if (key2.startsWith(authorizationParamsPrefix)) {
          authorizationParams[key2.slice(authorizationParamsPrefix.length)] = options2[key2];
        } else {
          _options2[key2] = options2[key2];
        }
      }
      await signIn$1(provider, _options2, authorizationParams, _config, event);
    },
    signOut: async (event) => {
      const _config = typeof config4 === "object" ? config4 : await config4(event);
      setEnvDefaults2(private_env, _config);
      const options2 = Object.fromEntries(await event.request.formData());
      await signOut$1(options2, _config, event);
    },
    async handle({ event, resolve: resolve2 }) {
      var _a, _b;
      const _config = typeof config4 === "object" ? config4 : await config4(event);
      setEnvDefaults2(private_env, _config);
      const { url, request } = event;
      (_a = event.locals).auth ?? (_a.auth = () => auth(event, _config));
      (_b = event.locals).getSession ?? (_b.getSession = event.locals.auth);
      const action = url.pathname.slice(
        // @ts-expect-error - basePath is defined in setEnvDefaults
        _config.basePath.length + 1
      ).split("/")[0];
      if (isAuthAction(action) && url.pathname.startsWith(_config.basePath + "/")) {
        return Auth(request, _config);
      }
      return resolve2(event);
    }
  };
}
var import_set_cookie_parser, dev, authorizationParamsPrefix, GITHUB_ID, GITHUB_SECRET, handle, signIn2, signOut2;
var init_hooks_server = __esm({
  ".svelte-kit/output/server/chunks/hooks.server.js"() {
    init_internal();
    init_core();
    init_prod_ssr();
    init_chunks();
    import_set_cookie_parser = __toESM(require_set_cookie(), 1);
    init_github();
    init_prisma_adapter();
    init_prisma();
    dev = DEV;
    authorizationParamsPrefix = "authorizationParams-";
    GITHUB_ID = "e96b52d6098bc20dd687";
    GITHUB_SECRET = "a13cd9a6aaa6fe51b1717e4561e4eb2eef87a6be";
    ({ handle, signIn: signIn2, signOut: signOut2 } = SvelteKitAuth({
      adapter: PrismaAdapter(prisma),
      providers: [
        GitHub({ clientId: GITHUB_ID, clientSecret: GITHUB_SECRET })
      ]
    }));
    console.log("On hooks.server.ts", handle.name);
  }
});

// .svelte-kit/output/server/chunks/internal.js
function override(paths) {
  base = paths.base;
  assets = paths.assets;
}
function reset2() {
  base = initial.base;
  assets = initial.assets;
}
function set_private_env(environment) {
  private_env = environment;
}
function set_public_env(environment) {
  public_env = environment;
}
function set_safe_public_env(environment) {
  safe_public_env = environment;
}
function afterUpdate() {
}
async function get_hooks() {
  return {
    ...await Promise.resolve().then(() => (init_hooks_server(), hooks_server_exports))
  };
}
var base, assets, initial, private_env, public_env, safe_public_env, building, prerendering, Root, options;
var init_internal = __esm({
  ".svelte-kit/output/server/chunks/internal.js"() {
    init_ssr();
    base = "";
    assets = base;
    initial = { base, assets };
    private_env = {};
    public_env = {};
    safe_public_env = {};
    building = false;
    prerendering = false;
    Root = create_ssr_component(($$result, $$props, $$bindings, slots) => {
      let { stores } = $$props;
      let { page: page2 } = $$props;
      let { constructors } = $$props;
      let { components = [] } = $$props;
      let { form } = $$props;
      let { data_0 = null } = $$props;
      let { data_1 = null } = $$props;
      {
        setContext("__svelte__", stores);
      }
      afterUpdate(stores.page.notify);
      if ($$props.stores === void 0 && $$bindings.stores && stores !== void 0)
        $$bindings.stores(stores);
      if ($$props.page === void 0 && $$bindings.page && page2 !== void 0)
        $$bindings.page(page2);
      if ($$props.constructors === void 0 && $$bindings.constructors && constructors !== void 0)
        $$bindings.constructors(constructors);
      if ($$props.components === void 0 && $$bindings.components && components !== void 0)
        $$bindings.components(components);
      if ($$props.form === void 0 && $$bindings.form && form !== void 0)
        $$bindings.form(form);
      if ($$props.data_0 === void 0 && $$bindings.data_0 && data_0 !== void 0)
        $$bindings.data_0(data_0);
      if ($$props.data_1 === void 0 && $$bindings.data_1 && data_1 !== void 0)
        $$bindings.data_1(data_1);
      let $$settled;
      let $$rendered;
      let previous_head = $$result.head;
      do {
        $$settled = true;
        $$result.head = previous_head;
        {
          stores.page.set(page2);
        }
        $$rendered = `  ${constructors[1] ? `${validate_component(constructors[0] || missing_component, "svelte:component").$$render(
          $$result,
          { data: data_0, this: components[0] },
          {
            this: ($$value) => {
              components[0] = $$value;
              $$settled = false;
            }
          },
          {
            default: () => {
              return `${validate_component(constructors[1] || missing_component, "svelte:component").$$render(
                $$result,
                { data: data_1, form, this: components[1] },
                {
                  this: ($$value) => {
                    components[1] = $$value;
                    $$settled = false;
                  }
                },
                {}
              )}`;
            }
          }
        )}` : `${validate_component(constructors[0] || missing_component, "svelte:component").$$render(
          $$result,
          { data: data_0, form, this: components[0] },
          {
            this: ($$value) => {
              components[0] = $$value;
              $$settled = false;
            }
          },
          {}
        )}`} ${``}`;
      } while (!$$settled);
      return $$rendered;
    });
    options = {
      app_dir: "_app",
      app_template_contains_nonce: false,
      csp: { "mode": "auto", "directives": { "upgrade-insecure-requests": false, "block-all-mixed-content": false }, "reportOnly": { "upgrade-insecure-requests": false, "block-all-mixed-content": false } },
      csrf_check_origin: true,
      embedded: false,
      env_public_prefix: "PUBLIC_",
      env_private_prefix: "",
      hooks: null,
      // added lazily, via `get_hooks`
      preload_strategy: "modulepreload",
      root: Root,
      service_worker: false,
      templates: {
        app: ({ head, body: body2, assets: assets2, nonce: nonce2, env }) => '<!doctype html>\n<html lang="en">\n	<head>\n		<meta charset="utf-8" />\n		<link rel="icon" href="' + assets2 + '/favicon.png" />\n		<meta name="viewport" content="width=device-width, initial-scale=1" />\n		' + head + '\n	</head>\n	<body>\n		<div style="display: contents">' + body2 + '</div>\n	</body>\n	<!-- data-sveltekit-preload-data="hover" -->\n</html>\n',
        error: ({ status, message: message2 }) => '<!doctype html>\n<html lang="en">\n	<head>\n		<meta charset="utf-8" />\n		<title>' + message2 + `</title>

		<style>
			body {
				--bg: white;
				--fg: #222;
				--divider: #ccc;
				background: var(--bg);
				color: var(--fg);
				font-family:
					system-ui,
					-apple-system,
					BlinkMacSystemFont,
					'Segoe UI',
					Roboto,
					Oxygen,
					Ubuntu,
					Cantarell,
					'Open Sans',
					'Helvetica Neue',
					sans-serif;
				display: flex;
				align-items: center;
				justify-content: center;
				height: 100vh;
				margin: 0;
			}

			.error {
				display: flex;
				align-items: center;
				max-width: 32rem;
				margin: 0 1rem;
			}

			.status {
				font-weight: 200;
				font-size: 3rem;
				line-height: 1;
				position: relative;
				top: -0.05rem;
			}

			.message {
				border-left: 1px solid var(--divider);
				padding: 0 0 0 1rem;
				margin: 0 0 0 1rem;
				min-height: 2.5rem;
				display: flex;
				align-items: center;
			}

			.message h1 {
				font-weight: 400;
				font-size: 1em;
				margin: 0;
			}

			@media (prefers-color-scheme: dark) {
				body {
					--bg: #222;
					--fg: #ddd;
					--divider: #666;
				}
			}
		</style>
	</head>
	<body>
		<div class="error">
			<span class="status">` + status + '</span>\n			<div class="message">\n				<h1>' + message2 + "</h1>\n			</div>\n		</div>\n	</body>\n</html>\n"
      },
      version_hash: "wrov89"
    };
  }
});

// .svelte-kit/output/server/chunks/exports.js
function resolve(base2, path) {
  if (path[0] === "/" && path[1] === "/")
    return path;
  let url = new URL(base2, internal);
  url = new URL(path, url);
  return url.protocol === internal.protocol ? url.pathname + url.search + url.hash : url.href;
}
function normalize_path(path, trailing_slash) {
  if (path === "/" || trailing_slash === "ignore")
    return path;
  if (trailing_slash === "never") {
    return path.endsWith("/") ? path.slice(0, -1) : path;
  } else if (trailing_slash === "always" && !path.endsWith("/")) {
    return path + "/";
  }
  return path;
}
function decode_pathname(pathname) {
  return pathname.split("%25").map(decodeURI).join("%25");
}
function decode_params(params) {
  for (const key2 in params) {
    params[key2] = decodeURIComponent(params[key2]);
  }
  return params;
}
function make_trackable(url, callback2, search_params_callback) {
  const tracked = new URL(url);
  Object.defineProperty(tracked, "searchParams", {
    value: new Proxy(tracked.searchParams, {
      get(obj, key2) {
        if (key2 === "get" || key2 === "getAll" || key2 === "has") {
          return (param) => {
            search_params_callback(param);
            return obj[key2](param);
          };
        }
        callback2();
        const value = Reflect.get(obj, key2);
        return typeof value === "function" ? value.bind(obj) : value;
      }
    }),
    enumerable: true,
    configurable: true
  });
  for (const property of tracked_url_properties) {
    Object.defineProperty(tracked, property, {
      get() {
        callback2();
        return url[property];
      },
      enumerable: true,
      configurable: true
    });
  }
  {
    tracked[Symbol.for("nodejs.util.inspect.custom")] = (depth, opts, inspect) => {
      return inspect(url, opts);
    };
  }
  {
    disable_hash(tracked);
  }
  return tracked;
}
function disable_hash(url) {
  allow_nodejs_console_log(url);
  Object.defineProperty(url, "hash", {
    get() {
      throw new Error(
        "Cannot access event.url.hash. Consider using `$page.url.hash` inside a component instead"
      );
    }
  });
}
function disable_search(url) {
  allow_nodejs_console_log(url);
  for (const property of ["search", "searchParams"]) {
    Object.defineProperty(url, property, {
      get() {
        throw new Error(`Cannot access url.${property} on a page with prerendering enabled`);
      }
    });
  }
}
function allow_nodejs_console_log(url) {
  {
    url[Symbol.for("nodejs.util.inspect.custom")] = (depth, opts, inspect) => {
      return inspect(new URL(url), opts);
    };
  }
}
function has_data_suffix(pathname) {
  return pathname.endsWith(DATA_SUFFIX) || pathname.endsWith(HTML_DATA_SUFFIX);
}
function add_data_suffix(pathname) {
  if (pathname.endsWith(".html"))
    return pathname.replace(/\.html$/, HTML_DATA_SUFFIX);
  return pathname.replace(/\/$/, "") + DATA_SUFFIX;
}
function strip_data_suffix(pathname) {
  if (pathname.endsWith(HTML_DATA_SUFFIX)) {
    return pathname.slice(0, -HTML_DATA_SUFFIX.length) + ".html";
  }
  return pathname.slice(0, -DATA_SUFFIX.length);
}
function validator(expected) {
  function validate(module, file) {
    if (!module)
      return;
    for (const key2 in module) {
      if (key2[0] === "_" || expected.has(key2))
        continue;
      const values = [...expected.values()];
      const hint = hint_for_supported_files(key2, file?.slice(file.lastIndexOf("."))) ?? `valid exports are ${values.join(", ")}, or anything with a '_' prefix`;
      throw new Error(`Invalid export '${key2}'${file ? ` in ${file}` : ""} (${hint})`);
    }
  }
  return validate;
}
function hint_for_supported_files(key2, ext = ".js") {
  const supported_files = [];
  if (valid_layout_exports.has(key2)) {
    supported_files.push(`+layout${ext}`);
  }
  if (valid_page_exports.has(key2)) {
    supported_files.push(`+page${ext}`);
  }
  if (valid_layout_server_exports.has(key2)) {
    supported_files.push(`+layout.server${ext}`);
  }
  if (valid_page_server_exports.has(key2)) {
    supported_files.push(`+page.server${ext}`);
  }
  if (valid_server_exports.has(key2)) {
    supported_files.push(`+server${ext}`);
  }
  if (supported_files.length > 0) {
    return `'${key2}' is a valid export in ${supported_files.slice(0, -1).join(", ")}${supported_files.length > 1 ? " or " : ""}${supported_files.at(-1)}`;
  }
}
var internal, tracked_url_properties, DATA_SUFFIX, HTML_DATA_SUFFIX, valid_layout_exports, valid_page_exports, valid_layout_server_exports, valid_page_server_exports, valid_server_exports, validate_layout_exports, validate_page_exports, validate_layout_server_exports, validate_page_server_exports, validate_server_exports;
var init_exports = __esm({
  ".svelte-kit/output/server/chunks/exports.js"() {
    internal = new URL("sveltekit-internal://");
    tracked_url_properties = /** @type {const} */
    [
      "href",
      "pathname",
      "search",
      "toString",
      "toJSON"
    ];
    DATA_SUFFIX = "/__data.json";
    HTML_DATA_SUFFIX = ".html__data.json";
    valid_layout_exports = /* @__PURE__ */ new Set([
      "load",
      "prerender",
      "csr",
      "ssr",
      "trailingSlash",
      "config"
    ]);
    valid_page_exports = /* @__PURE__ */ new Set([...valid_layout_exports, "entries"]);
    valid_layout_server_exports = /* @__PURE__ */ new Set([...valid_layout_exports]);
    valid_page_server_exports = /* @__PURE__ */ new Set([...valid_layout_server_exports, "actions", "entries"]);
    valid_server_exports = /* @__PURE__ */ new Set([
      "GET",
      "POST",
      "PATCH",
      "PUT",
      "DELETE",
      "OPTIONS",
      "HEAD",
      "fallback",
      "prerender",
      "trailingSlash",
      "config",
      "entries"
    ]);
    validate_layout_exports = validator(valid_layout_exports);
    validate_page_exports = validator(valid_page_exports);
    validate_layout_server_exports = validator(valid_layout_server_exports);
    validate_page_server_exports = validator(valid_page_server_exports);
    validate_server_exports = validator(valid_server_exports);
  }
});

// node_modules/devalue/src/utils.js
function is_primitive(thing) {
  return Object(thing) !== thing;
}
function is_plain_object(thing) {
  const proto = Object.getPrototypeOf(thing);
  return proto === Object.prototype || proto === null || Object.getOwnPropertyNames(proto).sort().join("\0") === object_proto_names;
}
function get_type(thing) {
  return Object.prototype.toString.call(thing).slice(8, -1);
}
function get_escaped_char(char) {
  switch (char) {
    case '"':
      return '\\"';
    case "<":
      return "\\u003C";
    case "\\":
      return "\\\\";
    case "\n":
      return "\\n";
    case "\r":
      return "\\r";
    case "	":
      return "\\t";
    case "\b":
      return "\\b";
    case "\f":
      return "\\f";
    case "\u2028":
      return "\\u2028";
    case "\u2029":
      return "\\u2029";
    default:
      return char < " " ? `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}` : "";
  }
}
function stringify_string(str) {
  let result = "";
  let last_pos = 0;
  const len = str.length;
  for (let i3 = 0; i3 < len; i3 += 1) {
    const char = str[i3];
    const replacement = get_escaped_char(char);
    if (replacement) {
      result += str.slice(last_pos, i3) + replacement;
      last_pos = i3 + 1;
    }
  }
  return `"${last_pos === 0 ? str : result + str.slice(last_pos)}"`;
}
var escaped, DevalueError, object_proto_names;
var init_utils = __esm({
  "node_modules/devalue/src/utils.js"() {
    escaped = {
      "<": "\\u003C",
      "\\": "\\\\",
      "\b": "\\b",
      "\f": "\\f",
      "\n": "\\n",
      "\r": "\\r",
      "	": "\\t",
      "\u2028": "\\u2028",
      "\u2029": "\\u2029"
    };
    DevalueError = class extends Error {
      /**
       * @param {string} message
       * @param {string[]} keys
       */
      constructor(message2, keys) {
        super(message2);
        this.name = "DevalueError";
        this.path = keys.join("");
      }
    };
    object_proto_names = /* @__PURE__ */ Object.getOwnPropertyNames(
      Object.prototype
    ).sort().join("\0");
  }
});

// node_modules/devalue/src/uneval.js
function uneval(value, replacer) {
  const counts = /* @__PURE__ */ new Map();
  const keys = [];
  const custom = /* @__PURE__ */ new Map();
  function walk(thing) {
    if (typeof thing === "function") {
      throw new DevalueError(`Cannot stringify a function`, keys);
    }
    if (!is_primitive(thing)) {
      if (counts.has(thing)) {
        counts.set(thing, counts.get(thing) + 1);
        return;
      }
      counts.set(thing, 1);
      if (replacer) {
        const str2 = replacer(thing);
        if (typeof str2 === "string") {
          custom.set(thing, str2);
          return;
        }
      }
      const type = get_type(thing);
      switch (type) {
        case "Number":
        case "BigInt":
        case "String":
        case "Boolean":
        case "Date":
        case "RegExp":
          return;
        case "Array":
          thing.forEach((value2, i3) => {
            keys.push(`[${i3}]`);
            walk(value2);
            keys.pop();
          });
          break;
        case "Set":
          Array.from(thing).forEach(walk);
          break;
        case "Map":
          for (const [key2, value2] of thing) {
            keys.push(
              `.get(${is_primitive(key2) ? stringify_primitive(key2) : "..."})`
            );
            walk(value2);
            keys.pop();
          }
          break;
        default:
          if (!is_plain_object(thing)) {
            throw new DevalueError(
              `Cannot stringify arbitrary non-POJOs`,
              keys
            );
          }
          if (Object.getOwnPropertySymbols(thing).length > 0) {
            throw new DevalueError(
              `Cannot stringify POJOs with symbolic keys`,
              keys
            );
          }
          for (const key2 in thing) {
            keys.push(`.${key2}`);
            walk(thing[key2]);
            keys.pop();
          }
      }
    }
  }
  walk(value);
  const names = /* @__PURE__ */ new Map();
  Array.from(counts).filter((entry) => entry[1] > 1).sort((a3, b3) => b3[1] - a3[1]).forEach((entry, i3) => {
    names.set(entry[0], get_name(i3));
  });
  function stringify2(thing) {
    if (names.has(thing)) {
      return names.get(thing);
    }
    if (is_primitive(thing)) {
      return stringify_primitive(thing);
    }
    if (custom.has(thing)) {
      return custom.get(thing);
    }
    const type = get_type(thing);
    switch (type) {
      case "Number":
      case "String":
      case "Boolean":
        return `Object(${stringify2(thing.valueOf())})`;
      case "RegExp":
        return `new RegExp(${stringify_string(thing.source)}, "${thing.flags}")`;
      case "Date":
        return `new Date(${thing.getTime()})`;
      case "Array":
        const members = (
          /** @type {any[]} */
          thing.map(
            (v3, i3) => i3 in thing ? stringify2(v3) : ""
          )
        );
        const tail = thing.length === 0 || thing.length - 1 in thing ? "" : ",";
        return `[${members.join(",")}${tail}]`;
      case "Set":
      case "Map":
        return `new ${type}([${Array.from(thing).map(stringify2).join(",")}])`;
      default:
        const obj = `{${Object.keys(thing).map((key2) => `${safe_key(key2)}:${stringify2(thing[key2])}`).join(",")}}`;
        const proto = Object.getPrototypeOf(thing);
        if (proto === null) {
          return Object.keys(thing).length > 0 ? `Object.assign(Object.create(null),${obj})` : `Object.create(null)`;
        }
        return obj;
    }
  }
  const str = stringify2(value);
  if (names.size) {
    const params = [];
    const statements = [];
    const values = [];
    names.forEach((name, thing) => {
      params.push(name);
      if (custom.has(thing)) {
        values.push(
          /** @type {string} */
          custom.get(thing)
        );
        return;
      }
      if (is_primitive(thing)) {
        values.push(stringify_primitive(thing));
        return;
      }
      const type = get_type(thing);
      switch (type) {
        case "Number":
        case "String":
        case "Boolean":
          values.push(`Object(${stringify2(thing.valueOf())})`);
          break;
        case "RegExp":
          values.push(thing.toString());
          break;
        case "Date":
          values.push(`new Date(${thing.getTime()})`);
          break;
        case "Array":
          values.push(`Array(${thing.length})`);
          thing.forEach((v3, i3) => {
            statements.push(`${name}[${i3}]=${stringify2(v3)}`);
          });
          break;
        case "Set":
          values.push(`new Set`);
          statements.push(
            `${name}.${Array.from(thing).map((v3) => `add(${stringify2(v3)})`).join(".")}`
          );
          break;
        case "Map":
          values.push(`new Map`);
          statements.push(
            `${name}.${Array.from(thing).map(([k3, v3]) => `set(${stringify2(k3)}, ${stringify2(v3)})`).join(".")}`
          );
          break;
        default:
          values.push(
            Object.getPrototypeOf(thing) === null ? "Object.create(null)" : "{}"
          );
          Object.keys(thing).forEach((key2) => {
            statements.push(
              `${name}${safe_prop(key2)}=${stringify2(thing[key2])}`
            );
          });
      }
    });
    statements.push(`return ${str}`);
    return `(function(${params.join(",")}){${statements.join(
      ";"
    )}}(${values.join(",")}))`;
  } else {
    return str;
  }
}
function get_name(num) {
  let name = "";
  do {
    name = chars[num % chars.length] + name;
    num = ~~(num / chars.length) - 1;
  } while (num >= 0);
  return reserved.test(name) ? `${name}0` : name;
}
function escape_unsafe_char(c3) {
  return escaped[c3] || c3;
}
function escape_unsafe_chars(str) {
  return str.replace(unsafe_chars, escape_unsafe_char);
}
function safe_key(key2) {
  return /^[_$a-zA-Z][_$a-zA-Z0-9]*$/.test(key2) ? key2 : escape_unsafe_chars(JSON.stringify(key2));
}
function safe_prop(key2) {
  return /^[_$a-zA-Z][_$a-zA-Z0-9]*$/.test(key2) ? `.${key2}` : `[${escape_unsafe_chars(JSON.stringify(key2))}]`;
}
function stringify_primitive(thing) {
  if (typeof thing === "string")
    return stringify_string(thing);
  if (thing === void 0)
    return "void 0";
  if (thing === 0 && 1 / thing < 0)
    return "-0";
  const str = String(thing);
  if (typeof thing === "number")
    return str.replace(/^(-)?0\./, "$1.");
  if (typeof thing === "bigint")
    return thing + "n";
  return str;
}
var chars, unsafe_chars, reserved;
var init_uneval = __esm({
  "node_modules/devalue/src/uneval.js"() {
    init_utils();
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$";
    unsafe_chars = /[<\b\f\n\r\t\0\u2028\u2029]/g;
    reserved = /^(?:do|if|in|for|int|let|new|try|var|byte|case|char|else|enum|goto|long|this|void|with|await|break|catch|class|const|final|float|short|super|throw|while|yield|delete|double|export|import|native|return|switch|throws|typeof|boolean|default|extends|finally|package|private|abstract|continue|debugger|function|volatile|interface|protected|transient|implements|instanceof|synchronized)$/;
  }
});

// node_modules/devalue/src/constants.js
var UNDEFINED, HOLE, NAN, POSITIVE_INFINITY, NEGATIVE_INFINITY, NEGATIVE_ZERO;
var init_constants = __esm({
  "node_modules/devalue/src/constants.js"() {
    UNDEFINED = -1;
    HOLE = -2;
    NAN = -3;
    POSITIVE_INFINITY = -4;
    NEGATIVE_INFINITY = -5;
    NEGATIVE_ZERO = -6;
  }
});

// node_modules/devalue/src/parse.js
var init_parse = __esm({
  "node_modules/devalue/src/parse.js"() {
    init_constants();
  }
});

// node_modules/devalue/src/stringify.js
function stringify(value, reducers) {
  const stringified = [];
  const indexes = /* @__PURE__ */ new Map();
  const custom = [];
  for (const key2 in reducers) {
    custom.push({ key: key2, fn: reducers[key2] });
  }
  const keys = [];
  let p3 = 0;
  function flatten(thing) {
    if (typeof thing === "function") {
      throw new DevalueError(`Cannot stringify a function`, keys);
    }
    if (indexes.has(thing))
      return indexes.get(thing);
    if (thing === void 0)
      return UNDEFINED;
    if (Number.isNaN(thing))
      return NAN;
    if (thing === Infinity)
      return POSITIVE_INFINITY;
    if (thing === -Infinity)
      return NEGATIVE_INFINITY;
    if (thing === 0 && 1 / thing < 0)
      return NEGATIVE_ZERO;
    const index6 = p3++;
    indexes.set(thing, index6);
    for (const { key: key2, fn } of custom) {
      const value2 = fn(thing);
      if (value2) {
        stringified[index6] = `["${key2}",${flatten(value2)}]`;
        return index6;
      }
    }
    let str = "";
    if (is_primitive(thing)) {
      str = stringify_primitive2(thing);
    } else {
      const type = get_type(thing);
      switch (type) {
        case "Number":
        case "String":
        case "Boolean":
          str = `["Object",${stringify_primitive2(thing)}]`;
          break;
        case "BigInt":
          str = `["BigInt",${thing}]`;
          break;
        case "Date":
          str = `["Date","${thing.toISOString()}"]`;
          break;
        case "RegExp":
          const { source, flags } = thing;
          str = flags ? `["RegExp",${stringify_string(source)},"${flags}"]` : `["RegExp",${stringify_string(source)}]`;
          break;
        case "Array":
          str = "[";
          for (let i3 = 0; i3 < thing.length; i3 += 1) {
            if (i3 > 0)
              str += ",";
            if (i3 in thing) {
              keys.push(`[${i3}]`);
              str += flatten(thing[i3]);
              keys.pop();
            } else {
              str += HOLE;
            }
          }
          str += "]";
          break;
        case "Set":
          str = '["Set"';
          for (const value2 of thing) {
            str += `,${flatten(value2)}`;
          }
          str += "]";
          break;
        case "Map":
          str = '["Map"';
          for (const [key2, value2] of thing) {
            keys.push(
              `.get(${is_primitive(key2) ? stringify_primitive2(key2) : "..."})`
            );
            str += `,${flatten(key2)},${flatten(value2)}`;
          }
          str += "]";
          break;
        default:
          if (!is_plain_object(thing)) {
            throw new DevalueError(
              `Cannot stringify arbitrary non-POJOs`,
              keys
            );
          }
          if (Object.getOwnPropertySymbols(thing).length > 0) {
            throw new DevalueError(
              `Cannot stringify POJOs with symbolic keys`,
              keys
            );
          }
          if (Object.getPrototypeOf(thing) === null) {
            str = '["null"';
            for (const key2 in thing) {
              keys.push(`.${key2}`);
              str += `,${stringify_string(key2)},${flatten(thing[key2])}`;
              keys.pop();
            }
            str += "]";
          } else {
            str = "{";
            let started = false;
            for (const key2 in thing) {
              if (started)
                str += ",";
              started = true;
              keys.push(`.${key2}`);
              str += `${stringify_string(key2)}:${flatten(thing[key2])}`;
              keys.pop();
            }
            str += "}";
          }
      }
    }
    stringified[index6] = str;
    return index6;
  }
  const index5 = flatten(value);
  if (index5 < 0)
    return `${index5}`;
  return `[${stringified.join(",")}]`;
}
function stringify_primitive2(thing) {
  const type = typeof thing;
  if (type === "string")
    return stringify_string(thing);
  if (thing instanceof String)
    return stringify_string(thing.toString());
  if (thing === void 0)
    return UNDEFINED.toString();
  if (thing === 0 && 1 / thing < 0)
    return NEGATIVE_ZERO.toString();
  if (type === "bigint")
    return `["BigInt","${thing}"]`;
  return String(thing);
}
var init_stringify = __esm({
  "node_modules/devalue/src/stringify.js"() {
    init_utils();
    init_constants();
  }
});

// node_modules/devalue/index.js
var init_devalue = __esm({
  "node_modules/devalue/index.js"() {
    init_uneval();
    init_parse();
    init_stringify();
  }
});

// .svelte-kit/output/server/chunks/index2.js
function readable(value, start) {
  return {
    subscribe: writable(value, start).subscribe
  };
}
function writable(value, start = noop) {
  let stop;
  const subscribers = /* @__PURE__ */ new Set();
  function set(new_value) {
    if (safe_not_equal(value, new_value)) {
      value = new_value;
      if (stop) {
        const run_queue = !subscriber_queue.length;
        for (const subscriber of subscribers) {
          subscriber[1]();
          subscriber_queue.push(subscriber, value);
        }
        if (run_queue) {
          for (let i3 = 0; i3 < subscriber_queue.length; i3 += 2) {
            subscriber_queue[i3][0](subscriber_queue[i3 + 1]);
          }
          subscriber_queue.length = 0;
        }
      }
    }
  }
  function update(fn) {
    set(fn(value));
  }
  function subscribe2(run2, invalidate = noop) {
    const subscriber = [run2, invalidate];
    subscribers.add(subscriber);
    if (subscribers.size === 1) {
      stop = start(set, update) || noop;
    }
    run2(value);
    return () => {
      subscribers.delete(subscriber);
      if (subscribers.size === 0 && stop) {
        stop();
        stop = null;
      }
    };
  }
  return { set, update, subscribe: subscribe2 };
}
var subscriber_queue;
var init_index2 = __esm({
  ".svelte-kit/output/server/chunks/index2.js"() {
    init_ssr();
    subscriber_queue = [];
  }
});

// .svelte-kit/output/server/entries/pages/_layout.server.ts.js
var layout_server_ts_exports = {};
__export(layout_server_ts_exports, {
  config: () => config,
  load: () => load
});
var config, load;
var init_layout_server_ts = __esm({
  ".svelte-kit/output/server/entries/pages/_layout.server.ts.js"() {
    config = {
      runtime: "edge"
    };
    load = async (event) => {
      return {
        session: await event.locals.auth()
      };
    };
  }
});

// .svelte-kit/output/server/chunks/stores.js
function get(key2, parse6 = JSON.parse) {
  try {
    return parse6(sessionStorage[key2]);
  } catch {
  }
}
var SNAPSHOT_KEY, SCROLL_KEY, getStores, page;
var init_stores = __esm({
  ".svelte-kit/output/server/chunks/stores.js"() {
    init_ssr();
    init_exports();
    init_devalue();
    SNAPSHOT_KEY = "sveltekit:snapshot";
    SCROLL_KEY = "sveltekit:scroll";
    get(SCROLL_KEY) ?? {};
    get(SNAPSHOT_KEY) ?? {};
    getStores = () => {
      const stores = getContext("__svelte__");
      return {
        /** @type {typeof page} */
        page: {
          subscribe: stores.page.subscribe
        },
        /** @type {typeof navigating} */
        navigating: {
          subscribe: stores.navigating.subscribe
        },
        /** @type {typeof updated} */
        updated: stores.updated
      };
    };
    page = {
      subscribe(fn) {
        const store = getStores().page;
        return store.subscribe(fn);
      }
    };
  }
});

// .svelte-kit/output/server/entries/pages/_layout.svelte.js
var layout_svelte_exports = {};
__export(layout_svelte_exports, {
  default: () => Layout
});
var Layout;
var init_layout_svelte = __esm({
  ".svelte-kit/output/server/entries/pages/_layout.svelte.js"() {
    init_ssr();
    init_stores();
    Layout = create_ssr_component(($$result, $$props, $$bindings, slots) => {
      let $page, $$unsubscribe_page;
      $$unsubscribe_page = subscribe(page, (value) => $page = value);
      $$unsubscribe_page();
      return `<div class="container mx-auto my-6 max-w-lg">${$page.data.session ? `<hgroup data-svelte-h="svelte-1mybkef"><h2><a href="/" class="text-sm text-center text-gray-800 md:text-lg">Home Page</a></h2></hgroup>` : ``} ${slots.default ? slots.default({}) : ``}</div>`;
    });
  }
});

// .svelte-kit/output/server/nodes/0.js
var __exports = {};
__export(__exports, {
  component: () => component,
  fonts: () => fonts,
  imports: () => imports,
  index: () => index,
  server: () => layout_server_ts_exports,
  server_id: () => server_id,
  stylesheets: () => stylesheets
});
var index, component_cache, component, server_id, imports, stylesheets, fonts;
var init__ = __esm({
  ".svelte-kit/output/server/nodes/0.js"() {
    init_layout_server_ts();
    index = 0;
    component = async () => component_cache ?? (component_cache = (await Promise.resolve().then(() => (init_layout_svelte(), layout_svelte_exports))).default);
    server_id = "src/routes/+layout.server.ts";
    imports = ["_app/immutable/nodes/0.crcIh9Zg.js", "_app/immutable/chunks/scheduler.Rzn6huuy.js", "_app/immutable/chunks/index.D6xxGKKq.js", "_app/immutable/chunks/stores.BHG8Ifde.js", "_app/immutable/chunks/entry.Dz1v4b8z.js"];
    stylesheets = ["_app/immutable/assets/0.CwaW_QGf.css"];
    fonts = [];
  }
});

// .svelte-kit/output/server/entries/fallbacks/error.svelte.js
var error_svelte_exports = {};
__export(error_svelte_exports, {
  default: () => Error2
});
var Error2;
var init_error_svelte = __esm({
  ".svelte-kit/output/server/entries/fallbacks/error.svelte.js"() {
    init_ssr();
    init_stores();
    Error2 = create_ssr_component(($$result, $$props, $$bindings, slots) => {
      let $page, $$unsubscribe_page;
      $$unsubscribe_page = subscribe(page, (value) => $page = value);
      $$unsubscribe_page();
      return `<h1>${escape($page.status)}</h1> <p>${escape($page.error?.message)}</p>`;
    });
  }
});

// .svelte-kit/output/server/nodes/1.js
var __exports2 = {};
__export(__exports2, {
  component: () => component2,
  fonts: () => fonts2,
  imports: () => imports2,
  index: () => index2,
  stylesheets: () => stylesheets2
});
var index2, component_cache2, component2, imports2, stylesheets2, fonts2;
var init__2 = __esm({
  ".svelte-kit/output/server/nodes/1.js"() {
    index2 = 1;
    component2 = async () => component_cache2 ?? (component_cache2 = (await Promise.resolve().then(() => (init_error_svelte(), error_svelte_exports))).default);
    imports2 = ["_app/immutable/nodes/1.CB6f6LEP.js", "_app/immutable/chunks/scheduler.Rzn6huuy.js", "_app/immutable/chunks/index.D6xxGKKq.js", "_app/immutable/chunks/stores.BHG8Ifde.js", "_app/immutable/chunks/entry.Dz1v4b8z.js"];
    stylesheets2 = [];
    fonts2 = [];
  }
});

// .svelte-kit/output/server/entries/pages/_page.server.ts.js
var page_server_ts_exports = {};
__export(page_server_ts_exports, {
  actions: () => actions2,
  config: () => config2,
  load: () => load2
});
var config2, load2, actions2;
var init_page_server_ts = __esm({
  ".svelte-kit/output/server/entries/pages/_page.server.ts.js"() {
    init_prisma();
    init_chunks();
    config2 = {
      runtime: "edge"
    };
    load2 = async ({ locals }) => {
      const session2 = await locals.auth();
      return {
        todos: await prisma.todo.findMany(),
        session: session2
      };
    };
    actions2 = {
      createTodo: async ({ request, locals }) => {
        const session2 = await locals.auth();
        if (!session2) {
          console.log("No session found!");
        }
        const data = await request.formData();
        const { text: text2, image } = Object.fromEntries(data);
        try {
          const prismaUser = await prisma.user.findUnique({
            where: {
              email: session2?.user?.email
            }
          });
          await prisma.todo.create({
            data: {
              text: text2,
              image,
              userId: prismaUser?.id
            }
          });
        } catch (error) {
          console.error(error);
          return fail(500, { message: "Could not create todo" });
        }
        return {
          status: 201
        };
      },
      deleteTodo: async ({ url }) => {
        const id = url.searchParams.get("id");
        if (!id) {
          return fail(400, { message: "Invalid request" });
        }
        try {
          await prisma.todo.delete({
            where: {
              id: Number(id)
            }
          });
        } catch (error) {
          console.error(error);
          return fail(500, { message: "Something went wrong in delete" });
        }
        return {
          status: 200
        };
      }
    };
  }
});

// .svelte-kit/output/server/entries/pages/_page.svelte.js
var page_svelte_exports = {};
__export(page_svelte_exports, {
  default: () => Page
});
var TodoForm, Page;
var init_page_svelte = __esm({
  ".svelte-kit/output/server/entries/pages/_page.svelte.js"() {
    init_ssr();
    init_devalue();
    init_stores();
    init_index2();
    TodoForm = create_ssr_component(($$result, $$props, $$bindings, slots) => {
      let { baseImage = writable("") } = $$props;
      let base642;
      if ($$props.baseImage === void 0 && $$bindings.baseImage && baseImage !== void 0)
        $$bindings.baseImage(baseImage);
      return `  <form class="my-6" action="?/createTodo" method="post" enctype="multipart/form-data"><div class="flex flex-col text-sm mb-2 space-y-2"><label for="todo" class="font-bold mb-2 text-gray-800" data-svelte-h="svelte-1vd8zs6">Todo</label> <input type="text" name="text" id="text" placeholder="What you gonna do?" class="appearance-none shadow-sm border border-gray-200 p-2 focus:outline-none focus:border-gray-500 rounded-lg" autocomplete="off"> <input type="hidden" name="image"${add_attribute("value", base642, 0)}> <input type="file" accept="image/*" class="w-full shadow-sm rounded bg-gray-500 hover:bg-gray-600 text-white py-2 px-4" id="image"></div> <button type="submit" class="w-full shadow-sm rounded bg-blue-500 hover:bg-blue-600 text-white py-2 px-4" data-svelte-h="svelte-17lmbkk">Submit</button></form>`;
    });
    Page = create_ssr_component(($$result, $$props, $$bindings, slots) => {
      let todos;
      let $page, $$unsubscribe_page;
      $$unsubscribe_page = subscribe(page, (value) => $page = value);
      let { data } = $$props;
      if ($$props.data === void 0 && $$bindings.data && data !== void 0)
        $$bindings.data(data);
      ({ todos } = data);
      $$unsubscribe_page();
      return `<main><div>${$page.data.session ? `<p>Signed in as ${escape($page.data.session.user?.name)}</p> <h1 class="text-2xl font-bold text-center text-gray-800 md:text-3xl" data-svelte-h="svelte-9u0k6o">My todos</h1> ${validate_component(TodoForm, "TodoForm").$$render($$result, {}, {}, {})} ${each(todos, (todo) => {
        return `<li class="bg-white flex space-x-3 items-center shadow-sm border border-gray-200 rounded-lg my-2 py-2 px-4 "><img${add_attribute("src", todo.image, 0)} alt="base64_image" class="size-10"> <span${add_attribute("class", "flex-1 text-gray-800", 0)}>${escape(todo.text)}</span> <a href="${"/update/" + escape(todo.id, true)}" role="button" class="text-sm bg-gray-500 hover:bg-gray-600 text-white py-1 px-2 rounded focus:outline-none focus:shadow-outline">Edit</a> <form action="${"?/deleteTodo&id=" + escape(todo.id, true)}" method="post"><button type="submit" class="text-sm bg-red-500 hover:bg-red-600 text-white py-1 px-2 rounded focus:outline-none focus:shadow-outline" data-svelte-h="svelte-5bceyc">Delete
                        </button></form> </li>`;
      })} <button class="bg-gray-700 py-1 px-2 rounded text-white" data-svelte-h="svelte-e2fbar">Sign Out</button>` : `<h1 class="text-2xl font-bold text-center text-gray-800 md:text-3xl" data-svelte-h="svelte-li3w2t">Sign In</h1> <button class="bg-gray-700 py-1 px-2 rounded text-white" data-svelte-h="svelte-1gdgxqv">Sign In with GitHub</button>`}</div></main>`;
    });
  }
});

// .svelte-kit/output/server/nodes/2.js
var __exports3 = {};
__export(__exports3, {
  component: () => component3,
  fonts: () => fonts3,
  imports: () => imports3,
  index: () => index3,
  server: () => page_server_ts_exports,
  server_id: () => server_id2,
  stylesheets: () => stylesheets3
});
var index3, component_cache3, component3, server_id2, imports3, stylesheets3, fonts3;
var init__3 = __esm({
  ".svelte-kit/output/server/nodes/2.js"() {
    init_page_server_ts();
    index3 = 2;
    component3 = async () => component_cache3 ?? (component_cache3 = (await Promise.resolve().then(() => (init_page_svelte(), page_svelte_exports))).default);
    server_id2 = "src/routes/+page.server.ts";
    imports3 = ["_app/immutable/nodes/2.amZVOODV.js", "_app/immutable/chunks/scheduler.Rzn6huuy.js", "_app/immutable/chunks/index.D6xxGKKq.js", "_app/immutable/chunks/entry.Dz1v4b8z.js", "_app/immutable/chunks/stores.BHG8Ifde.js"];
    stylesheets3 = [];
    fonts3 = [];
  }
});

// .svelte-kit/output/server/entries/pages/update/_todoid_/_page.server.ts.js
var page_server_ts_exports2 = {};
__export(page_server_ts_exports2, {
  actions: () => actions3,
  config: () => config3,
  load: () => load3
});
var config3, load3, actions3;
var init_page_server_ts2 = __esm({
  ".svelte-kit/output/server/entries/pages/update/_todoid_/_page.server.ts.js"() {
    init_prisma();
    init_chunks();
    config3 = {
      runtime: "edge"
    };
    load3 = async ({ params: { todoid } }) => {
      const todo = await prisma.todo.findUnique({
        where: {
          id: Number(todoid)
        }
      });
      return { todo };
    };
    actions3 = {
      updateTodo: async ({ request, params }) => {
        const data = await request.formData();
        const { text: text2 } = Object.fromEntries(data);
        try {
          await prisma.todo.update({
            where: {
              id: Number(params.todoid)
            },
            data: {
              text: text2
            }
          });
        } catch (error2) {
          console.error(error2);
          return fail(500, { message: "Could not update todo" });
        }
        return {
          status: 200
        };
      }
    };
  }
});

// .svelte-kit/output/server/entries/pages/update/_todoid_/_page.svelte.js
var page_svelte_exports2 = {};
__export(page_svelte_exports2, {
  default: () => Page2
});
var Page2;
var init_page_svelte2 = __esm({
  ".svelte-kit/output/server/entries/pages/update/_todoid_/_page.svelte.js"() {
    init_ssr();
    Page2 = create_ssr_component(($$result, $$props, $$bindings, slots) => {
      let todo;
      let { data } = $$props;
      if ($$props.data === void 0 && $$bindings.data && data !== void 0)
        $$bindings.data(data);
      ({ todo } = data);
      return `<form class="my-6" action="?/updateTodo" method="post"><div class="flex flex-col text-sm mb-2"><label for="todo" class="font-bold mb-2 text-gray-800" data-svelte-h="svelte-1vd8zs6">Todo</label> <input type="text"${add_attribute("value", todo?.text, 0)} name="text" id="text" placeholder="What you gonna do?" class="appearance-none shadow-sm border border-gray-200 p-2 focus:outline-none focus:border-gray-500 rounded-lg" autocomplete="off"></div> <button type="submit" class="w-full shadow-sm rounded bg-blue-500 hover:bg-blue-600 text-white py-2 px-4" data-svelte-h="svelte-1anhru4">Done</button></form>`;
    });
  }
});

// .svelte-kit/output/server/nodes/3.js
var __exports4 = {};
__export(__exports4, {
  component: () => component4,
  fonts: () => fonts4,
  imports: () => imports4,
  index: () => index4,
  server: () => page_server_ts_exports2,
  server_id: () => server_id3,
  stylesheets: () => stylesheets4
});
var index4, component_cache4, component4, server_id3, imports4, stylesheets4, fonts4;
var init__4 = __esm({
  ".svelte-kit/output/server/nodes/3.js"() {
    init_page_server_ts2();
    index4 = 3;
    component4 = async () => component_cache4 ?? (component_cache4 = (await Promise.resolve().then(() => (init_page_svelte2(), page_svelte_exports2))).default);
    server_id3 = "src/routes/update/[todoid]/+page.server.ts";
    imports4 = ["_app/immutable/nodes/3.ZJYJJXTg.js", "_app/immutable/chunks/scheduler.Rzn6huuy.js", "_app/immutable/chunks/index.D6xxGKKq.js"];
    stylesheets4 = [];
    fonts4 = [];
  }
});

// .svelte-kit/output/server/index.js
init_prod_ssr();
init_internal();
init_chunks();
init_exports();
init_devalue();
init_index2();
var import_cookie6 = __toESM(require_cookie(), 1);
var set_cookie_parser = __toESM(require_set_cookie(), 1);
var SVELTE_KIT_ASSETS = "/_svelte_kit_assets";
var ENDPOINT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
var PAGE_METHODS = ["GET", "POST", "HEAD"];
function negotiate(accept, types2) {
  const parts = [];
  accept.split(",").forEach((str, i3) => {
    const match = /([^/]+)\/([^;]+)(?:;q=([0-9.]+))?/.exec(str);
    if (match) {
      const [, type, subtype, q = "1"] = match;
      parts.push({ type, subtype, q: +q, i: i3 });
    }
  });
  parts.sort((a3, b3) => {
    if (a3.q !== b3.q) {
      return b3.q - a3.q;
    }
    if (a3.subtype === "*" !== (b3.subtype === "*")) {
      return a3.subtype === "*" ? 1 : -1;
    }
    if (a3.type === "*" !== (b3.type === "*")) {
      return a3.type === "*" ? 1 : -1;
    }
    return a3.i - b3.i;
  });
  let accepted;
  let min_priority = Infinity;
  for (const mimetype of types2) {
    const [type, subtype] = mimetype.split("/");
    const priority = parts.findIndex(
      (part) => (part.type === type || part.type === "*") && (part.subtype === subtype || part.subtype === "*")
    );
    if (priority !== -1 && priority < min_priority) {
      accepted = mimetype;
      min_priority = priority;
    }
  }
  return accepted;
}
function is_content_type(request, ...types2) {
  const type = request.headers.get("content-type")?.split(";", 1)[0].trim() ?? "";
  return types2.includes(type.toLowerCase());
}
function is_form_content_type(request) {
  return is_content_type(
    request,
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain"
  );
}
function coalesce_to_error(err) {
  return err instanceof Error || err && /** @type {any} */
  err.name && /** @type {any} */
  err.message ? (
    /** @type {Error} */
    err
  ) : new Error(JSON.stringify(err));
}
function normalize_error(error) {
  return (
    /** @type {import('../runtime/control.js').Redirect | HttpError | SvelteKitError | Error} */
    error
  );
}
function get_status(error) {
  return error instanceof HttpError || error instanceof SvelteKitError ? error.status : 500;
}
function get_message(error) {
  return error instanceof SvelteKitError ? error.text : "Internal Error";
}
function method_not_allowed(mod, method) {
  return text(`${method} method not allowed`, {
    status: 405,
    headers: {
      // https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/405
      // "The server must generate an Allow header field in a 405 status code response"
      allow: allowed_methods(mod).join(", ")
    }
  });
}
function allowed_methods(mod) {
  const allowed = ENDPOINT_METHODS.filter((method) => method in mod);
  if ("GET" in mod || "HEAD" in mod)
    allowed.push("HEAD");
  return allowed;
}
function static_error_page(options2, status, message2) {
  let page2 = options2.templates.error({ status, message: message2 });
  return text(page2, {
    headers: { "content-type": "text/html; charset=utf-8" },
    status
  });
}
async function handle_fatal_error(event, options2, error) {
  error = error instanceof HttpError ? error : coalesce_to_error(error);
  const status = get_status(error);
  const body2 = await handle_error_and_jsonify(event, options2, error);
  const type = negotiate(event.request.headers.get("accept") || "text/html", [
    "application/json",
    "text/html"
  ]);
  if (event.isDataRequest || type === "application/json") {
    return json(body2, {
      status
    });
  }
  return static_error_page(options2, status, body2.message);
}
async function handle_error_and_jsonify(event, options2, error) {
  if (error instanceof HttpError) {
    return error.body;
  }
  const status = get_status(error);
  const message2 = get_message(error);
  return await options2.hooks.handleError({ error, event, status, message: message2 }) ?? { message: message2 };
}
function redirect_response(status, location) {
  const response = new Response(void 0, {
    status,
    headers: { location }
  });
  return response;
}
function clarify_devalue_error(event, error) {
  if (error.path) {
    return `Data returned from \`load\` while rendering ${event.route.id} is not serializable: ${error.message} (data${error.path})`;
  }
  if (error.path === "") {
    return `Data returned from \`load\` while rendering ${event.route.id} is not a plain object`;
  }
  return error.message;
}
function stringify_uses(node) {
  const uses = [];
  if (node.uses && node.uses.dependencies.size > 0) {
    uses.push(`"dependencies":${JSON.stringify(Array.from(node.uses.dependencies))}`);
  }
  if (node.uses && node.uses.search_params.size > 0) {
    uses.push(`"search_params":${JSON.stringify(Array.from(node.uses.search_params))}`);
  }
  if (node.uses && node.uses.params.size > 0) {
    uses.push(`"params":${JSON.stringify(Array.from(node.uses.params))}`);
  }
  if (node.uses?.parent)
    uses.push('"parent":1');
  if (node.uses?.route)
    uses.push('"route":1');
  if (node.uses?.url)
    uses.push('"url":1');
  return `"uses":{${uses.join(",")}}`;
}
async function render_endpoint(event, mod, state2) {
  const method = (
    /** @type {import('types').HttpMethod} */
    event.request.method
  );
  let handler = mod[method] || mod.fallback;
  if (method === "HEAD" && mod.GET && !mod.HEAD) {
    handler = mod.GET;
  }
  if (!handler) {
    return method_not_allowed(mod, method);
  }
  const prerender = mod.prerender ?? state2.prerender_default;
  if (prerender && (mod.POST || mod.PATCH || mod.PUT || mod.DELETE)) {
    throw new Error("Cannot prerender endpoints that have mutative methods");
  }
  if (state2.prerendering && !prerender) {
    if (state2.depth > 0) {
      throw new Error(`${event.route.id} is not prerenderable`);
    } else {
      return new Response(void 0, { status: 204 });
    }
  }
  try {
    let response = await handler(
      /** @type {import('@sveltejs/kit').RequestEvent<Record<string, any>>} */
      event
    );
    if (!(response instanceof Response)) {
      throw new Error(
        `Invalid response from route ${event.url.pathname}: handler should return a Response object`
      );
    }
    if (state2.prerendering) {
      response = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: new Headers(response.headers)
      });
      response.headers.set("x-sveltekit-prerender", String(prerender));
    }
    return response;
  } catch (e2) {
    if (e2 instanceof Redirect) {
      return new Response(void 0, {
        status: e2.status,
        headers: { location: e2.location }
      });
    }
    throw e2;
  }
}
function is_endpoint_request(event) {
  const { method, headers: headers2 } = event.request;
  if (ENDPOINT_METHODS.includes(method) && !PAGE_METHODS.includes(method)) {
    return true;
  }
  if (method === "POST" && headers2.get("x-sveltekit-action") === "true")
    return false;
  const accept = event.request.headers.get("accept") ?? "*/*";
  return negotiate(accept, ["*", "text/html"]) !== "text/html";
}
function compact(arr) {
  return arr.filter(
    /** @returns {val is NonNullable<T>} */
    (val) => val != null
  );
}
function is_action_json_request(event) {
  const accept = negotiate(event.request.headers.get("accept") ?? "*/*", [
    "application/json",
    "text/html"
  ]);
  return accept === "application/json" && event.request.method === "POST";
}
async function handle_action_json_request(event, options2, server2) {
  const actions4 = server2?.actions;
  if (!actions4) {
    const no_actions_error = new SvelteKitError(
      405,
      "Method Not Allowed",
      "POST method not allowed. No actions exist for this page"
    );
    return action_json(
      {
        type: "error",
        error: await handle_error_and_jsonify(event, options2, no_actions_error)
      },
      {
        status: no_actions_error.status,
        headers: {
          // https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/405
          // "The server must generate an Allow header field in a 405 status code response"
          allow: "GET"
        }
      }
    );
  }
  check_named_default_separate(actions4);
  try {
    const data = await call_action(event, actions4);
    if (false)
      ;
    if (data instanceof ActionFailure) {
      return action_json({
        type: "failure",
        status: data.status,
        // @ts-expect-error we assign a string to what is supposed to be an object. That's ok
        // because we don't use the object outside, and this way we have better code navigation
        // through knowing where the related interface is used.
        data: stringify_action_response(
          data.data,
          /** @type {string} */
          event.route.id
        )
      });
    } else {
      return action_json({
        type: "success",
        status: data ? 200 : 204,
        // @ts-expect-error see comment above
        data: stringify_action_response(
          data,
          /** @type {string} */
          event.route.id
        )
      });
    }
  } catch (e2) {
    const err = normalize_error(e2);
    if (err instanceof Redirect) {
      return action_json_redirect(err);
    }
    return action_json(
      {
        type: "error",
        error: await handle_error_and_jsonify(event, options2, check_incorrect_fail_use(err))
      },
      {
        status: get_status(err)
      }
    );
  }
}
function check_incorrect_fail_use(error) {
  return error instanceof ActionFailure ? new Error('Cannot "throw fail()". Use "return fail()"') : error;
}
function action_json_redirect(redirect2) {
  return action_json({
    type: "redirect",
    status: redirect2.status,
    location: redirect2.location
  });
}
function action_json(data, init22) {
  return json(data, init22);
}
function is_action_request(event) {
  return event.request.method === "POST";
}
async function handle_action_request(event, server2) {
  const actions4 = server2?.actions;
  if (!actions4) {
    event.setHeaders({
      // https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/405
      // "The server must generate an Allow header field in a 405 status code response"
      allow: "GET"
    });
    return {
      type: "error",
      error: new SvelteKitError(
        405,
        "Method Not Allowed",
        "POST method not allowed. No actions exist for this page"
      )
    };
  }
  check_named_default_separate(actions4);
  try {
    const data = await call_action(event, actions4);
    if (false)
      ;
    if (data instanceof ActionFailure) {
      return {
        type: "failure",
        status: data.status,
        data: data.data
      };
    } else {
      return {
        type: "success",
        status: 200,
        // @ts-expect-error this will be removed upon serialization, so `undefined` is the same as omission
        data
      };
    }
  } catch (e2) {
    const err = normalize_error(e2);
    if (err instanceof Redirect) {
      return {
        type: "redirect",
        status: err.status,
        location: err.location
      };
    }
    return {
      type: "error",
      error: check_incorrect_fail_use(err)
    };
  }
}
function check_named_default_separate(actions4) {
  if (actions4.default && Object.keys(actions4).length > 1) {
    throw new Error(
      "When using named actions, the default action cannot be used. See the docs for more info: https://kit.svelte.dev/docs/form-actions#named-actions"
    );
  }
}
async function call_action(event, actions4) {
  const url = new URL(event.request.url);
  let name = "default";
  for (const param of url.searchParams) {
    if (param[0].startsWith("/")) {
      name = param[0].slice(1);
      if (name === "default") {
        throw new Error('Cannot use reserved action name "default"');
      }
      break;
    }
  }
  const action = actions4[name];
  if (!action) {
    throw new SvelteKitError(404, "Not Found", `No action with name '${name}' found`);
  }
  if (!is_form_content_type(event.request)) {
    throw new SvelteKitError(
      415,
      "Unsupported Media Type",
      `Form actions expect form-encoded data \u2014 received ${event.request.headers.get(
        "content-type"
      )}`
    );
  }
  return action(event);
}
function uneval_action_response(data, route_id) {
  return try_deserialize(data, uneval, route_id);
}
function stringify_action_response(data, route_id) {
  return try_deserialize(data, stringify, route_id);
}
function try_deserialize(data, fn, route_id) {
  try {
    return fn(data);
  } catch (e2) {
    const error = (
      /** @type {any} */
      e2
    );
    if ("path" in error) {
      let message2 = `Data returned from action inside ${route_id} is not serializable: ${error.message}`;
      if (error.path !== "")
        message2 += ` (data.${error.path})`;
      throw new Error(message2);
    }
    throw error;
  }
}
var INVALIDATED_PARAM = "x-sveltekit-invalidated";
var TRAILING_SLASH_PARAM = "x-sveltekit-trailing-slash";
function b64_encode(buffer) {
  if (globalThis.Buffer) {
    return Buffer.from(buffer).toString("base64");
  }
  const little_endian = new Uint8Array(new Uint16Array([1]).buffer)[0] > 0;
  return btoa(
    new TextDecoder(little_endian ? "utf-16le" : "utf-16be").decode(
      new Uint16Array(new Uint8Array(buffer))
    )
  );
}
async function load_server_data({ event, state: state2, node, parent }) {
  if (!node?.server)
    return null;
  let is_tracking = true;
  const uses = {
    dependencies: /* @__PURE__ */ new Set(),
    params: /* @__PURE__ */ new Set(),
    parent: false,
    route: false,
    url: false,
    search_params: /* @__PURE__ */ new Set()
  };
  const url = make_trackable(
    event.url,
    () => {
      if (is_tracking) {
        uses.url = true;
      }
    },
    (param) => {
      if (is_tracking) {
        uses.search_params.add(param);
      }
    }
  );
  if (state2.prerendering) {
    disable_search(url);
  }
  const result = await node.server.load?.call(null, {
    ...event,
    fetch: (info, init22) => {
      new URL(info instanceof Request ? info.url : info, event.url);
      return event.fetch(info, init22);
    },
    /** @param {string[]} deps */
    depends: (...deps) => {
      for (const dep of deps) {
        const { href } = new URL(dep, event.url);
        uses.dependencies.add(href);
      }
    },
    params: new Proxy(event.params, {
      get: (target, key2) => {
        if (is_tracking) {
          uses.params.add(key2);
        }
        return target[
          /** @type {string} */
          key2
        ];
      }
    }),
    parent: async () => {
      if (is_tracking) {
        uses.parent = true;
      }
      return parent();
    },
    route: new Proxy(event.route, {
      get: (target, key2) => {
        if (is_tracking) {
          uses.route = true;
        }
        return target[
          /** @type {'id'} */
          key2
        ];
      }
    }),
    url,
    untrack(fn) {
      is_tracking = false;
      try {
        return fn();
      } finally {
        is_tracking = true;
      }
    }
  });
  return {
    type: "data",
    data: result ?? null,
    uses,
    slash: node.server.trailingSlash
  };
}
async function load_data({
  event,
  fetched,
  node,
  parent,
  server_data_promise,
  state: state2,
  resolve_opts,
  csr
}) {
  const server_data_node = await server_data_promise;
  if (!node?.universal?.load) {
    return server_data_node?.data ?? null;
  }
  const result = await node.universal.load.call(null, {
    url: event.url,
    params: event.params,
    data: server_data_node?.data ?? null,
    route: event.route,
    fetch: create_universal_fetch(event, state2, fetched, csr, resolve_opts),
    setHeaders: event.setHeaders,
    depends: () => {
    },
    parent,
    untrack: (fn) => fn()
  });
  return result ?? null;
}
function create_universal_fetch(event, state2, fetched, csr, resolve_opts) {
  const universal_fetch = async (input, init22) => {
    const cloned_body = input instanceof Request && input.body ? input.clone().body : null;
    const cloned_headers = input instanceof Request && [...input.headers].length ? new Headers(input.headers) : init22?.headers;
    let response = await event.fetch(input, init22);
    const url = new URL(input instanceof Request ? input.url : input, event.url);
    const same_origin = url.origin === event.url.origin;
    let dependency;
    if (same_origin) {
      if (state2.prerendering) {
        dependency = { response, body: null };
        state2.prerendering.dependencies.set(url.pathname, dependency);
      }
    } else {
      const mode = input instanceof Request ? input.mode : init22?.mode ?? "cors";
      if (mode === "no-cors") {
        response = new Response("", {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers
        });
      } else {
        const acao = response.headers.get("access-control-allow-origin");
        if (!acao || acao !== event.url.origin && acao !== "*") {
          throw new Error(
            `CORS error: ${acao ? "Incorrect" : "No"} 'Access-Control-Allow-Origin' header is present on the requested resource`
          );
        }
      }
    }
    const proxy = new Proxy(response, {
      get(response2, key2, _receiver) {
        async function push_fetched(body2, is_b64) {
          const status_number = Number(response2.status);
          if (isNaN(status_number)) {
            throw new Error(
              `response.status is not a number. value: "${response2.status}" type: ${typeof response2.status}`
            );
          }
          fetched.push({
            url: same_origin ? url.href.slice(event.url.origin.length) : url.href,
            method: event.request.method,
            request_body: (
              /** @type {string | ArrayBufferView | undefined} */
              input instanceof Request && cloned_body ? await stream_to_string(cloned_body) : init22?.body
            ),
            request_headers: cloned_headers,
            response_body: body2,
            response: response2,
            is_b64
          });
        }
        if (key2 === "arrayBuffer") {
          return async () => {
            const buffer = await response2.arrayBuffer();
            if (dependency) {
              dependency.body = new Uint8Array(buffer);
            }
            if (buffer instanceof ArrayBuffer) {
              await push_fetched(b64_encode(buffer), true);
            }
            return buffer;
          };
        }
        async function text2() {
          const body2 = await response2.text();
          if (!body2 || typeof body2 === "string") {
            await push_fetched(body2, false);
          }
          if (dependency) {
            dependency.body = body2;
          }
          return body2;
        }
        if (key2 === "text") {
          return text2;
        }
        if (key2 === "json") {
          return async () => {
            return JSON.parse(await text2());
          };
        }
        return Reflect.get(response2, key2, response2);
      }
    });
    if (csr) {
      const get2 = response.headers.get;
      response.headers.get = (key2) => {
        const lower = key2.toLowerCase();
        const value = get2.call(response.headers, lower);
        if (value && !lower.startsWith("x-sveltekit-")) {
          const included = resolve_opts.filterSerializedResponseHeaders(lower, value);
          if (!included) {
            throw new Error(
              `Failed to get response header "${lower}" \u2014 it must be included by the \`filterSerializedResponseHeaders\` option: https://kit.svelte.dev/docs/hooks#server-hooks-handle (at ${event.route.id})`
            );
          }
        }
        return value;
      };
    }
    return proxy;
  };
  return (input, init22) => {
    const response = universal_fetch(input, init22);
    response.catch(() => {
    });
    return response;
  };
}
async function stream_to_string(stream) {
  let result = "";
  const reader = stream.getReader();
  const decoder3 = new TextDecoder();
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    result += decoder3.decode(value);
  }
  return result;
}
function hash(...values) {
  let hash2 = 5381;
  for (const value of values) {
    if (typeof value === "string") {
      let i3 = value.length;
      while (i3)
        hash2 = hash2 * 33 ^ value.charCodeAt(--i3);
    } else if (ArrayBuffer.isView(value)) {
      const buffer = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      let i3 = buffer.length;
      while (i3)
        hash2 = hash2 * 33 ^ buffer[--i3];
    } else {
      throw new TypeError("value must be a string or TypedArray");
    }
  }
  return (hash2 >>> 0).toString(36);
}
var escape_html_attr_dict = {
  "&": "&amp;",
  '"': "&quot;"
};
var escape_html_attr_regex = new RegExp(
  // special characters
  `[${Object.keys(escape_html_attr_dict).join("")}]|[\\ud800-\\udbff](?![\\udc00-\\udfff])|[\\ud800-\\udbff][\\udc00-\\udfff]|[\\udc00-\\udfff]`,
  "g"
);
function escape_html_attr(str) {
  const escaped_str = str.replace(escape_html_attr_regex, (match) => {
    if (match.length === 2) {
      return match;
    }
    return escape_html_attr_dict[match] ?? `&#${match.charCodeAt(0)};`;
  });
  return `"${escaped_str}"`;
}
var replacements = {
  "<": "\\u003C",
  "\u2028": "\\u2028",
  "\u2029": "\\u2029"
};
var pattern = new RegExp(`[${Object.keys(replacements).join("")}]`, "g");
function serialize_data(fetched, filter, prerendering2 = false) {
  const headers2 = {};
  let cache_control = null;
  let age = null;
  let varyAny = false;
  for (const [key2, value] of fetched.response.headers) {
    if (filter(key2, value)) {
      headers2[key2] = value;
    }
    if (key2 === "cache-control")
      cache_control = value;
    else if (key2 === "age")
      age = value;
    else if (key2 === "vary" && value.trim() === "*")
      varyAny = true;
  }
  const payload = {
    status: fetched.response.status,
    statusText: fetched.response.statusText,
    headers: headers2,
    body: fetched.response_body
  };
  const safe_payload = JSON.stringify(payload).replace(pattern, (match) => replacements[match]);
  const attrs = [
    'type="application/json"',
    "data-sveltekit-fetched",
    `data-url=${escape_html_attr(fetched.url)}`
  ];
  if (fetched.is_b64) {
    attrs.push("data-b64");
  }
  if (fetched.request_headers || fetched.request_body) {
    const values = [];
    if (fetched.request_headers) {
      values.push([...new Headers(fetched.request_headers)].join(","));
    }
    if (fetched.request_body) {
      values.push(fetched.request_body);
    }
    attrs.push(`data-hash="${hash(...values)}"`);
  }
  if (!prerendering2 && fetched.method === "GET" && cache_control && !varyAny) {
    const match = /s-maxage=(\d+)/g.exec(cache_control) ?? /max-age=(\d+)/g.exec(cache_control);
    if (match) {
      const ttl = +match[1] - +(age ?? "0");
      attrs.push(`data-ttl="${ttl}"`);
    }
  }
  return `<script ${attrs.join(" ")}>${safe_payload}<\/script>`;
}
var s3 = JSON.stringify;
var encoder$2 = new TextEncoder();
function sha256(data) {
  if (!key[0])
    precompute();
  const out = init2.slice(0);
  const array2 = encode4(data);
  for (let i3 = 0; i3 < array2.length; i3 += 16) {
    const w3 = array2.subarray(i3, i3 + 16);
    let tmp;
    let a3;
    let b3;
    let out0 = out[0];
    let out1 = out[1];
    let out2 = out[2];
    let out3 = out[3];
    let out4 = out[4];
    let out5 = out[5];
    let out6 = out[6];
    let out7 = out[7];
    for (let i22 = 0; i22 < 64; i22++) {
      if (i22 < 16) {
        tmp = w3[i22];
      } else {
        a3 = w3[i22 + 1 & 15];
        b3 = w3[i22 + 14 & 15];
        tmp = w3[i22 & 15] = (a3 >>> 7 ^ a3 >>> 18 ^ a3 >>> 3 ^ a3 << 25 ^ a3 << 14) + (b3 >>> 17 ^ b3 >>> 19 ^ b3 >>> 10 ^ b3 << 15 ^ b3 << 13) + w3[i22 & 15] + w3[i22 + 9 & 15] | 0;
      }
      tmp = tmp + out7 + (out4 >>> 6 ^ out4 >>> 11 ^ out4 >>> 25 ^ out4 << 26 ^ out4 << 21 ^ out4 << 7) + (out6 ^ out4 & (out5 ^ out6)) + key[i22];
      out7 = out6;
      out6 = out5;
      out5 = out4;
      out4 = out3 + tmp | 0;
      out3 = out2;
      out2 = out1;
      out1 = out0;
      out0 = tmp + (out1 & out2 ^ out3 & (out1 ^ out2)) + (out1 >>> 2 ^ out1 >>> 13 ^ out1 >>> 22 ^ out1 << 30 ^ out1 << 19 ^ out1 << 10) | 0;
    }
    out[0] = out[0] + out0 | 0;
    out[1] = out[1] + out1 | 0;
    out[2] = out[2] + out2 | 0;
    out[3] = out[3] + out3 | 0;
    out[4] = out[4] + out4 | 0;
    out[5] = out[5] + out5 | 0;
    out[6] = out[6] + out6 | 0;
    out[7] = out[7] + out7 | 0;
  }
  const bytes = new Uint8Array(out.buffer);
  reverse_endianness(bytes);
  return base64(bytes);
}
var init2 = new Uint32Array(8);
var key = new Uint32Array(64);
function precompute() {
  function frac(x2) {
    return (x2 - Math.floor(x2)) * 4294967296;
  }
  let prime = 2;
  for (let i3 = 0; i3 < 64; prime++) {
    let is_prime = true;
    for (let factor = 2; factor * factor <= prime; factor++) {
      if (prime % factor === 0) {
        is_prime = false;
        break;
      }
    }
    if (is_prime) {
      if (i3 < 8) {
        init2[i3] = frac(prime ** (1 / 2));
      }
      key[i3] = frac(prime ** (1 / 3));
      i3++;
    }
  }
}
function reverse_endianness(bytes) {
  for (let i3 = 0; i3 < bytes.length; i3 += 4) {
    const a3 = bytes[i3 + 0];
    const b3 = bytes[i3 + 1];
    const c3 = bytes[i3 + 2];
    const d3 = bytes[i3 + 3];
    bytes[i3 + 0] = d3;
    bytes[i3 + 1] = c3;
    bytes[i3 + 2] = b3;
    bytes[i3 + 3] = a3;
  }
}
function encode4(str) {
  const encoded = encoder$2.encode(str);
  const length = encoded.length * 8;
  const size = 512 * Math.ceil((length + 65) / 512);
  const bytes = new Uint8Array(size / 8);
  bytes.set(encoded);
  bytes[encoded.length] = 128;
  reverse_endianness(bytes);
  const words = new Uint32Array(bytes.buffer);
  words[words.length - 2] = Math.floor(length / 4294967296);
  words[words.length - 1] = length;
  return words;
}
var chars2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split("");
function base64(bytes) {
  const l3 = bytes.length;
  let result = "";
  let i3;
  for (i3 = 2; i3 < l3; i3 += 3) {
    result += chars2[bytes[i3 - 2] >> 2];
    result += chars2[(bytes[i3 - 2] & 3) << 4 | bytes[i3 - 1] >> 4];
    result += chars2[(bytes[i3 - 1] & 15) << 2 | bytes[i3] >> 6];
    result += chars2[bytes[i3] & 63];
  }
  if (i3 === l3 + 1) {
    result += chars2[bytes[i3 - 2] >> 2];
    result += chars2[(bytes[i3 - 2] & 3) << 4];
    result += "==";
  }
  if (i3 === l3) {
    result += chars2[bytes[i3 - 2] >> 2];
    result += chars2[(bytes[i3 - 2] & 3) << 4 | bytes[i3 - 1] >> 4];
    result += chars2[(bytes[i3 - 1] & 15) << 2];
    result += "=";
  }
  return result;
}
var array = new Uint8Array(16);
function generate_nonce() {
  crypto.getRandomValues(array);
  return base64(array);
}
var quoted = /* @__PURE__ */ new Set([
  "self",
  "unsafe-eval",
  "unsafe-hashes",
  "unsafe-inline",
  "none",
  "strict-dynamic",
  "report-sample",
  "wasm-unsafe-eval",
  "script"
]);
var crypto_pattern = /^(nonce|sha\d\d\d)-/;
var _use_hashes, _script_needs_csp, _style_needs_csp, _directives, _script_src, _script_src_elem, _style_src, _style_src_attr, _style_src_elem, _nonce;
var BaseProvider = class {
  /**
   * @param {boolean} use_hashes
   * @param {import('types').CspDirectives} directives
   * @param {string} nonce
   */
  constructor(use_hashes, directives, nonce2) {
    /** @type {boolean} */
    __privateAdd(this, _use_hashes, void 0);
    /** @type {boolean} */
    __privateAdd(this, _script_needs_csp, void 0);
    /** @type {boolean} */
    __privateAdd(this, _style_needs_csp, void 0);
    /** @type {import('types').CspDirectives} */
    __privateAdd(this, _directives, void 0);
    /** @type {import('types').Csp.Source[]} */
    __privateAdd(this, _script_src, void 0);
    /** @type {import('types').Csp.Source[]} */
    __privateAdd(this, _script_src_elem, void 0);
    /** @type {import('types').Csp.Source[]} */
    __privateAdd(this, _style_src, void 0);
    /** @type {import('types').Csp.Source[]} */
    __privateAdd(this, _style_src_attr, void 0);
    /** @type {import('types').Csp.Source[]} */
    __privateAdd(this, _style_src_elem, void 0);
    /** @type {string} */
    __privateAdd(this, _nonce, void 0);
    __privateSet(this, _use_hashes, use_hashes);
    __privateSet(this, _directives, directives);
    const d3 = __privateGet(this, _directives);
    __privateSet(this, _script_src, []);
    __privateSet(this, _script_src_elem, []);
    __privateSet(this, _style_src, []);
    __privateSet(this, _style_src_attr, []);
    __privateSet(this, _style_src_elem, []);
    const effective_script_src = d3["script-src"] || d3["default-src"];
    const script_src_elem = d3["script-src-elem"];
    const effective_style_src = d3["style-src"] || d3["default-src"];
    const style_src_attr = d3["style-src-attr"];
    const style_src_elem = d3["style-src-elem"];
    __privateSet(this, _script_needs_csp, !!effective_script_src && effective_script_src.filter((value) => value !== "unsafe-inline").length > 0 || !!script_src_elem && script_src_elem.filter((value) => value !== "unsafe-inline").length > 0);
    __privateSet(this, _style_needs_csp, !!effective_style_src && effective_style_src.filter((value) => value !== "unsafe-inline").length > 0 || !!style_src_attr && style_src_attr.filter((value) => value !== "unsafe-inline").length > 0 || !!style_src_elem && style_src_elem.filter((value) => value !== "unsafe-inline").length > 0);
    this.script_needs_nonce = __privateGet(this, _script_needs_csp) && !__privateGet(this, _use_hashes);
    this.style_needs_nonce = __privateGet(this, _style_needs_csp) && !__privateGet(this, _use_hashes);
    __privateSet(this, _nonce, nonce2);
  }
  /** @param {string} content */
  add_script(content) {
    if (__privateGet(this, _script_needs_csp)) {
      const d3 = __privateGet(this, _directives);
      if (__privateGet(this, _use_hashes)) {
        const hash2 = sha256(content);
        __privateGet(this, _script_src).push(`sha256-${hash2}`);
        if (d3["script-src-elem"]?.length) {
          __privateGet(this, _script_src_elem).push(`sha256-${hash2}`);
        }
      } else {
        if (__privateGet(this, _script_src).length === 0) {
          __privateGet(this, _script_src).push(`nonce-${__privateGet(this, _nonce)}`);
        }
        if (d3["script-src-elem"]?.length) {
          __privateGet(this, _script_src_elem).push(`nonce-${__privateGet(this, _nonce)}`);
        }
      }
    }
  }
  /** @param {string} content */
  add_style(content) {
    if (__privateGet(this, _style_needs_csp)) {
      const empty_comment_hash = "9OlNO0DNEeaVzHL4RZwCLsBHA8WBQ8toBp/4F5XV2nc=";
      const d3 = __privateGet(this, _directives);
      if (__privateGet(this, _use_hashes)) {
        const hash2 = sha256(content);
        __privateGet(this, _style_src).push(`sha256-${hash2}`);
        if (d3["style-src-attr"]?.length) {
          __privateGet(this, _style_src_attr).push(`sha256-${hash2}`);
        }
        if (d3["style-src-elem"]?.length) {
          if (hash2 !== empty_comment_hash && !d3["style-src-elem"].includes(`sha256-${empty_comment_hash}`)) {
            __privateGet(this, _style_src_elem).push(`sha256-${empty_comment_hash}`);
          }
          __privateGet(this, _style_src_elem).push(`sha256-${hash2}`);
        }
      } else {
        if (__privateGet(this, _style_src).length === 0 && !d3["style-src"]?.includes("unsafe-inline")) {
          __privateGet(this, _style_src).push(`nonce-${__privateGet(this, _nonce)}`);
        }
        if (d3["style-src-attr"]?.length) {
          __privateGet(this, _style_src_attr).push(`nonce-${__privateGet(this, _nonce)}`);
        }
        if (d3["style-src-elem"]?.length) {
          if (!d3["style-src-elem"].includes(`sha256-${empty_comment_hash}`)) {
            __privateGet(this, _style_src_elem).push(`sha256-${empty_comment_hash}`);
          }
          __privateGet(this, _style_src_elem).push(`nonce-${__privateGet(this, _nonce)}`);
        }
      }
    }
  }
  /**
   * @param {boolean} [is_meta]
   */
  get_header(is_meta = false) {
    const header = [];
    const directives = { ...__privateGet(this, _directives) };
    if (__privateGet(this, _style_src).length > 0) {
      directives["style-src"] = [
        ...directives["style-src"] || directives["default-src"] || [],
        ...__privateGet(this, _style_src)
      ];
    }
    if (__privateGet(this, _style_src_attr).length > 0) {
      directives["style-src-attr"] = [
        ...directives["style-src-attr"] || [],
        ...__privateGet(this, _style_src_attr)
      ];
    }
    if (__privateGet(this, _style_src_elem).length > 0) {
      directives["style-src-elem"] = [
        ...directives["style-src-elem"] || [],
        ...__privateGet(this, _style_src_elem)
      ];
    }
    if (__privateGet(this, _script_src).length > 0) {
      directives["script-src"] = [
        ...directives["script-src"] || directives["default-src"] || [],
        ...__privateGet(this, _script_src)
      ];
    }
    if (__privateGet(this, _script_src_elem).length > 0) {
      directives["script-src-elem"] = [
        ...directives["script-src-elem"] || [],
        ...__privateGet(this, _script_src_elem)
      ];
    }
    for (const key2 in directives) {
      if (is_meta && (key2 === "frame-ancestors" || key2 === "report-uri" || key2 === "sandbox")) {
        continue;
      }
      const value = (
        /** @type {string[] | true} */
        directives[key2]
      );
      if (!value)
        continue;
      const directive = [key2];
      if (Array.isArray(value)) {
        value.forEach((value2) => {
          if (quoted.has(value2) || crypto_pattern.test(value2)) {
            directive.push(`'${value2}'`);
          } else {
            directive.push(value2);
          }
        });
      }
      header.push(directive.join(" "));
    }
    return header.join("; ");
  }
};
_use_hashes = new WeakMap();
_script_needs_csp = new WeakMap();
_style_needs_csp = new WeakMap();
_directives = new WeakMap();
_script_src = new WeakMap();
_script_src_elem = new WeakMap();
_style_src = new WeakMap();
_style_src_attr = new WeakMap();
_style_src_elem = new WeakMap();
_nonce = new WeakMap();
var CspProvider = class extends BaseProvider {
  get_meta() {
    const content = this.get_header(true);
    if (!content) {
      return;
    }
    return `<meta http-equiv="content-security-policy" content=${escape_html_attr(content)}>`;
  }
};
var CspReportOnlyProvider = class extends BaseProvider {
  /**
   * @param {boolean} use_hashes
   * @param {import('types').CspDirectives} directives
   * @param {string} nonce
   */
  constructor(use_hashes, directives, nonce2) {
    super(use_hashes, directives, nonce2);
    if (Object.values(directives).filter((v3) => !!v3).length > 0) {
      const has_report_to = directives["report-to"]?.length ?? 0 > 0;
      const has_report_uri = directives["report-uri"]?.length ?? 0 > 0;
      if (!has_report_to && !has_report_uri) {
        throw Error(
          "`content-security-policy-report-only` must be specified with either the `report-to` or `report-uri` directives, or both"
        );
      }
    }
  }
};
var Csp = class {
  /**
   * @param {import('./types.js').CspConfig} config
   * @param {import('./types.js').CspOpts} opts
   */
  constructor({ mode, directives, reportOnly }, { prerender }) {
    /** @readonly */
    __publicField(this, "nonce", generate_nonce());
    /** @type {CspProvider} */
    __publicField(this, "csp_provider");
    /** @type {CspReportOnlyProvider} */
    __publicField(this, "report_only_provider");
    const use_hashes = mode === "hash" || mode === "auto" && prerender;
    this.csp_provider = new CspProvider(use_hashes, directives, this.nonce);
    this.report_only_provider = new CspReportOnlyProvider(use_hashes, reportOnly, this.nonce);
  }
  get script_needs_nonce() {
    return this.csp_provider.script_needs_nonce || this.report_only_provider.script_needs_nonce;
  }
  get style_needs_nonce() {
    return this.csp_provider.style_needs_nonce || this.report_only_provider.style_needs_nonce;
  }
  /** @param {string} content */
  add_script(content) {
    this.csp_provider.add_script(content);
    this.report_only_provider.add_script(content);
  }
  /** @param {string} content */
  add_style(content) {
    this.csp_provider.add_style(content);
    this.report_only_provider.add_style(content);
  }
};
function defer() {
  let fulfil;
  let reject;
  const promise = new Promise((f3, r3) => {
    fulfil = f3;
    reject = r3;
  });
  return { promise, fulfil, reject };
}
function create_async_iterator() {
  const deferred = [defer()];
  return {
    iterator: {
      [Symbol.asyncIterator]() {
        return {
          next: async () => {
            const next = await deferred[0].promise;
            if (!next.done)
              deferred.shift();
            return next;
          }
        };
      }
    },
    push: (value) => {
      deferred[deferred.length - 1].fulfil({
        value,
        done: false
      });
      deferred.push(defer());
    },
    done: () => {
      deferred[deferred.length - 1].fulfil({ done: true });
    }
  };
}
var updated = {
  ...readable(false),
  check: () => false
};
var encoder$1 = new TextEncoder();
async function render_response({
  branch,
  fetched,
  options: options2,
  manifest: manifest2,
  state: state2,
  page_config,
  status,
  error = null,
  event,
  resolve_opts,
  action_result
}) {
  if (state2.prerendering) {
    if (options2.csp.mode === "nonce") {
      throw new Error('Cannot use prerendering if config.kit.csp.mode === "nonce"');
    }
    if (options2.app_template_contains_nonce) {
      throw new Error("Cannot use prerendering if page template contains %sveltekit.nonce%");
    }
  }
  const { client } = manifest2._;
  const modulepreloads = new Set(client.imports);
  const stylesheets5 = new Set(client.stylesheets);
  const fonts5 = new Set(client.fonts);
  const link_header_preloads = /* @__PURE__ */ new Set();
  const inline_styles = /* @__PURE__ */ new Map();
  let rendered;
  const form_value = action_result?.type === "success" || action_result?.type === "failure" ? action_result.data ?? null : null;
  let base$1 = base;
  let assets$1 = assets;
  let base_expression = s3(base);
  if (!state2.prerendering?.fallback) {
    const segments = event.url.pathname.slice(base.length).split("/").slice(2);
    base$1 = segments.map(() => "..").join("/") || ".";
    base_expression = `new URL(${s3(base$1)}, location).pathname.slice(0, -1)`;
    if (!assets || assets[0] === "/" && assets !== SVELTE_KIT_ASSETS) {
      assets$1 = base$1;
    }
  }
  if (page_config.ssr) {
    const props = {
      stores: {
        page: writable(null),
        navigating: writable(null),
        updated
      },
      constructors: await Promise.all(branch.map(({ node }) => node.component())),
      form: form_value
    };
    let data2 = {};
    for (let i3 = 0; i3 < branch.length; i3 += 1) {
      data2 = { ...data2, ...branch[i3].data };
      props[`data_${i3}`] = data2;
    }
    props.page = {
      error,
      params: (
        /** @type {Record<string, any>} */
        event.params
      ),
      route: event.route,
      status,
      url: event.url,
      data: data2,
      form: form_value,
      state: {}
    };
    override({ base: base$1, assets: assets$1 });
    {
      try {
        rendered = options2.root.render(props);
      } finally {
        reset2();
      }
    }
    for (const { node } of branch) {
      for (const url of node.imports)
        modulepreloads.add(url);
      for (const url of node.stylesheets)
        stylesheets5.add(url);
      for (const url of node.fonts)
        fonts5.add(url);
      if (node.inline_styles) {
        Object.entries(await node.inline_styles()).forEach(([k3, v3]) => inline_styles.set(k3, v3));
      }
    }
  } else {
    rendered = { head: "", html: "", css: { code: "", map: null } };
  }
  let head = "";
  let body2 = rendered.html;
  const csp = new Csp(options2.csp, {
    prerender: !!state2.prerendering
  });
  const prefixed = (path) => {
    if (path.startsWith("/")) {
      return base + path;
    }
    return `${assets$1}/${path}`;
  };
  if (inline_styles.size > 0) {
    const content = Array.from(inline_styles.values()).join("\n");
    const attributes = [];
    if (csp.style_needs_nonce)
      attributes.push(` nonce="${csp.nonce}"`);
    csp.add_style(content);
    head += `
	<style${attributes.join("")}>${content}</style>`;
  }
  for (const dep of stylesheets5) {
    const path = prefixed(dep);
    const attributes = ['rel="stylesheet"'];
    if (inline_styles.has(dep)) {
      attributes.push("disabled", 'media="(max-width: 0)"');
    } else {
      if (resolve_opts.preload({ type: "css", path })) {
        const preload_atts = ['rel="preload"', 'as="style"'];
        link_header_preloads.add(`<${encodeURI(path)}>; ${preload_atts.join(";")}; nopush`);
      }
    }
    head += `
		<link href="${path}" ${attributes.join(" ")}>`;
  }
  for (const dep of fonts5) {
    const path = prefixed(dep);
    if (resolve_opts.preload({ type: "font", path })) {
      const ext = dep.slice(dep.lastIndexOf(".") + 1);
      const attributes = [
        'rel="preload"',
        'as="font"',
        `type="font/${ext}"`,
        `href="${path}"`,
        "crossorigin"
      ];
      head += `
		<link ${attributes.join(" ")}>`;
    }
  }
  const global = `__sveltekit_${options2.version_hash}`;
  const { data, chunks } = get_data(
    event,
    options2,
    branch.map((b3) => b3.server_data),
    global
  );
  if (page_config.ssr && page_config.csr) {
    body2 += `
			${fetched.map(
      (item) => serialize_data(item, resolve_opts.filterSerializedResponseHeaders, !!state2.prerendering)
    ).join("\n			")}`;
  }
  if (page_config.csr) {
    if (client.uses_env_dynamic_public && state2.prerendering) {
      modulepreloads.add(`${options2.app_dir}/env.js`);
    }
    const included_modulepreloads = Array.from(modulepreloads, (dep) => prefixed(dep)).filter(
      (path) => resolve_opts.preload({ type: "js", path })
    );
    for (const path of included_modulepreloads) {
      link_header_preloads.add(`<${encodeURI(path)}>; rel="modulepreload"; nopush`);
      if (options2.preload_strategy !== "modulepreload") {
        head += `
		<link rel="preload" as="script" crossorigin="anonymous" href="${path}">`;
      } else if (state2.prerendering) {
        head += `
		<link rel="modulepreload" href="${path}">`;
      }
    }
    const blocks = [];
    const load_env_eagerly = client.uses_env_dynamic_public && state2.prerendering;
    const properties = [`base: ${base_expression}`];
    if (assets) {
      properties.push(`assets: ${s3(assets)}`);
    }
    if (client.uses_env_dynamic_public) {
      properties.push(`env: ${load_env_eagerly ? "null" : s3(public_env)}`);
    }
    if (chunks) {
      blocks.push("const deferred = new Map();");
      properties.push(`defer: (id) => new Promise((fulfil, reject) => {
							deferred.set(id, { fulfil, reject });
						})`);
      properties.push(`resolve: ({ id, data, error }) => {
							const { fulfil, reject } = deferred.get(id);
							deferred.delete(id);

							if (error) reject(error);
							else fulfil(data);
						}`);
    }
    blocks.push(`${global} = {
						${properties.join(",\n						")}
					};`);
    const args = ["app", "element"];
    blocks.push("const element = document.currentScript.parentElement;");
    if (page_config.ssr) {
      const serialized = { form: "null", error: "null" };
      blocks.push(`const data = ${data};`);
      if (form_value) {
        serialized.form = uneval_action_response(
          form_value,
          /** @type {string} */
          event.route.id
        );
      }
      if (error) {
        serialized.error = uneval(error);
      }
      const hydrate = [
        `node_ids: [${branch.map(({ node }) => node.index).join(", ")}]`,
        "data",
        `form: ${serialized.form}`,
        `error: ${serialized.error}`
      ];
      if (status !== 200) {
        hydrate.push(`status: ${status}`);
      }
      if (options2.embedded) {
        hydrate.push(`params: ${uneval(event.params)}`, `route: ${s3(event.route)}`);
      }
      const indent = "	".repeat(load_env_eagerly ? 7 : 6);
      args.push(`{
${indent}	${hydrate.join(`,
${indent}	`)}
${indent}}`);
    }
    if (load_env_eagerly) {
      blocks.push(`import(${s3(`${base$1}/${options2.app_dir}/env.js`)}).then(({ env }) => {
						${global}.env = env;

						Promise.all([
							import(${s3(prefixed(client.start))}),
							import(${s3(prefixed(client.app))})
						]).then(([kit, app]) => {
							kit.start(${args.join(", ")});
						});
					});`);
    } else {
      blocks.push(`Promise.all([
						import(${s3(prefixed(client.start))}),
						import(${s3(prefixed(client.app))})
					]).then(([kit, app]) => {
						kit.start(${args.join(", ")});
					});`);
    }
    if (options2.service_worker) {
      const opts = "";
      blocks.push(`if ('serviceWorker' in navigator) {
						addEventListener('load', function () {
							navigator.serviceWorker.register('${prefixed("service-worker.js")}'${opts});
						});
					}`);
    }
    const init_app = `
				{
					${blocks.join("\n\n					")}
				}
			`;
    csp.add_script(init_app);
    body2 += `
			<script${csp.script_needs_nonce ? ` nonce="${csp.nonce}"` : ""}>${init_app}<\/script>
		`;
  }
  const headers2 = new Headers({
    "x-sveltekit-page": "true",
    "content-type": "text/html"
  });
  if (state2.prerendering) {
    const http_equiv = [];
    const csp_headers = csp.csp_provider.get_meta();
    if (csp_headers) {
      http_equiv.push(csp_headers);
    }
    if (state2.prerendering.cache) {
      http_equiv.push(`<meta http-equiv="cache-control" content="${state2.prerendering.cache}">`);
    }
    if (http_equiv.length > 0) {
      head = http_equiv.join("\n") + head;
    }
  } else {
    const csp_header = csp.csp_provider.get_header();
    if (csp_header) {
      headers2.set("content-security-policy", csp_header);
    }
    const report_only_header = csp.report_only_provider.get_header();
    if (report_only_header) {
      headers2.set("content-security-policy-report-only", report_only_header);
    }
    if (link_header_preloads.size) {
      headers2.set("link", Array.from(link_header_preloads).join(", "));
    }
  }
  head += rendered.head;
  const html = options2.templates.app({
    head,
    body: body2,
    assets: assets$1,
    nonce: (
      /** @type {string} */
      csp.nonce
    ),
    env: safe_public_env
  });
  const transformed = await resolve_opts.transformPageChunk({
    html,
    done: true
  }) || "";
  if (!chunks) {
    headers2.set("etag", `"${hash(transformed)}"`);
  }
  return !chunks ? text(transformed, {
    status,
    headers: headers2
  }) : new Response(
    new ReadableStream({
      async start(controller) {
        controller.enqueue(encoder$1.encode(transformed + "\n"));
        for await (const chunk of chunks) {
          controller.enqueue(encoder$1.encode(chunk));
        }
        controller.close();
      },
      type: "bytes"
    }),
    {
      headers: {
        "content-type": "text/html"
      }
    }
  );
}
function get_data(event, options2, nodes, global) {
  let promise_id = 1;
  let count = 0;
  const { iterator, push, done } = create_async_iterator();
  function replacer(thing) {
    if (typeof thing?.then === "function") {
      const id = promise_id++;
      count += 1;
      thing.then(
        /** @param {any} data */
        (data) => ({ data })
      ).catch(
        /** @param {any} error */
        async (error) => ({
          error: await handle_error_and_jsonify(event, options2, error)
        })
      ).then(
        /**
         * @param {{data: any; error: any}} result
         */
        async ({ data, error }) => {
          count -= 1;
          let str;
          try {
            str = uneval({ id, data, error }, replacer);
          } catch (e2) {
            error = await handle_error_and_jsonify(
              event,
              options2,
              new Error(`Failed to serialize promise while rendering ${event.route.id}`)
            );
            data = void 0;
            str = uneval({ id, data, error }, replacer);
          }
          push(`<script>${global}.resolve(${str})<\/script>
`);
          if (count === 0)
            done();
        }
      );
      return `${global}.defer(${id})`;
    }
  }
  try {
    const strings = nodes.map((node) => {
      if (!node)
        return "null";
      return `{"type":"data","data":${uneval(node.data, replacer)},${stringify_uses(node)}${node.slash ? `,"slash":${JSON.stringify(node.slash)}` : ""}}`;
    });
    return {
      data: `[${strings.join(",")}]`,
      chunks: count > 0 ? iterator : null
    };
  } catch (e2) {
    throw new Error(clarify_devalue_error(
      event,
      /** @type {any} */
      e2
    ));
  }
}
function get_option(nodes, option) {
  return nodes.reduce(
    (value, node) => {
      return (
        /** @type {Value} TypeScript's too dumb to understand this */
        node?.universal?.[option] ?? node?.server?.[option] ?? value
      );
    },
    /** @type {Value | undefined} */
    void 0
  );
}
async function respond_with_error({
  event,
  options: options2,
  manifest: manifest2,
  state: state2,
  status,
  error,
  resolve_opts
}) {
  if (event.request.headers.get("x-sveltekit-error")) {
    return static_error_page(
      options2,
      status,
      /** @type {Error} */
      error.message
    );
  }
  const fetched = [];
  try {
    const branch = [];
    const default_layout = await manifest2._.nodes[0]();
    const ssr = get_option([default_layout], "ssr") ?? true;
    const csr = get_option([default_layout], "csr") ?? true;
    if (ssr) {
      state2.error = true;
      const server_data_promise = load_server_data({
        event,
        state: state2,
        node: default_layout,
        parent: async () => ({})
      });
      const server_data = await server_data_promise;
      const data = await load_data({
        event,
        fetched,
        node: default_layout,
        parent: async () => ({}),
        resolve_opts,
        server_data_promise,
        state: state2,
        csr
      });
      branch.push(
        {
          node: default_layout,
          server_data,
          data
        },
        {
          node: await manifest2._.nodes[1](),
          // 1 is always the root error
          data: null,
          server_data: null
        }
      );
    }
    return await render_response({
      options: options2,
      manifest: manifest2,
      state: state2,
      page_config: {
        ssr,
        csr
      },
      status,
      error: await handle_error_and_jsonify(event, options2, error),
      branch,
      fetched,
      event,
      resolve_opts
    });
  } catch (e2) {
    if (e2 instanceof Redirect) {
      return redirect_response(e2.status, e2.location);
    }
    return static_error_page(
      options2,
      get_status(e2),
      (await handle_error_and_jsonify(event, options2, e2)).message
    );
  }
}
function once(fn) {
  let done = false;
  let result;
  return () => {
    if (done)
      return result;
    done = true;
    return result = fn();
  };
}
var encoder4 = new TextEncoder();
async function render_data(event, route, options2, manifest2, state2, invalidated_data_nodes, trailing_slash) {
  if (!route.page) {
    return new Response(void 0, {
      status: 404
    });
  }
  try {
    const node_ids = [...route.page.layouts, route.page.leaf];
    const invalidated = invalidated_data_nodes ?? node_ids.map(() => true);
    let aborted = false;
    const url = new URL(event.url);
    url.pathname = normalize_path(url.pathname, trailing_slash);
    const new_event = { ...event, url };
    const functions = node_ids.map((n3, i3) => {
      return once(async () => {
        try {
          if (aborted) {
            return (
              /** @type {import('types').ServerDataSkippedNode} */
              {
                type: "skip"
              }
            );
          }
          const node = n3 == void 0 ? n3 : await manifest2._.nodes[n3]();
          return load_server_data({
            event: new_event,
            state: state2,
            node,
            parent: async () => {
              const data2 = {};
              for (let j3 = 0; j3 < i3; j3 += 1) {
                const parent = (
                  /** @type {import('types').ServerDataNode | null} */
                  await functions[j3]()
                );
                if (parent) {
                  Object.assign(data2, parent.data);
                }
              }
              return data2;
            }
          });
        } catch (e2) {
          aborted = true;
          throw e2;
        }
      });
    });
    const promises = functions.map(async (fn, i3) => {
      if (!invalidated[i3]) {
        return (
          /** @type {import('types').ServerDataSkippedNode} */
          {
            type: "skip"
          }
        );
      }
      return fn();
    });
    let length = promises.length;
    const nodes = await Promise.all(
      promises.map(
        (p3, i3) => p3.catch(async (error) => {
          if (error instanceof Redirect) {
            throw error;
          }
          length = Math.min(length, i3 + 1);
          return (
            /** @type {import('types').ServerErrorNode} */
            {
              type: "error",
              error: await handle_error_and_jsonify(event, options2, error),
              status: error instanceof HttpError || error instanceof SvelteKitError ? error.status : void 0
            }
          );
        })
      )
    );
    const { data, chunks } = get_data_json(event, options2, nodes);
    if (!chunks) {
      return json_response(data);
    }
    return new Response(
      new ReadableStream({
        async start(controller) {
          controller.enqueue(encoder4.encode(data));
          for await (const chunk of chunks) {
            controller.enqueue(encoder4.encode(chunk));
          }
          controller.close();
        },
        type: "bytes"
      }),
      {
        headers: {
          // we use a proprietary content type to prevent buffering.
          // the `text` prefix makes it inspectable
          "content-type": "text/sveltekit-data",
          "cache-control": "private, no-store"
        }
      }
    );
  } catch (e2) {
    const error = normalize_error(e2);
    if (error instanceof Redirect) {
      return redirect_json_response(error);
    } else {
      return json_response(await handle_error_and_jsonify(event, options2, error), 500);
    }
  }
}
function json_response(json2, status = 200) {
  return text(typeof json2 === "string" ? json2 : JSON.stringify(json2), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "private, no-store"
    }
  });
}
function redirect_json_response(redirect2) {
  return json_response({
    type: "redirect",
    location: redirect2.location
  });
}
function get_data_json(event, options2, nodes) {
  let promise_id = 1;
  let count = 0;
  const { iterator, push, done } = create_async_iterator();
  const reducers = {
    /** @param {any} thing */
    Promise: (thing) => {
      if (typeof thing?.then === "function") {
        const id = promise_id++;
        count += 1;
        let key2 = "data";
        thing.catch(
          /** @param {any} e */
          async (e2) => {
            key2 = "error";
            return handle_error_and_jsonify(
              event,
              options2,
              /** @type {any} */
              e2
            );
          }
        ).then(
          /** @param {any} value */
          async (value) => {
            let str;
            try {
              str = stringify(value, reducers);
            } catch (e2) {
              const error = await handle_error_and_jsonify(
                event,
                options2,
                new Error(`Failed to serialize promise while rendering ${event.route.id}`)
              );
              key2 = "error";
              str = stringify(error, reducers);
            }
            count -= 1;
            push(`{"type":"chunk","id":${id},"${key2}":${str}}
`);
            if (count === 0)
              done();
          }
        );
        return id;
      }
    }
  };
  try {
    const strings = nodes.map((node) => {
      if (!node)
        return "null";
      if (node.type === "error" || node.type === "skip") {
        return JSON.stringify(node);
      }
      return `{"type":"data","data":${stringify(node.data, reducers)},${stringify_uses(
        node
      )}${node.slash ? `,"slash":${JSON.stringify(node.slash)}` : ""}}`;
    });
    return {
      data: `{"type":"data","nodes":[${strings.join(",")}]}
`,
      chunks: count > 0 ? iterator : null
    };
  } catch (e2) {
    throw new Error(clarify_devalue_error(
      event,
      /** @type {any} */
      e2
    ));
  }
}
function load_page_nodes(page2, manifest2) {
  return Promise.all([
    // we use == here rather than === because [undefined] serializes as "[null]"
    ...page2.layouts.map((n3) => n3 == void 0 ? n3 : manifest2._.nodes[n3]()),
    manifest2._.nodes[page2.leaf]()
  ]);
}
var MAX_DEPTH = 10;
async function render_page(event, page2, options2, manifest2, state2, resolve_opts) {
  if (state2.depth > MAX_DEPTH) {
    return text(`Not found: ${event.url.pathname}`, {
      status: 404
      // TODO in some cases this should be 500. not sure how to differentiate
    });
  }
  if (is_action_json_request(event)) {
    const node = await manifest2._.nodes[page2.leaf]();
    return handle_action_json_request(event, options2, node?.server);
  }
  try {
    const nodes = await load_page_nodes(page2, manifest2);
    const leaf_node = (
      /** @type {import('types').SSRNode} */
      nodes.at(-1)
    );
    let status = 200;
    let action_result = void 0;
    if (is_action_request(event)) {
      action_result = await handle_action_request(event, leaf_node.server);
      if (action_result?.type === "redirect") {
        return redirect_response(action_result.status, action_result.location);
      }
      if (action_result?.type === "error") {
        status = get_status(action_result.error);
      }
      if (action_result?.type === "failure") {
        status = action_result.status;
      }
    }
    const should_prerender_data = nodes.some((node) => node?.server?.load);
    const data_pathname = add_data_suffix(event.url.pathname);
    const should_prerender = get_option(nodes, "prerender") ?? false;
    if (should_prerender) {
      const mod = leaf_node.server;
      if (mod?.actions) {
        throw new Error("Cannot prerender pages with actions");
      }
    } else if (state2.prerendering) {
      return new Response(void 0, {
        status: 204
      });
    }
    state2.prerender_default = should_prerender;
    const fetched = [];
    if (get_option(nodes, "ssr") === false && !(state2.prerendering && should_prerender_data)) {
      return await render_response({
        branch: [],
        fetched,
        page_config: {
          ssr: false,
          csr: get_option(nodes, "csr") ?? true
        },
        status,
        error: null,
        event,
        options: options2,
        manifest: manifest2,
        state: state2,
        resolve_opts
      });
    }
    const branch = [];
    let load_error = null;
    const server_promises = nodes.map((node, i3) => {
      if (load_error) {
        throw load_error;
      }
      return Promise.resolve().then(async () => {
        try {
          if (node === leaf_node && action_result?.type === "error") {
            throw action_result.error;
          }
          return await load_server_data({
            event,
            state: state2,
            node,
            parent: async () => {
              const data = {};
              for (let j3 = 0; j3 < i3; j3 += 1) {
                const parent = await server_promises[j3];
                if (parent)
                  Object.assign(data, await parent.data);
              }
              return data;
            }
          });
        } catch (e2) {
          load_error = /** @type {Error} */
          e2;
          throw load_error;
        }
      });
    });
    const csr = get_option(nodes, "csr") ?? true;
    const load_promises = nodes.map((node, i3) => {
      if (load_error)
        throw load_error;
      return Promise.resolve().then(async () => {
        try {
          return await load_data({
            event,
            fetched,
            node,
            parent: async () => {
              const data = {};
              for (let j3 = 0; j3 < i3; j3 += 1) {
                Object.assign(data, await load_promises[j3]);
              }
              return data;
            },
            resolve_opts,
            server_data_promise: server_promises[i3],
            state: state2,
            csr
          });
        } catch (e2) {
          load_error = /** @type {Error} */
          e2;
          throw load_error;
        }
      });
    });
    for (const p3 of server_promises)
      p3.catch(() => {
      });
    for (const p3 of load_promises)
      p3.catch(() => {
      });
    for (let i3 = 0; i3 < nodes.length; i3 += 1) {
      const node = nodes[i3];
      if (node) {
        try {
          const server_data = await server_promises[i3];
          const data = await load_promises[i3];
          branch.push({ node, server_data, data });
        } catch (e2) {
          const err = normalize_error(e2);
          if (err instanceof Redirect) {
            if (state2.prerendering && should_prerender_data) {
              const body2 = JSON.stringify({
                type: "redirect",
                location: err.location
              });
              state2.prerendering.dependencies.set(data_pathname, {
                response: text(body2),
                body: body2
              });
            }
            return redirect_response(err.status, err.location);
          }
          const status2 = get_status(err);
          const error = await handle_error_and_jsonify(event, options2, err);
          while (i3--) {
            if (page2.errors[i3]) {
              const index5 = (
                /** @type {number} */
                page2.errors[i3]
              );
              const node2 = await manifest2._.nodes[index5]();
              let j3 = i3;
              while (!branch[j3])
                j3 -= 1;
              return await render_response({
                event,
                options: options2,
                manifest: manifest2,
                state: state2,
                resolve_opts,
                page_config: { ssr: true, csr: true },
                status: status2,
                error,
                branch: compact(branch.slice(0, j3 + 1)).concat({
                  node: node2,
                  data: null,
                  server_data: null
                }),
                fetched
              });
            }
          }
          return static_error_page(options2, status2, error.message);
        }
      } else {
        branch.push(null);
      }
    }
    if (state2.prerendering && should_prerender_data) {
      let { data, chunks } = get_data_json(
        event,
        options2,
        branch.map((node) => node?.server_data)
      );
      if (chunks) {
        for await (const chunk of chunks) {
          data += chunk;
        }
      }
      state2.prerendering.dependencies.set(data_pathname, {
        response: text(data),
        body: data
      });
    }
    const ssr = get_option(nodes, "ssr") ?? true;
    return await render_response({
      event,
      options: options2,
      manifest: manifest2,
      state: state2,
      resolve_opts,
      page_config: {
        csr: get_option(nodes, "csr") ?? true,
        ssr
      },
      status,
      error: null,
      branch: ssr === false ? [] : compact(branch),
      action_result,
      fetched
    });
  } catch (e2) {
    return await respond_with_error({
      event,
      options: options2,
      manifest: manifest2,
      state: state2,
      status: 500,
      error: e2,
      resolve_opts
    });
  }
}
function exec(match, params, matchers) {
  const result = {};
  const values = match.slice(1);
  const values_needing_match = values.filter((value) => value !== void 0);
  let buffered = 0;
  for (let i3 = 0; i3 < params.length; i3 += 1) {
    const param = params[i3];
    let value = values[i3 - buffered];
    if (param.chained && param.rest && buffered) {
      value = values.slice(i3 - buffered, i3 + 1).filter((s22) => s22).join("/");
      buffered = 0;
    }
    if (value === void 0) {
      if (param.rest)
        result[param.name] = "";
      continue;
    }
    if (!param.matcher || matchers[param.matcher](value)) {
      result[param.name] = value;
      const next_param = params[i3 + 1];
      const next_value = values[i3 + 1];
      if (next_param && !next_param.rest && next_param.optional && next_value && param.chained) {
        buffered = 0;
      }
      if (!next_param && !next_value && Object.keys(result).length === values_needing_match.length) {
        buffered = 0;
      }
      continue;
    }
    if (param.optional && param.chained) {
      buffered++;
      continue;
    }
    return;
  }
  if (buffered)
    return;
  return result;
}
function validate_options(options2) {
  if (options2?.path === void 0) {
    throw new Error("You must specify a `path` when setting, deleting or serializing cookies");
  }
}
function get_cookies(request, url, trailing_slash) {
  const header = request.headers.get("cookie") ?? "";
  const initial_cookies = (0, import_cookie6.parse)(header, { decode: (value) => value });
  const normalized_url = normalize_path(url.pathname, trailing_slash);
  const new_cookies = {};
  const defaults = {
    httpOnly: true,
    sameSite: "lax",
    secure: url.hostname === "localhost" && url.protocol === "http:" ? false : true
  };
  const cookies = {
    // The JSDoc param annotations appearing below for get, set and delete
    // are necessary to expose the `cookie` library types to
    // typescript users. `@type {import('@sveltejs/kit').Cookies}` above is not
    // sufficient to do so.
    /**
     * @param {string} name
     * @param {import('cookie').CookieParseOptions} opts
     */
    get(name, opts) {
      const c3 = new_cookies[name];
      if (c3 && domain_matches(url.hostname, c3.options.domain) && path_matches(url.pathname, c3.options.path)) {
        return c3.value;
      }
      const decoder3 = opts?.decode || decodeURIComponent;
      const req_cookies = (0, import_cookie6.parse)(header, { decode: decoder3 });
      const cookie = req_cookies[name];
      return cookie;
    },
    /**
     * @param {import('cookie').CookieParseOptions} opts
     */
    getAll(opts) {
      const decoder3 = opts?.decode || decodeURIComponent;
      const cookies2 = (0, import_cookie6.parse)(header, { decode: decoder3 });
      for (const c3 of Object.values(new_cookies)) {
        if (domain_matches(url.hostname, c3.options.domain) && path_matches(url.pathname, c3.options.path)) {
          cookies2[c3.name] = c3.value;
        }
      }
      return Object.entries(cookies2).map(([name, value]) => ({ name, value }));
    },
    /**
     * @param {string} name
     * @param {string} value
     * @param {import('./page/types.js').Cookie['options']} options
     */
    set(name, value, options2) {
      validate_options(options2);
      set_internal(name, value, { ...defaults, ...options2 });
    },
    /**
     * @param {string} name
     *  @param {import('./page/types.js').Cookie['options']} options
     */
    delete(name, options2) {
      validate_options(options2);
      cookies.set(name, "", { ...options2, maxAge: 0 });
    },
    /**
     * @param {string} name
     * @param {string} value
     *  @param {import('./page/types.js').Cookie['options']} options
     */
    serialize(name, value, options2) {
      validate_options(options2);
      let path = options2.path;
      if (!options2.domain || options2.domain === url.hostname) {
        path = resolve(normalized_url, path);
      }
      return (0, import_cookie6.serialize)(name, value, { ...defaults, ...options2, path });
    }
  };
  function get_cookie_header(destination, header2) {
    const combined_cookies = {
      // cookies sent by the user agent have lowest precedence
      ...initial_cookies
    };
    for (const key2 in new_cookies) {
      const cookie = new_cookies[key2];
      if (!domain_matches(destination.hostname, cookie.options.domain))
        continue;
      if (!path_matches(destination.pathname, cookie.options.path))
        continue;
      const encoder22 = cookie.options.encode || encodeURIComponent;
      combined_cookies[cookie.name] = encoder22(cookie.value);
    }
    if (header2) {
      const parsed = (0, import_cookie6.parse)(header2, { decode: (value) => value });
      for (const name in parsed) {
        combined_cookies[name] = parsed[name];
      }
    }
    return Object.entries(combined_cookies).map(([name, value]) => `${name}=${value}`).join("; ");
  }
  function set_internal(name, value, options2) {
    let path = options2.path;
    if (!options2.domain || options2.domain === url.hostname) {
      path = resolve(normalized_url, path);
    }
    new_cookies[name] = { name, value, options: { ...options2, path } };
  }
  return { cookies, new_cookies, get_cookie_header, set_internal };
}
function domain_matches(hostname, constraint) {
  if (!constraint)
    return true;
  const normalized = constraint[0] === "." ? constraint.slice(1) : constraint;
  if (hostname === normalized)
    return true;
  return hostname.endsWith("." + normalized);
}
function path_matches(path, constraint) {
  if (!constraint)
    return true;
  const normalized = constraint.endsWith("/") ? constraint.slice(0, -1) : constraint;
  if (path === normalized)
    return true;
  return path.startsWith(normalized + "/");
}
function add_cookies_to_headers(headers2, cookies) {
  for (const new_cookie of cookies) {
    const { name, value, options: options2 } = new_cookie;
    headers2.append("set-cookie", (0, import_cookie6.serialize)(name, value, options2));
    if (options2.path.endsWith(".html")) {
      const path = add_data_suffix(options2.path);
      headers2.append("set-cookie", (0, import_cookie6.serialize)(name, value, { ...options2, path }));
    }
  }
}
function create_fetch({ event, options: options2, manifest: manifest2, state: state2, get_cookie_header, set_internal }) {
  const server_fetch = async (info, init22) => {
    const original_request = normalize_fetch_input(info, init22, event.url);
    let mode = (info instanceof Request ? info.mode : init22?.mode) ?? "cors";
    let credentials = (info instanceof Request ? info.credentials : init22?.credentials) ?? "same-origin";
    return options2.hooks.handleFetch({
      event,
      request: original_request,
      fetch: async (info2, init3) => {
        const request = normalize_fetch_input(info2, init3, event.url);
        const url = new URL(request.url);
        if (!request.headers.has("origin")) {
          request.headers.set("origin", event.url.origin);
        }
        if (info2 !== original_request) {
          mode = (info2 instanceof Request ? info2.mode : init3?.mode) ?? "cors";
          credentials = (info2 instanceof Request ? info2.credentials : init3?.credentials) ?? "same-origin";
        }
        if ((request.method === "GET" || request.method === "HEAD") && (mode === "no-cors" && url.origin !== event.url.origin || url.origin === event.url.origin)) {
          request.headers.delete("origin");
        }
        if (url.origin !== event.url.origin) {
          if (`.${url.hostname}`.endsWith(`.${event.url.hostname}`) && credentials !== "omit") {
            const cookie = get_cookie_header(url, request.headers.get("cookie"));
            if (cookie)
              request.headers.set("cookie", cookie);
          }
          return fetch(request);
        }
        const prefix = assets || base;
        const decoded = decodeURIComponent(url.pathname);
        const filename = (decoded.startsWith(prefix) ? decoded.slice(prefix.length) : decoded).slice(1);
        const filename_html = `${filename}/index.html`;
        const is_asset = manifest2.assets.has(filename);
        const is_asset_html = manifest2.assets.has(filename_html);
        if (is_asset || is_asset_html) {
          const file = is_asset ? filename : filename_html;
          if (state2.read) {
            const type = is_asset ? manifest2.mimeTypes[filename.slice(filename.lastIndexOf("."))] : "text/html";
            return new Response(state2.read(file), {
              headers: type ? { "content-type": type } : {}
            });
          }
          return await fetch(request);
        }
        if (credentials !== "omit") {
          const cookie = get_cookie_header(url, request.headers.get("cookie"));
          if (cookie) {
            request.headers.set("cookie", cookie);
          }
          const authorization = event.request.headers.get("authorization");
          if (authorization && !request.headers.has("authorization")) {
            request.headers.set("authorization", authorization);
          }
        }
        if (!request.headers.has("accept")) {
          request.headers.set("accept", "*/*");
        }
        if (!request.headers.has("accept-language")) {
          request.headers.set(
            "accept-language",
            /** @type {string} */
            event.request.headers.get("accept-language")
          );
        }
        const response = await respond(request, options2, manifest2, {
          ...state2,
          depth: state2.depth + 1
        });
        const set_cookie = response.headers.get("set-cookie");
        if (set_cookie) {
          for (const str of set_cookie_parser.splitCookiesString(set_cookie)) {
            const { name, value, ...options3 } = set_cookie_parser.parseString(str);
            const path = options3.path ?? (url.pathname.split("/").slice(0, -1).join("/") || "/");
            set_internal(name, value, {
              path,
              .../** @type {import('cookie').CookieSerializeOptions} */
              options3
            });
          }
        }
        return response;
      }
    });
  };
  return (input, init22) => {
    const response = server_fetch(input, init22);
    response.catch(() => {
    });
    return response;
  };
}
function normalize_fetch_input(info, init22, url) {
  if (info instanceof Request) {
    return info;
  }
  return new Request(typeof info === "string" ? new URL(info, url) : info, init22);
}
var body;
var etag;
var headers;
function get_public_env(request) {
  body ?? (body = `export const env=${JSON.stringify(public_env)}`);
  etag ?? (etag = `W/${Date.now()}`);
  headers ?? (headers = new Headers({
    "content-type": "application/javascript; charset=utf-8",
    etag
  }));
  if (request.headers.get("if-none-match") === etag) {
    return new Response(void 0, { status: 304, headers });
  }
  return new Response(body, { headers });
}
function get_page_config(nodes) {
  let current = {};
  for (const node of nodes) {
    if (!node?.universal?.config && !node?.server?.config)
      continue;
    current = {
      ...current,
      ...node?.universal?.config,
      ...node?.server?.config
    };
  }
  return Object.keys(current).length ? current : void 0;
}
var default_transform = ({ html }) => html;
var default_filter = () => false;
var default_preload = ({ type }) => type === "js" || type === "css";
var page_methods = /* @__PURE__ */ new Set(["GET", "HEAD", "POST"]);
var allowed_page_methods = /* @__PURE__ */ new Set(["GET", "HEAD", "OPTIONS"]);
async function respond(request, options2, manifest2, state2) {
  const url = new URL(request.url);
  if (options2.csrf_check_origin) {
    const forbidden = is_form_content_type(request) && (request.method === "POST" || request.method === "PUT" || request.method === "PATCH" || request.method === "DELETE") && request.headers.get("origin") !== url.origin;
    if (forbidden) {
      const csrf_error = new HttpError(
        403,
        `Cross-site ${request.method} form submissions are forbidden`
      );
      if (request.headers.get("accept") === "application/json") {
        return json(csrf_error.body, { status: csrf_error.status });
      }
      return text(csrf_error.body.message, { status: csrf_error.status });
    }
  }
  let rerouted_path;
  try {
    rerouted_path = options2.hooks.reroute({ url: new URL(url) }) ?? url.pathname;
  } catch (e2) {
    return text("Internal Server Error", {
      status: 500
    });
  }
  let decoded;
  try {
    decoded = decode_pathname(rerouted_path);
  } catch {
    return text("Malformed URI", { status: 400 });
  }
  let route = null;
  let params = {};
  if (base && !state2.prerendering?.fallback) {
    if (!decoded.startsWith(base)) {
      return text("Not found", { status: 404 });
    }
    decoded = decoded.slice(base.length) || "/";
  }
  if (decoded === `/${options2.app_dir}/env.js`) {
    return get_public_env(request);
  }
  if (decoded.startsWith(`/${options2.app_dir}`)) {
    return text("Not found", { status: 404 });
  }
  const is_data_request = has_data_suffix(decoded);
  let invalidated_data_nodes;
  if (is_data_request) {
    decoded = strip_data_suffix(decoded) || "/";
    url.pathname = strip_data_suffix(url.pathname) + (url.searchParams.get(TRAILING_SLASH_PARAM) === "1" ? "/" : "") || "/";
    url.searchParams.delete(TRAILING_SLASH_PARAM);
    invalidated_data_nodes = url.searchParams.get(INVALIDATED_PARAM)?.split("").map((node) => node === "1");
    url.searchParams.delete(INVALIDATED_PARAM);
  }
  if (!state2.prerendering?.fallback) {
    const matchers = await manifest2._.matchers();
    for (const candidate of manifest2._.routes) {
      const match = candidate.pattern.exec(decoded);
      if (!match)
        continue;
      const matched = exec(match, candidate.params, matchers);
      if (matched) {
        route = candidate;
        params = decode_params(matched);
        break;
      }
    }
  }
  let trailing_slash = void 0;
  const headers2 = {};
  let cookies_to_add = {};
  const event = {
    // @ts-expect-error `cookies` and `fetch` need to be created after the `event` itself
    cookies: null,
    // @ts-expect-error
    fetch: null,
    getClientAddress: state2.getClientAddress || (() => {
      throw new Error(
        `${"@sveltejs/adapter-vercel"} does not specify getClientAddress. Please raise an issue`
      );
    }),
    locals: {},
    params,
    platform: state2.platform,
    request,
    route: { id: route?.id ?? null },
    setHeaders: (new_headers) => {
      for (const key2 in new_headers) {
        const lower = key2.toLowerCase();
        const value = new_headers[key2];
        if (lower === "set-cookie") {
          throw new Error(
            "Use `event.cookies.set(name, value, options)` instead of `event.setHeaders` to set cookies"
          );
        } else if (lower in headers2) {
          throw new Error(`"${key2}" header is already set`);
        } else {
          headers2[lower] = value;
          if (state2.prerendering && lower === "cache-control") {
            state2.prerendering.cache = /** @type {string} */
            value;
          }
        }
      }
    },
    url,
    isDataRequest: is_data_request,
    isSubRequest: state2.depth > 0
  };
  let resolve_opts = {
    transformPageChunk: default_transform,
    filterSerializedResponseHeaders: default_filter,
    preload: default_preload
  };
  try {
    if (route) {
      if (url.pathname === base || url.pathname === base + "/") {
        trailing_slash = "always";
      } else if (route.page) {
        const nodes = await load_page_nodes(route.page, manifest2);
        if (DEV)
          ;
        trailing_slash = get_option(nodes, "trailingSlash");
      } else if (route.endpoint) {
        const node = await route.endpoint();
        trailing_slash = node.trailingSlash;
        if (DEV)
          ;
      }
      if (!is_data_request) {
        const normalized = normalize_path(url.pathname, trailing_slash ?? "never");
        if (normalized !== url.pathname && !state2.prerendering?.fallback) {
          return new Response(void 0, {
            status: 308,
            headers: {
              "x-sveltekit-normalize": "1",
              location: (
                // ensure paths starting with '//' are not treated as protocol-relative
                (normalized.startsWith("//") ? url.origin + normalized : normalized) + (url.search === "?" ? "" : url.search)
              )
            }
          });
        }
      }
      if (state2.before_handle || state2.emulator?.platform) {
        let config4 = {};
        let prerender = false;
        if (route.endpoint) {
          const node = await route.endpoint();
          config4 = node.config ?? config4;
          prerender = node.prerender ?? prerender;
        } else if (route.page) {
          const nodes = await load_page_nodes(route.page, manifest2);
          config4 = get_page_config(nodes) ?? config4;
          prerender = get_option(nodes, "prerender") ?? false;
        }
        if (state2.before_handle) {
          state2.before_handle(event, config4, prerender);
        }
        if (state2.emulator?.platform) {
          event.platform = await state2.emulator.platform({ config: config4, prerender });
        }
      }
    }
    const { cookies, new_cookies, get_cookie_header, set_internal } = get_cookies(
      request,
      url,
      trailing_slash ?? "never"
    );
    cookies_to_add = new_cookies;
    event.cookies = cookies;
    event.fetch = create_fetch({
      event,
      options: options2,
      manifest: manifest2,
      state: state2,
      get_cookie_header,
      set_internal
    });
    if (state2.prerendering && !state2.prerendering.fallback)
      disable_search(url);
    const response = await options2.hooks.handle({
      event,
      resolve: (event2, opts) => resolve2(event2, opts).then((response2) => {
        for (const key2 in headers2) {
          const value = headers2[key2];
          response2.headers.set(
            key2,
            /** @type {string} */
            value
          );
        }
        add_cookies_to_headers(response2.headers, Object.values(cookies_to_add));
        if (state2.prerendering && event2.route.id !== null) {
          response2.headers.set("x-sveltekit-routeid", encodeURI(event2.route.id));
        }
        return response2;
      })
    });
    if (response.status === 200 && response.headers.has("etag")) {
      let if_none_match_value = request.headers.get("if-none-match");
      if (if_none_match_value?.startsWith('W/"')) {
        if_none_match_value = if_none_match_value.substring(2);
      }
      const etag2 = (
        /** @type {string} */
        response.headers.get("etag")
      );
      if (if_none_match_value === etag2) {
        const headers22 = new Headers({ etag: etag2 });
        for (const key2 of [
          "cache-control",
          "content-location",
          "date",
          "expires",
          "vary",
          "set-cookie"
        ]) {
          const value = response.headers.get(key2);
          if (value)
            headers22.set(key2, value);
        }
        return new Response(void 0, {
          status: 304,
          headers: headers22
        });
      }
    }
    if (is_data_request && response.status >= 300 && response.status <= 308) {
      const location = response.headers.get("location");
      if (location) {
        return redirect_json_response(new Redirect(
          /** @type {any} */
          response.status,
          location
        ));
      }
    }
    return response;
  } catch (e2) {
    if (e2 instanceof Redirect) {
      const response = is_data_request ? redirect_json_response(e2) : route?.page && is_action_json_request(event) ? action_json_redirect(e2) : redirect_response(e2.status, e2.location);
      add_cookies_to_headers(response.headers, Object.values(cookies_to_add));
      return response;
    }
    return await handle_fatal_error(event, options2, e2);
  }
  async function resolve2(event2, opts) {
    try {
      if (opts) {
        resolve_opts = {
          transformPageChunk: opts.transformPageChunk || default_transform,
          filterSerializedResponseHeaders: opts.filterSerializedResponseHeaders || default_filter,
          preload: opts.preload || default_preload
        };
      }
      if (state2.prerendering?.fallback) {
        return await render_response({
          event: event2,
          options: options2,
          manifest: manifest2,
          state: state2,
          page_config: { ssr: false, csr: true },
          status: 200,
          error: null,
          branch: [],
          fetched: [],
          resolve_opts
        });
      }
      if (route) {
        const method = (
          /** @type {import('types').HttpMethod} */
          event2.request.method
        );
        let response;
        if (is_data_request) {
          response = await render_data(
            event2,
            route,
            options2,
            manifest2,
            state2,
            invalidated_data_nodes,
            trailing_slash ?? "never"
          );
        } else if (route.endpoint && (!route.page || is_endpoint_request(event2))) {
          response = await render_endpoint(event2, await route.endpoint(), state2);
        } else if (route.page) {
          if (page_methods.has(method)) {
            response = await render_page(event2, route.page, options2, manifest2, state2, resolve_opts);
          } else {
            const allowed_methods2 = new Set(allowed_page_methods);
            const node = await manifest2._.nodes[route.page.leaf]();
            if (node?.server?.actions) {
              allowed_methods2.add("POST");
            }
            if (method === "OPTIONS") {
              response = new Response(null, {
                status: 204,
                headers: {
                  allow: Array.from(allowed_methods2.values()).join(", ")
                }
              });
            } else {
              const mod = [...allowed_methods2].reduce(
                (acc, curr) => {
                  acc[curr] = true;
                  return acc;
                },
                /** @type {Record<string, any>} */
                {}
              );
              response = method_not_allowed(mod, method);
            }
          }
        } else {
          throw new Error("This should never happen");
        }
        if (request.method === "GET" && route.page && route.endpoint) {
          const vary = response.headers.get("vary")?.split(",")?.map((v3) => v3.trim().toLowerCase());
          if (!(vary?.includes("accept") || vary?.includes("*"))) {
            response = new Response(response.body, {
              status: response.status,
              statusText: response.statusText,
              headers: new Headers(response.headers)
            });
            response.headers.append("Vary", "Accept");
          }
        }
        return response;
      }
      if (state2.error && event2.isSubRequest) {
        return await fetch(request, {
          headers: {
            "x-sveltekit-error": "true"
          }
        });
      }
      if (state2.error) {
        return text("Internal Server Error", {
          status: 500
        });
      }
      if (state2.depth === 0) {
        return await respond_with_error({
          event: event2,
          options: options2,
          manifest: manifest2,
          state: state2,
          status: 404,
          error: new SvelteKitError(404, "Not Found", `Not found: ${event2.url.pathname}`),
          resolve_opts
        });
      }
      if (state2.prerendering) {
        return text("not found", { status: 404 });
      }
      return await fetch(request);
    } catch (e2) {
      return await handle_fatal_error(event2, options2, e2);
    } finally {
      event2.cookies.set = () => {
        throw new Error("Cannot use `cookies.set(...)` after the response has been generated");
      };
      event2.setHeaders = () => {
        throw new Error("Cannot use `setHeaders(...)` after the response has been generated");
      };
    }
  }
}
function filter_private_env(env, { public_prefix, private_prefix }) {
  return Object.fromEntries(
    Object.entries(env).filter(
      ([k3]) => k3.startsWith(private_prefix) && (public_prefix === "" || !k3.startsWith(public_prefix))
    )
  );
}
function filter_public_env(env, { public_prefix, private_prefix }) {
  return Object.fromEntries(
    Object.entries(env).filter(
      ([k3]) => k3.startsWith(public_prefix) && (private_prefix === "" || !k3.startsWith(private_prefix))
    )
  );
}
var prerender_env_handler = {
  get({ type }, prop) {
    throw new Error(
      `Cannot read values from $env/dynamic/${type} while prerendering (attempted to read env.${prop.toString()}). Use $env/static/${type} instead`
    );
  }
};
var _options, _manifest;
var Server = class {
  /** @param {import('@sveltejs/kit').SSRManifest} manifest */
  constructor(manifest2) {
    /** @type {import('types').SSROptions} */
    __privateAdd(this, _options, void 0);
    /** @type {import('@sveltejs/kit').SSRManifest} */
    __privateAdd(this, _manifest, void 0);
    __privateSet(this, _options, options);
    __privateSet(this, _manifest, manifest2);
  }
  /**
   * @param {{
   *   env: Record<string, string>;
   *   read?: (file: string) => ReadableStream;
   * }} opts
   */
  async init({ env, read }) {
    const prefixes = {
      public_prefix: __privateGet(this, _options).env_public_prefix,
      private_prefix: __privateGet(this, _options).env_private_prefix
    };
    const private_env2 = filter_private_env(env, prefixes);
    const public_env2 = filter_public_env(env, prefixes);
    set_private_env(
      prerendering ? new Proxy({ type: "private" }, prerender_env_handler) : private_env2
    );
    set_public_env(
      prerendering ? new Proxy({ type: "public" }, prerender_env_handler) : public_env2
    );
    set_safe_public_env(public_env2);
    if (!__privateGet(this, _options).hooks) {
      try {
        const module = await get_hooks();
        __privateGet(this, _options).hooks = {
          handle: module.handle || (({ event, resolve: resolve2 }) => resolve2(event)),
          handleError: module.handleError || (({ error }) => console.error(error)),
          handleFetch: module.handleFetch || (({ request, fetch: fetch2 }) => fetch2(request)),
          reroute: module.reroute || (() => {
          })
        };
      } catch (error) {
        {
          throw error;
        }
      }
    }
  }
  /**
   * @param {Request} request
   * @param {import('types').RequestOptions} options
   */
  async respond(request, options2) {
    return respond(request, __privateGet(this, _options), __privateGet(this, _manifest), {
      ...options2,
      error: false,
      depth: 0
    });
  }
};
_options = new WeakMap();
_manifest = new WeakMap();

// .svelte-kit/vercel-tmp/fn/manifest.js
var manifest = (() => {
  function __memo(fn) {
    let value;
    return () => value ?? (value = value = fn());
  }
  return {
    appDir: "_app",
    appPath: "_app",
    assets: /* @__PURE__ */ new Set(["favicon.png"]),
    mimeTypes: { ".png": "image/png" },
    _: {
      client: { "start": "_app/immutable/entry/start.CrDpCT18.js", "app": "_app/immutable/entry/app.CwNSdDTz.js", "imports": ["_app/immutable/entry/start.CrDpCT18.js", "_app/immutable/chunks/entry.Dz1v4b8z.js", "_app/immutable/chunks/scheduler.Rzn6huuy.js", "_app/immutable/entry/app.CwNSdDTz.js", "_app/immutable/chunks/scheduler.Rzn6huuy.js", "_app/immutable/chunks/index.D6xxGKKq.js"], "stylesheets": [], "fonts": [], "uses_env_dynamic_public": false },
      nodes: [
        __memo(() => Promise.resolve().then(() => (init__(), __exports))),
        __memo(() => Promise.resolve().then(() => (init__2(), __exports2))),
        __memo(() => Promise.resolve().then(() => (init__3(), __exports3))),
        __memo(() => Promise.resolve().then(() => (init__4(), __exports4)))
      ],
      routes: [
        {
          id: "/",
          pattern: /^\/$/,
          params: [],
          page: { layouts: [0], errors: [1], leaf: 2 },
          endpoint: null
        },
        {
          id: "/update/[todoid]",
          pattern: /^\/update\/([^/]+?)\/?$/,
          params: [{ "name": "todoid", "optional": false, "rest": false, "chained": false }],
          page: { layouts: [0], errors: [1], leaf: 3 },
          endpoint: null
        }
      ],
      matchers: async () => {
        return {};
      },
      server_assets: {}
    }
  };
})();

// .svelte-kit/vercel-tmp/fn/edge.js
var server = new Server(manifest);
var initialized = server.init({
  env: (
    /** @type {Record<string, string>} */
    process.env
  )
});
var edge_default = async (request, context) => {
  await initialized;
  return server.respond(request, {
    getClientAddress() {
      return (
        /** @type {string} */
        request.headers.get("x-forwarded-for")
      );
    },
    platform: {
      context
    }
  });
};
export {
  edge_default as default
};
/*! Bundled license information:

cookie/index.js:
  (*!
   * cookie
   * Copyright(c) 2012-2014 Roman Shtylman
   * Copyright(c) 2015 Douglas Christopher Wilson
   * MIT Licensed
   *)
*/
//# sourceMappingURL=index.js.map

import { Groups } from "@gitbeaker/rest";
import TTLCache from "@isaacs/ttlcache";
import type { Request } from "express";
import type * as client from "openid-client";

import { getCallbackPath } from "@/redirect";
import { debug } from "@/server/debugger";
import logger from "@/server/logger";
import type { AuthProvider, OpenIDToken, ProviderUser, TokenInfo } from "@/server/plugin/AuthProvider";
import type { ConfigHolder } from "@/server/plugin/Config";
import { getBaseUrl, getClaimsFromIdToken, hashObject } from "@/server/plugin/utils";

export class OpenIDConnectAuthProvider implements AuthProvider {
  private client?: typeof client;
  private clientConfig?: client.Configuration;

  private providerHost: string;
  private scope: string;

  private readonly stateCache: TTLCache<string, string>;
  private readonly userinfoCache: TTLCache<string, Record<string, unknown>>;
  private readonly groupsCache: TTLCache<string, string[]>;

  constructor(private readonly config: ConfigHolder) {
    this.providerHost = this.config.providerHost;
    this.scope = this.config.scope;

    this.stateCache = new TTLCache({ max: 1000, ttl: 5 * 60 * 1000 }); // 5min
    this.userinfoCache = new TTLCache({ max: 1000, ttl: 60 * 1000 }); // 1min
    this.groupsCache = new TTLCache({ max: 1000, ttl: 5 * 60 * 1000 }); // 5m;

    this.init().catch((e) => {
      logger.error({ message: e.message }, "Could not discover client: @{message}");
    });
  }

  private get openIDClient(): typeof client {
    if (!this.client) {
      throw new ReferenceError("Import 'openid-client' failed");
    }

    return this.client;
  }

  private get openIDClientConfig(): client.Configuration {
    if (!this.clientConfig) {
      throw new ReferenceError("Client configuration has not been discovered");
    }

    return this.clientConfig;
  }

  private async init() {
    this.client = await import("openid-client");

    let config: client.Configuration;

    const configurationUri = this.config.configurationUri;
    const clientId = this.config.clientId;
    const clientSecret = this.config.clientSecret;

    if (configurationUri) {
      config = await this.client.discovery(new URL(configurationUri), clientId, clientSecret);
    } else {
      const providerHost = this.providerHost;

      const authorizationEndpoint = this.config.authorizationEndpoint;
      const tokenEndpoint = this.config.tokenEndpoint;
      const userinfoEndpoint = this.config.userinfoEndpoint;
      const jwksUri = this.config.jwksUri;

      if ([authorizationEndpoint, tokenEndpoint, userinfoEndpoint, jwksUri].some((endpoint) => !!endpoint)) {
        config = new this.client.Configuration(
          {
            issuer: this.config.issuer ?? providerHost,
            authorization_endpoint: authorizationEndpoint,
            token_endpoint: tokenEndpoint,
            userinfo_endpoint: userinfoEndpoint,
            jwks_uri: jwksUri,
            response_types_supported: ["code"],
          },
          clientId,
          clientSecret,
        );
      } else {
        if (!providerHost) {
          throw new ReferenceError("Provider host is not set");
        }
        config = await this.client.discovery(new URL(providerHost), clientId, clientSecret);
      }
    }

    this.clientConfig = config;
  }

  getId(): string {
    return "openid";
  }

  getLoginUrl(request: Request): string {
    const baseUrl = getBaseUrl(this.config.urlPrefix, request, true);
    const redirectUrl = baseUrl + getCallbackPath(request.params.id);

    const state = this.openIDClient.randomState();
    const nonce = this.openIDClient.randomNonce();

    this.stateCache.set(state, nonce);

    const u = this.openIDClient.buildAuthorizationUrl(this.openIDClientConfig, {
      scope: this.scope,
      redirect_uri: redirectUrl,
      state: state,
      nonce: nonce,
    });

    return u.toString();
  }

  /**
   * Parse callback request and get the token from provider.
   *
   * @param callbackRequest
   * @returns
   */
  async getToken(callbackRequest: Request): Promise<TokenInfo> {
    const parameters = callbackRequest.query;

    debug("Receive callback parameters, %j", parameters);

    const state = parameters.state;
    if (!state || typeof state !== "string") {
      throw new URIError("State parameter is missing or not a string");
    }

    if (!this.stateCache.has(state)) {
      throw new URIError("State parameter does not match a known state");
    }

    const nonce = this.stateCache.get(state);
    this.stateCache.delete(state);

    const tokens = await this.openIDClient.authorizationCodeGrant(this.openIDClientConfig, callbackRequest, {
      expectedNonce: nonce,
      expectedState: state,
      idTokenExpected: this.scope.includes("openid"),
    });
    if (!tokens.access_token) {
      throw new Error("No access_token was returned from the provider");
    }

    const expiresIn = tokens.expiresIn();

    if (!expiresIn) {
      throw new TypeError('Token is expired or does not have "expires_in"');
    }

    const claims = tokens.claims()!;

    const expiresAt = claims.exp ?? Math.trunc(Date.now() / 1000) + expiresIn;

    return {
      subject: claims.sub,
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      expiresAt: expiresAt,
    };
  }

  /**
   * Get the user info from id_token
   *
   * @param token
   * @returns
   */
  private getUserinfoFromIdToken(token: TokenInfo): Record<string, unknown> {
    const idToken = token.idToken;
    if (!idToken) {
      throw new TypeError("No 'id_token' found in token");
    }
    return getClaimsFromIdToken(idToken);
  }

  /**
   * Get the user info from the userinfo endpoint or from the cache.
   *
   * @param token
   * @returns
   */
  private async getUserinfoFromEndpoint(token: OpenIDToken): Promise<Record<string, unknown>> {
    let accessToken: string;
    let key: string;
    let subject: string | undefined;

    if (typeof token === "string") {
      accessToken = token;
      key = token;
    } else {
      accessToken = token.accessToken;
      key = token.subject ?? hashObject(token);
      subject = token.subject;
    }

    let userinfo = this.userinfoCache.get(key);

    if (!userinfo) {
      userinfo = await this.openIDClient.fetchUserInfo(
        this.openIDClientConfig,
        accessToken,
        subject ?? this.openIDClient.skipSubjectCheck,
      );

      this.userinfoCache.set(key, userinfo);
    }
    return userinfo;
  }

  /**
   * Get the user from the userinfo.
   *
   * @param token
   * @returns
   */
  async getUserinfo(token: OpenIDToken): Promise<ProviderUser> {
    let userinfo: Record<string, unknown>;

    let username: unknown, groups: unknown;
    if (typeof token !== "string") {
      /**
       * username and groups can be in the id_token if the scope is openid.
       */
      try {
        userinfo = this.getUserinfoFromIdToken(token);

        username = userinfo[this.config.usernameClaim];
        if (this.config.groupsClaim) {
          groups = userinfo[this.config.groupsClaim];
        }
      } catch {
        debug("Could not get userinfo from id_token. Trying userinfo endpoint...");
      }
    }

    if (!username || !groups) {
      /**
       * or we can get them from the userinfo endpoint.
       */
      try {
        userinfo = await this.getUserinfoFromEndpoint(token);

        username ??= userinfo[this.config.usernameClaim];
        if (this.config.groupsClaim) {
          groups ??= userinfo[this.config.groupsClaim];
        }
      } catch {
        debug("Could not get userinfo from userinfo endpoint.");
      }
    }

    if (!username) {
      throw new Error(`Could not get username with claim: "${this.config.usernameClaim}"`);
    }

    // We prefer the groups from the providerType if it is set.
    if (this.config.providerType) {
      groups = await this.getGroupsWithProviderType(token, this.config.providerType);
    }

    if (groups) {
      groups = Array.isArray(groups) ? groups.map(String) : [String(groups)];
    }

    return {
      name: String(username),
      groups: groups as string[] | undefined,
    };
  }

  /**
   * Get the groups for the user from the provider.
   *
   * @param token
   * @param providerType
   * @returns
   */
  private async getGroupsWithProviderType(token: OpenIDToken, providerType: string): Promise<string[]> {
    const key = typeof token === "string" ? token : (token.subject ?? hashObject(token));

    let groups = this.groupsCache.get(key);

    if (groups) return groups;

    switch (providerType) {
      case "gitlab": {
        groups = await this.getGitlabGroups(token);
        break;
      }
      default: {
        throw new ReferenceError("Unexpected provider type.");
      }
    }

    this.groupsCache.set(key, groups);
    return groups;
  }

  /**
   * Get the groups for the user from the Gitlab API.
   *
   * @param token
   * @returns {Promise<string[]>} The groups the user is in.
   */
  async getGitlabGroups(token: OpenIDToken): Promise<string[]> {
    const group = new Groups({
      host: this.providerHost,
      oauthToken: typeof token === "string" ? token : token.accessToken,
    });

    const userGroups = await group.all();

    return userGroups.map((g) => g.name);
  }
}

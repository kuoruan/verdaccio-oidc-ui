import { authenticatedUserGroups } from "@/constants";
import logger from "@/logger";

import { ParsedPluginConfig } from "./Config";
import { Verdaccio } from "./Verdaccio";

import type { RemoteUser } from "@verdaccio/types";

export class AuthCore {
  private readonly configuredGroups: Record<string, true>;

  constructor(private readonly verdaccio: Verdaccio, private readonly config: ParsedPluginConfig) {
    this.configuredGroups = this.getConfiguredGroups();
  }

  /**
   * Returns all permission groups used in the Verdacio config.
   */
  getConfiguredGroups() {
    const configuredGroups: Record<string, true> = {};
    Object.values(this.config.packages || {}).forEach((packageConfig) => {
      ["access", "publish", "unpublish"]
        .flatMap((key) => packageConfig[key])
        .filter(Boolean)
        .forEach((group: string) => {
          configuredGroups[group] = true;
        });
    });
    return configuredGroups;
  }

  private get requiredGroup(): string | null {
    return this.config.authorizedGroup ? this.config.authorizedGroup : null;
  }

  createAuthenticatedUser(username: string, groups: string[]): RemoteUser {
    const relevantGroups = groups.filter((group) => group in this.configuredGroups);

    relevantGroups.push(username);

    if (this.requiredGroup) {
      relevantGroups.push(this.requiredGroup);
    }

    // get unique and sorted groups
    const realGroups = relevantGroups.filter((val, index, self) => self.indexOf(val) === index).sort();

    const user: RemoteUser = {
      name: username,
      groups: [...authenticatedUserGroups, ...realGroups],
      real_groups: realGroups,
    };
    logger.info({ user }, "Created authenticated user @{user}");

    return user;
  }

  async createUiCallbackUrl(username: string, providerToken: string, groups: string[]): Promise<string> {
    const user = this.createAuthenticatedUser(username, groups);

    const uiToken = await this.verdaccio.issueUiToken(user);
    const npmToken = await this.verdaccio.issueNpmToken(providerToken, user);

    const query = { username, uiToken, npmToken };
    return `/?${new URLSearchParams(query).toString()}`;
  }

  authenticate(username: string, groups: string[] = []): boolean {
    if (this.requiredGroup) {
      if (username !== this.requiredGroup && !groups.includes(this.requiredGroup)) {
        logger.error(
          { username, requiredGroup: this.requiredGroup },
          `Access denied: User "@{username}" is not a member of "@{requiredGroup}"`
        );
        return false;
      }
    }

    // empty group is allowed
    return true;
  }
}

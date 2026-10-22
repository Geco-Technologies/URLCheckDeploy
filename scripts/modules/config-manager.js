/**
 * Configuration Manager for Check
 * Handles enterprise configuration, branding, and settings management
 */

import { chrome, storage } from "../browser-polyfill.js";
import logger from "../utils/logger.js";

export class ConfigManager {
  constructor() {
    this.config = null;
    this.brandingConfig = null;
    this.enterpriseConfig = null;
  }

  async loadConfig() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try {
          return await promise;
        } catch (_) {
          return {};
        }
      };

      // Load enterprise configuration from managed storage (GPO/Intune)
      this.enterpriseConfig = await this.loadEnterpriseConfig();

      // Load local configuration with safe wrapper
      const localConfig = await safe(storage.local.get(["config"]));

      // Migrate legacy configuration structure if needed
      if (localConfig?.config) {
        localConfig.config = this.migrateLegacyConfig(localConfig.config);
      }

      // Load branding configuration
      this.brandingConfig = await this.loadBrandingConfig();

      // Merge configurations with enterprise taking precedence
      this.config = this.mergeConfigurations(
        localConfig?.config,
        this.enterpriseConfig,
        this.brandingConfig
      );

      logger.log("Check: Configuration loaded successfully");
      return this.config;
    } catch (error) {
      logger.error("Check: Failed to load configuration:", error);
      throw error;
    }
  }

  migrateLegacyConfig(config) {
    // Migrate legacy detectionRules.customRulesUrl to top-level customRulesUrl
    if (config.detectionRules?.customRulesUrl && !config.customRulesUrl) {
      config.customRulesUrl = config.detectionRules.customRulesUrl;
      logger.log("Check: Migrated legacy customRulesUrl to top-level");
    }

    // Migrate legacy detectionRules.updateInterval to top-level updateInterval
    if (config.detectionRules?.updateInterval && !config.updateInterval) {
      // Convert milliseconds to hours if needed
      const interval = config.detectionRules.updateInterval;
      config.updateInterval = interval > 1000 ? Math.round(interval / 3600000) : interval;
      logger.log("Check: Migrated legacy updateInterval to top-level");
    }

    return config;
  }

  async loadEnterpriseConfig() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try {
          return await promise;
        } catch (_) {
          return {};
        }
      };

      // Check if we're in development mode for mock policies
      const isDevelopment = this.isDevelopmentMode();

      // Check if enterprise simulation mode is enabled (dev only)
      let simulateEnterpriseMode = false;
      if (isDevelopment) {
        const simulateMode = await safe(
          storage.local.get(["simulateEnterpriseMode"])
        );
        simulateEnterpriseMode = simulateMode?.simulateEnterpriseMode || false;
      }

      if (isDevelopment && simulateEnterpriseMode) {
        // Return mock enterprise configuration for development/testing
        logger.log(
          "Check: Using mock enterprise configuration (simulate mode enabled)"
        );
        return {
          // Extension configuration
          showNotifications: true,
          enableValidPageBadge: true,
          enablePageBlocking: true,

      // Phase 1 / 1b / 2 — device-code phishing + unlock (ClickFix flag only)
      enableDeviceCodePhishingHeuristics: true,
      hardBlockLegitimateDeviceLogin: true,
      enableUnlockCodes: true,
      unlockValidationMode: "policy_list",
      unlockCodeEntries: [],
      unlockEndpointUrl: "",
      unlockDeviceLabel: "",
      unlockDefaultTtlSeconds: 14400,
      unlockMaxAttempts: 5,
      unlockAttemptWindowSeconds: 900,
      unlockHelpdeskMessage:
        "Contact Unite helpdesk (phone/Teams) and ask for an unlock code. Do not enter codes from unsolicited email or chat.",
      enableClickFixHeuristics: false,

          enableCippReporting: false,
          cippServerUrl: "",
          cippTenantId: "",
          customRulesUrl:
            "https://raw.githubusercontent.com/CyberDrain/Check/refs/heads/main/rules/detection-rules.json",
          updateInterval: 24,
          enableDebugLogging: false,
          domainSquatting: {
            enabled: true,
            deviationThreshold: 2,
            algorithms: {
              levenshtein: true,
              homoglyph: true,
              typosquat: true,
              combosquat: true,
            },
            protectedDomains: [],
            Action: "block",
            logDetections: true,
          },
          // Note: enableDeveloperConsoleLogging is not policy-managed - remains under user control

          // Custom branding (matches managed_schema.json structure)
          customBranding: {
            companyName: "Unite Networks",
            productName: "Check Enterprise",
            supportUrl: "",
            privacyPolicyUrl: "",
            aboutUrl: "",
            primaryColor: "#7C2FC9",
            logoUrl: "images/icon128.png",
          },
        };
      }

      // Attempt to load from managed storage (deployed via GPO/Intune)
      const managedConfig = await safe(storage.managed.get(null));

      if (managedConfig && Object.keys(managedConfig).length > 0) {
        logger.log("Check: Enterprise configuration found");
        return managedConfig;
      }

      return {};
    } catch (error) {
      logger.log("Check: No enterprise configuration available");
      return {};
    }
  }

  isDevelopmentMode() {
    // Check if we're in development mode
    // This could be based on environment, hostname, or other indicators
    try {
      // Check if we're running in an extension context and in development
      const manifestData = chrome.runtime.getManifest();
      const isDev = !("update_url" in manifestData); // No update_url means unpacked extension
      return isDev;
    } catch (error) {
      return false;
    }
  }

  async loadBrandingConfig() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try {
          return await promise;
        } catch (_) {
          return null;
        }
      };

      // First, try to load user-configured branding from storage
      const userBranding = await safe(
        storage.local.get(["brandingConfig"])
      );

      if (userBranding && userBranding.brandingConfig) {
        logger.log("Check: Using user-configured branding from storage");
        return userBranding.brandingConfig;
      }

      // Fallback: Load branding configuration from config file with timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      try {
        const response = await fetch(
          chrome.runtime.getURL("config/branding.json"),
          { signal: controller.signal }
        );
        clearTimeout(timeoutId);

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const brandingConfig = await response.json();
        logger.log("Check: Using branding from config file");
        return brandingConfig;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      logger.log("Check: Using default branding configuration");
      return this.getDefaultBrandingConfig();
    }
  }

  mergeConfigurations(localConfig, enterpriseConfig, brandingConfig) {
    const defaultConfig = this.getDefaultConfig();

    // Handle enterprise custom branding separately
    let finalBrandingConfig = brandingConfig;
    if (enterpriseConfig.customBranding) {
      // Enterprise custom branding takes precedence over file-based branding
      finalBrandingConfig = {
        ...brandingConfig,
        ...enterpriseConfig.customBranding,
      };
    }

    // Merge in order of precedence: enterprise > local > branding > default
    const merged = {
      ...defaultConfig,
      ...finalBrandingConfig,
      ...localConfig,
      ...enterpriseConfig,
    };

    // Fix customRulesUrl precedence - user-saved value should override defaults but NOT enterprise
    if (!enterpriseConfig?.customRulesUrl) {
      if (localConfig?.customRulesUrl && localConfig.customRulesUrl.trim() !== "") {
        merged.customRulesUrl = localConfig.customRulesUrl;
        if (merged.detectionRules) {
          merged.detectionRules.customRulesUrl = localConfig.customRulesUrl;
        }
      } else if (localConfig?.detectionRules?.customRulesUrl && localConfig.detectionRules.customRulesUrl.trim() !== "") {
        merged.customRulesUrl = localConfig.detectionRules.customRulesUrl;
      }
    }

    // Remove customBranding from the top level since it's been merged into branding
    if (merged.customBranding) {
      delete merged.customBranding;
    }
    
    // Auto-enable debug logging when developer console logging is enabled
    if (merged.enableDeveloperConsoleLogging === true && merged.enableDebugLogging !== true) {
      merged.enableDebugLogging = true;
      logger.log("Check: Auto-enabled debug logging (developer console logging is enabled)");
    }

    // Ensure enterprise policies cannot be overridden
    if (enterpriseConfig.enforcedPolicies) {
      merged.enforcedPolicies = enterpriseConfig.enforcedPolicies;

      // Lock configuration options that are enterprise-managed
      Object.keys(enterpriseConfig.enforcedPolicies).forEach((policy) => {
        if (enterpriseConfig.enforcedPolicies[policy].locked) {
          merged[policy] = enterpriseConfig[policy];
        }
      });
    }

    return merged;
  }

  getDefaultConfig() {
    return {
      // Extension settings
      extensionEnabled: true,
      debugMode: false,

      // Security settings
      blockMaliciousUrls: true,
      blockPhishingAttempts: true,
      enableContentManipulation: true,
      enableUrlMonitoring: true,

      // Detection settings
      detectionRules: {
        enableCustomRules: true,
        updateInterval: 86400000, // 24 hours
        strictMode: false,
      },

      // UI settings
      showNotifications: true,
      notificationDuration: 5000,
      enableValidPageBadge: true,
      enablePageBlocking: true,
      enableDeviceCodePhishingHeuristics: true,
      hardBlockLegitimateDeviceLogin: true,
      enableUnlockCodes: true,
      unlockValidationMode: "policy_list",
      unlockCodeEntries: [],
      unlockEndpointUrl: "",
      unlockDeviceLabel: "",
      unlockDefaultTtlSeconds: 14400,
      unlockMaxAttempts: 5,
      unlockAttemptWindowSeconds: 900,
      unlockHelpdeskMessage:
        "Contact Unite helpdesk (phone/Teams) and ask for an unlock code. Do not enter codes from unsolicited email or chat.",
      enableClickFixHeuristics: false,

      // Debug settings
      enableDebugLogging: false,

      // Custom rules - centralized at top level
      customRulesUrl: "https://raw.githubusercontent.com/CyberDrain/Check/refs/heads/main/rules/detection-rules.json",
      updateInterval: 24, // hours

      // Domain squatting runtime settings
      domainSquatting: {
        enabled: true,
        deviationThreshold: 2,
        algorithms: {
          levenshtein: true,
          homoglyph: true,
          typosquat: true,
          combosquat: true,
        },
        protectedDomains: [],
        Action: "block",
        logDetections: true,
      },

      // Performance settings
      scanDelay: 100,
      maxScanDepth: 10,

      // Allow/Deny lists
      allowlistedDomains: [],
      denylistedDomains: [],

      // External feed lists (threat-intel URLs fetched and cached in the background)
      externalAllowlistFeeds: [],
      externalBlocklistFeeds: [
        "https://urlhaus.abuse.ch/downloads/text_online/",
      ],
      feedsUpdateInterval: 6, // hours

      // Enterprise features
      enterpriseMode: false,
      centralManagement: false,
      reportingEndpoint: "",

      // CIPP integration
      enableCippReporting: false,
      cippServerUrl: "",
      cippTenantId: "",

      // Feature flags
      features: {
        urlBlocking: true,
        contentInjection: true,
        realTimeScanning: true,
        behaviorAnalysis: false,
      },
    };
  }

  getDefaultBrandingConfig() {
    return {
      // Company branding
      companyName: "Check",
      productName: "Check",
      version: "1.0.0",

      // Visual branding
      primaryColor: "#F77F00",
      secondaryColor: "#64748b",
      logoUrl: "images/icon48.png",
      faviconUrl: "images/favicon.ico",

      // Contact information
      supportEmail: "",
      supportUrl: "",
      privacyPolicyUrl: "",
      aboutUrl: "",
      termsOfServiceUrl: "",

      // Customizable text
      welcomeMessage:
        "Welcome to Check - Your Enterprise Web Security Solution",
      blockedPageTitle: "Access Blocked by Check",
      blockedPageMessage:
        "This page has been blocked by your organization's security policy.",

      // Feature customization
      showCompanyBranding: true,

      // License information
      licenseKey: "",
      licensedTo: "",
      licenseExpiry: null,
    };
  }

  async setDefaultConfig() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try {
          return await promise;
        } catch (_) {
          return undefined;
        }
      };

      const defaultConfig = this.getDefaultConfig();
      await safe(storage.local.set({ config: defaultConfig }));
      this.config = defaultConfig;
    } catch (error) {
      logger.error("Check: Failed to set default config:", error);
      this.config = this.getDefaultConfig();
    }
  }

  async updateConfig(updates) {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try {
          return await promise;
        } catch (_) {
          return undefined;
        }
      };

      // Get the CURRENT LOCAL CONFIG (not merged), so we only save user overrides
      const localConfigResult = await safe(storage.local.get(["config"]));
      const localConfig = localConfigResult?.config || {};
      
      // Merge updates into the local config (not the merged config)
      const updatedLocalConfig = { ...localConfig, ...updates };
      
      // Remove empty customRulesUrl to allow fallback to default
      if (updates.customRulesUrl !== undefined && updates.customRulesUrl.trim() === '') {
        delete updatedLocalConfig.customRulesUrl;
      }

      // Validate that enterprise-enforced policies are not being modified
      if (this.enterpriseConfig?.enforcedPolicies) {
        Object.keys(this.enterpriseConfig.enforcedPolicies).forEach(
          (policy) => {
            if (
              this.enterpriseConfig.enforcedPolicies[policy]?.locked &&
              updates[policy] !== undefined &&
              updates[policy] !== this.enterpriseConfig[policy]
            ) {
              throw new Error(
                `Policy '${policy}' is locked by enterprise configuration`
              );
            }
          }
        );
      }

      // Save only the user's config overrides to local storage
      await safe(storage.local.set({ config: updatedLocalConfig }));
      
      // Reload the full merged config
      await this.loadConfig();

      // Notify other components of configuration change with safe wrapper
      try {
        chrome.runtime.sendMessage(
          {
            type: "CONFIG_UPDATED",
            config: this.config,
          },
          () => {
            if (chrome.runtime.lastError) {
              // Silently handle errors
            }
          }
        );
      } catch (error) {
        // Silently handle errors
      }

      return this.config;
    } catch (error) {
      logger.error("Check: Failed to update configuration:", error);
      throw error;
    }
  }

  async getConfig() {
    if (!this.config) {
      await this.loadConfig();
    }
    return this.config;
  }

  async getBrandingConfig() {
    if (!this.brandingConfig) {
      await this.loadConfig();
    }
    return this.brandingConfig;
  }

  async getFinalBrandingConfig() {
    // Get the enterprise config to check for custom branding
    if (!this.enterpriseConfig) {
      await this.loadConfig();
    }

    // Start with defaults to ensure required branding links are always available
    const defaultBranding = this.getDefaultBrandingConfig();
    let finalBranding = {
      ...defaultBranding,
      ...(await this.getBrandingConfig()),
    };

    // If enterprise has custom branding, merge it in (takes precedence)
    if (this.enterpriseConfig && this.enterpriseConfig.customBranding) {
      finalBranding = {
        ...finalBranding,
        ...this.enterpriseConfig.customBranding,
      };
      logger.log("Check: Applied enterprise custom branding");
    }

    // Include genericWebhook from config if available
    const currentConfig = await this.getConfig();
    if (currentConfig.genericWebhook) {
      finalBranding.genericWebhook = currentConfig.genericWebhook;
    }

    // Derive support URL when only partial branding is configured
    if (!finalBranding.supportUrl && finalBranding.supportEmail) {
      finalBranding.supportUrl = `mailto:${finalBranding.supportEmail}`;
    }

    return finalBranding;
  }

  async refreshConfig() {
    this.config = null;
    this.brandingConfig = null;
    this.enterpriseConfig = null;
    return await this.loadConfig();
  }

  async migrateConfig(previousVersion) {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try {
          return await promise;
        } catch (_) {
          return {};
        }
      };

      logger.log(
        `Check: Migrating configuration from version ${previousVersion}`
      );

      const currentConfig = await safe(storage.local.get(["config"]));
      if (!currentConfig?.config) return;

      let changed = false;
      const cfg = { ...currentConfig.config };

      // Seed the URLhaus blocklist feed for existing installs that have never
      // configured external feeds (the field was added as a default in a later
      // version, so older stored configs will be missing it or have an empty array).
      if (!Array.isArray(cfg.externalBlocklistFeeds) || cfg.externalBlocklistFeeds.length === 0) {
        cfg.externalBlocklistFeeds = ["https://urlhaus.abuse.ch/downloads/text_online/"];
        changed = true;
      }
      if (!Array.isArray(cfg.externalAllowlistFeeds)) {
        cfg.externalAllowlistFeeds = [];
        changed = true;
      }
      if (cfg.feedsUpdateInterval === undefined || cfg.feedsUpdateInterval === null) {
        cfg.feedsUpdateInterval = 6;
        changed = true;
      }

      if (changed) {
        await safe(storage.local.set({ config: cfg }));
        logger.log("Check: Configuration migration: seeded default external feeds");
      }

      logger.log("Check: Configuration migration completed");
    } catch (error) {
      logger.error("Check: Configuration migration failed:", error);
    }
  }

  isVersionLessThan(version1, version2) {
    const v1Parts = version1.split(".").map(Number);
    const v2Parts = version2.split(".").map(Number);

    for (let i = 0; i < Math.max(v1Parts.length, v2Parts.length); i++) {
      const v1Part = v1Parts[i] || 0;
      const v2Part = v2Parts[i] || 0;

      if (v1Part < v2Part) return true;
      if (v1Part > v2Part) return false;
    }

    return false;
  }

  // Utility methods for enterprise deployment
  async exportConfiguration() {
    const config = await this.getConfig();
    const exportData = {
      config,
      branding: this.brandingConfig,
      timestamp: new Date().toISOString(),
      version: chrome.runtime.getManifest().version,
    };

    return JSON.stringify(exportData, null, 2);
  }

  async importConfiguration(configJson) {
    try {
      const importData = JSON.parse(configJson);

      // Validate import data
      if (!importData.config) {
        throw new Error("Invalid configuration format");
      }

      // Update configuration
      await this.updateConfig(importData.config);

      // Update branding if provided with safe wrapper
      if (importData.branding) {
        const safe = async (promise) => {
          try {
            return await promise;
          } catch (_) {
            return undefined;
          }
        };
        await safe(storage.local.set({ branding: importData.branding }));
        this.brandingConfig = importData.branding;
      }

      logger.log("Check: Configuration imported successfully");
      return true;
    } catch (error) {
      logger.error("Check: Failed to import configuration:", error);
      throw error;
    }
  }
}

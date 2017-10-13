const { utils: Cu } = Components;
Cu.import("resource://gre/modules/AddonManager.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

XPCOMUtils.defineLazyModuleGetter(this, "config", "resource://pioneer-study-nothing/Config.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "PioneerUtils",
  "resource://pioneer-study-nothing/PioneerUtils.jsm");

const REASONS = {
  APP_STARTUP:      1, // The application is starting up.
  APP_SHUTDOWN:     2, // The application is shutting down.
  ADDON_ENABLE:     3, // The add-on is being enabled.
  ADDON_DISABLE:    4, // The add-on is being disabled. (Also sent during uninstallation)
  ADDON_INSTALL:    5, // The add-on is being installed.
  ADDON_UNINSTALL:  6, // The add-on is being uninstalled.
  ADDON_UPGRADE:    7, // The add-on is being upgraded.
  ADDON_DOWNGRADE:  8, // The add-on is being downgraded.
};
const PING_SENT_PREF = "extensions.pioneer-study-nothing.pingSent";
const EXPIRATION_DATE_PREF = "extensions.pioneer-study-nothing.expirationDateString";


function uninstallAddon(id) {
  AddonManager.getAddonByID(id, addon => addon.uninstall());
}


this.install = function() {};


this.startup = async function(data, reason) {
  const pioneerUtils = new PioneerUtils(config.pioneer);

  // Always set EXPIRATION_DATE_PREF if it not set, even if outside of install.
  // This is a failsafe if opt-out expiration doesn't work, so should be resilient.
  // Also helps for testing.
  if (!Services.prefs.prefHasUserValue(EXPIRATION_DATE_PREF)) {
    const now = new Date(Date.now());
    const expirationDateString = new Date(now.setDate(now.getDate() + 7)).toISOString();
    Services.prefs.setCharPref(EXPIRATION_DATE_PREF, expirationDateString);
  }

  if (reason === REASONS.ADDON_INSTALL) {
    const eligible = await config.isEligible(); // addon-specific
    if (!eligible) {
      uninstallAddon(data.id);
      return;
    }
  }

  const expirationDate = new Date(Services.prefs.getCharPref(EXPIRATION_DATE_PREF));
  if (Date.now() > expirationDate) {
    uninstallAddon(data.id);
  }

  if (!Services.prefs.getBoolPref(PING_SENT_PREF, false)) {
    const payload = {
      exampleString: `${Date.now()}`,
    };

    pioneerUtils.submitEncryptedPing(payload).then(function() {
      Services.prefs.setBoolPref(PING_SENT_PREF, true);
    });
  }
};


this.shutdown = async function(data, reason) {
  Cu.unload("resource://pioneer-study-nothing/Config.jsm");
  Cu.unload("resource://pioneer-study-nothing/PioneerUtils.jsm");
};


this.uninstall = function() {};

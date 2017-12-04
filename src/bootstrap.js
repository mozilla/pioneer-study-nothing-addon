const { utils: Cu } = Components;
Cu.import("resource://gre/modules/AddonManager.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

XPCOMUtils.defineLazyModuleGetter(
  this, "config", "resource://pioneer-study-nothing/Config.jsm"
);
XPCOMUtils.defineLazyModuleGetter(
  this, "PioneerUtils", "resource://pioneer-study-nothing/PioneerUtils.jsm"
);
XPCOMUtils.defineLazyModuleGetter(
  this, "PrefUtils", "resource://pioneer-study-nothing/lib/PrefUtils.jsm"
);

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


this.install = function() {};


this.startup = async function(data, reason) {
  const pioneerUtils = new PioneerUtils(config);
  const events = pioneerUtils.getAvailableEvents();

  const isEligible = await pioneerUtils.isUserOptedIn();
  if (!isEligible) {
    pioneerUtils.endStudy(events.INELIGIBLE);
    return;
  }

  // Always set EXPIRATION_DATE_PREF if it not set, even if outside of install.
  // This is a failsafe if opt-out expiration doesn't work, so should be resilient.
  let expirationDate = PrefUtils.getLongPref(EXPIRATION_DATE_PREF, 0);
  if (!expirationDate) {
    const phases = Object.values(Config.phases);
    const studyLength = phases.map(p => p.duration || 0).reduce((a, b) => a + b);
    expirationDate = Date.now() + studyLength;
    PrefUtils.setLongPref(EXPIRATION_DATE_PREF, expirationDate);
  }

  // Check if the study has expired
  if (Date.now() > expirationDate) {
    pioneerUtils.endStudy(events.EXPIRED);
    return;
  }

  if (reason === REASONS.ADDON_INSTALL && !Services.prefs.getBoolPref(PING_SENT_PREF, false)) {
    const payload = {
      eventId: "enrolled",
    };
    pioneerUtils.submitEncryptedPing("event", 1, payload).then(function() {
      Services.prefs.setBoolPref(PING_SENT_PREF, true);
    });
  }
};


this.shutdown = async function(data, reason) {
  Cu.unload("resource://pioneer-study-nothing/Config.jsm");
  Cu.unload("resource://pioneer-study-nothing/PioneerUtils.jsm");
  Cu.unload("resource://pioneer-study-nothing/lib/PrefUtils.jsm");
};


this.uninstall = function() {};

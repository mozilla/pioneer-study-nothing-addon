const { utils: Cu } = Components;
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

const { TelemetryController } = Cu.import("resource://gre/modules/TelemetryController.jsm", null);

XPCOMUtils.defineLazyModuleGetter(this, "config",
  "resource://pioneer-study-nothing/Config.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "studyUtils",
  "resource://pioneer-study-nothing/StudyUtils.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "Jose",
  "resource://pioneer-study-nothing/Jose.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "JoseJWE",
  "resource://pioneer-study-nothing/Jose.jsm");

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
const EXPIRATION_DATE_STRING_PREF = "extensions.pioneer-study-nothing.expirationDateString";


// The encryption key ID from the server
const ENCRYPTION_KEY_ID = "pioneer-20170905";

// The public key used for encryption
const PK = {
  "e": "AQAB",
  "kty": "RSA",
  "n": "3nI-DQ7NoUZCvT348Vi4JfGC1h6R3Qf_yXR0dKM5DmwsuQMxguce6sZ28GWQHJjgbdcs8nTuNQihyVtr9vLsoKUVSmPs_a3QEGXEhTpuTtm7cCb_7HyAlwGtysn2AsdElG8HsDFWlZmiDaHTrTmdLnuk-Z3GRg4nnA4xs4vvUuh0fCVIKoSMFyt3Tkc6IBWJ9X3XrDEbSPrghXV7Cu8LMK3Y4avy6rjEGjWXL-WqIPhiYJcBiFnCcqUCMPvdW7Fs9B36asc_2EQAM5d7BAiBwMjoosSyU6b4JGpI530c3xhqLbX00q1ePCG732cIwp0-bGWV_q0FpQX2M9cNv2Ax4Q"
};


async function encryptData(data) {
  const rsa_key = Jose.Utils.importRsaPublicKey(PK, "RSA-OAEP");
  const cryptographer = new Jose.WebCryptographer();
  const encrypter = new JoseJWE.Encrypter(cryptographer, rsa_key);
  return await encrypter.encrypt(data);
}


async function encryptedTelemetryPing() {
  const data = JSON.stringify({
    exampleString: `${Date.now()}`,
  });

  const payload = {
    encryptedData: await encryptData(data),
    encryptionKeyId: ENCRYPTION_KEY_ID,
    pioneerId: config.pioneer.id,
    studyName: config.pioneer.studyName,
    studyVersion: config.study.studyVersion,
  };

  const telOptions = {addClientId: true, addEnvironment: true};

  return TelemetryController.submitExternalPing("pioneer-study", payload, telOptions);
}


this.install = function() {};


this.startup = async function(data, reason) {
  studyUtils.setup({
    ...config,
    addon: {
      id: data.id,
      version: data.version
    },
  });
  const variation = config.study.weightedVariations[0];
  studyUtils.setVariation(variation);

  // Always set EXPIRATION_DATE_PREF if it not set, even if outside of install.
  // This is a failsafe if opt-out expiration doesn't work, so should be resilient.
  // Also helps for testing.
  if (!Services.prefs.prefHasUserValue(EXPIRATION_DATE_STRING_PREF)) {
    const now = new Date(Date.now());
    const expirationDateString = new Date(now.setDate(now.getDate() + 3)).toISOString();
    Services.prefs.setCharPref(EXPIRATION_DATE_STRING_PREF, expirationDateString);
  }

  if (reason === REASONS.ADDON_INSTALL) {
    studyUtils.firstSeen(); // sends telemetry "enter"
    const eligible = await config.isEligible(); // addon-specific
    if (!eligible) {
      // uses config.endings.ineligible.url if any,
      // sends UT for "ineligible"
      // then uninstalls addon
      await studyUtils.endStudy({ reason: "ineligible" });
      return;
    }
  }
  // sets experiment as active and sends installed telemetry upon first install
  await studyUtils.startup({ reason });

  const expirationDate = new Date(Services.prefs.getCharPref(EXPIRATION_DATE_STRING_PREF));
  if (Date.now() > expirationDate) {
    studyUtils.endStudy({ reason: "expired" });
  }

  if (!Services.prefs.getBoolPref(PING_SENT_PREF, false)) {
    encryptedTelemetryPing().then(function() {
      Services.prefs.setBoolPref(PING_SENT_PREF, true);
    });
  }
};


this.shutdown = async function(data, reason) {
  const isUninstall = reason === REASONS.ADDON_UNINSTALL || reason === REASONS.ADDON_DISABLE;
  if (isUninstall) {
    // Send this before the ShuttingDown event to ensure that message handlers
    // are still registered and receive it.
    Services.mm.broadcastAsyncMessage("Pioneer:Uninstalling");

    if (!studyUtils._isEnding) {
      // we are the first requestors, must be user action.
      await studyUtils.endStudy({ reason: "user-disable" });
    }
  }

  Cu.unload("resource://pioneer-study-nothing/StudyUtils.jsm");
  Cu.unload("resource://pioneer-study-nothing/Config.jsm");
  Cu.unload("resource://pioneer-study-nothing/Jose.jsm");
};


this.uninstall = function() {};

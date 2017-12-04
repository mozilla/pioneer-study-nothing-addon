/* eslint no-unused-vars: ["error", { "varsIgnorePattern": "(config|EXPORTED_SYMBOLS)" }]*/

const { utils: Cu } = Components;
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

XPCOMUtils.defineLazyModuleGetter(
  this, "AddonManager", "resource://gre/modules/AddonManager.jsm"
);

const EXPORTED_SYMBOLS = ["config"];

const TELEMETRY_ENV_PREF = "extensions.pioneer-study-nothing.telemetryEnv";


const config = {
  addonId: "nothing-study@pioneer.mozilla.org",
  studyName: "nothing",
  branches: [
    { name: "default", weight: 1 },
  ],
  telemetryEnv: Services.prefs.getCharPref(TELEMETRY_ENV_PREF, "prod"),
};

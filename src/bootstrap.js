"use strict";

/* global  __SCRIPT_URI_SPEC__, Components, Log  */
/* eslint no-unused-vars: ["error", { "varsIgnorePattern": "(startup|shutdown|install|uninstall)" }] */

const { utils: Cu } = Components;

Cu.import('resource://gre/modules/AddonManager.jsm');
Cu.import('resource://gre/modules/Console.jsm');
Cu.import('resource://gre/modules/Log.jsm');
const { TelemetryEnvironment } = Cu.import('resource://gre/modules/TelemetryEnvironment.jsm', null);

const APP_STARTUP = 1;
const APP_SHUTDOWN = 2;
const ADDON_ENABLE = 3;
const ADDON_DISABLE = 4;
const ADDON_INSTALL = 5;
const ADDON_UNINSTALL = 6;
const ADDON_UPGRADE = 7;
const ADDON_DOWNGRADE = 8;

const REASONS = {
  [APP_STARTUP]: 'APP_STARTUP',
  [APP_SHUTDOWN]: 'APP_SHUTDOWN',
  [ADDON_ENABLE]: 'ADDON_ENABLE',
  [ADDON_DISABLE]: 'ADDON_DISABLE',
  [ADDON_INSTALL]: 'ADDON_INSTALL',
  [ADDON_UNINSTALL]: 'ADDON_UNINSTALL',
  [ADDON_UPGRADE]: 'ADDON_UPGRADE',
  [ADDON_DOWNGRADE]: 'ADDON_DOWNGRADE',
};

const CONFIG_PATH = `${__SCRIPT_URI_SPEC__}/../Config.jsm`;
const { config } = Cu.import(CONFIG_PATH, {});

const studyConfig = config.study;

const log = Log.repository.getLogger(studyConfig.studyName);
log.addAppender(new Log.ConsoleAppender(new Log.BasicFormatter()));
log.level = Log.Level[config.log.bootstrap.level] || Log.Level.Debug;

const STUDY_UTILS_PATH = `${__SCRIPT_URI_SPEC__}/../${studyConfig.studyUtilsPath}`;
const { studyUtils } = Cu.import(STUDY_UTILS_PATH, {});

const JOSE_PATH = `${__SCRIPT_URI_SPEC__}/../${studyConfig.josePath}`;
const { Jose } = Cu.import(JOSE_PATH, {});


async function startup(addonData, reason) {
  console.log(Jose);
  // addonData: Array [ "id", "version", "installPath", "resourceURI", "instanceID", "webExtension" ]  bootstrap.js:48
  log.debug("startup", REASONS[reason] || reason);
  studyUtils.setup({
    studyName: studyConfig.studyName,
    endings: studyConfig.endings,
    addon: {id: addonData.id, version: addonData.version},
    telemetry: studyConfig.telemetry,
  });
  studyUtils.setLoggingLevel(config.log.studyUtils.level);

  Jsm.import(config.modules);

  if (reason === ADDON_INSTALL) {
    studyUtils.firstSeen();  // sends telemetry "enter"
    const eligible = await config.isEligible(); // addon-specific
    if (!eligible) {
      // uses config.endings.ineligible.url if any,
      // sends UT for "ineligible"
      // then uninstalls addon
      await studyUtils.endStudy({reason: "ineligible"});
      return;
    }
  }
  await studyUtils.startup({reason});
}


function shutdown(addonData, reason) {
  console.log("shutdown", REASONS[reason] || reason);
  console.log("JSMs unloading");
  Cu.unload('resource://gre/modules/Console.jsm');
  Cu.unload('resource://gre/modules/AddonManager.jsm');
  Cu.unload('resource://gre/modules/TelemetryEnvironment.jsm');
  Jsm.unload(config.modules);
  Jsm.unload([CONFIG_PATH, STUDY_UTILS_PATH, JOSE_PATH]);
}


function uninstall(addonData, reason) {
  console.log("uninstall", REASONS[reason] || reason);
}


function install(addonData, reason) {
  console.log("install", REASONS[reason] || reason);
}


async function removeAddon(addonData){
  console.log(`Uninstalling: ${addonData.id}`);
  await new Promise(function(resolve, reject){
    AddonManager.getAddonByID(addonData.id, addon => resolve(addon.uninstall()));
  });
}


// jsm loader / unloader
class Jsm {
  static import(modulesArray) {
    for (const module of modulesArray) {
      log.debug(`Loading ${module}`);
      Cu.import(module);
    }
  }
  static unload(modulesArray) {
    for (const module of modulesArray) {
      log.debug(`Unloading ${module}`);
      Cu.unload(module);
    }
  }
}

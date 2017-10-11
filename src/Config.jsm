const { utils: Cu } = Components;
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "AddonManager",
  "resource://gre/modules/AddonManager.jsm");

/* eslint no-unused-vars: ["error", { "varsIgnorePattern": "(config|EXPORTED_SYMBOLS)" }]*/
const EXPORTED_SYMBOLS = ["config"];

const config = {
  study: {
    studyName: "nothing", // no spaces, for all the reasons
    studyVersion: 1,
    pioneerId: "d49379ee-db62-4b45-a501-9257208c1725",
    weightedVariations: [
      { name: "control", weight: 1 },
    ],
    /** **endings**
      * - keys indicate the 'endStudy' even that opens these.
      * - urls should be static (data) or external, because they have to
      *   survive uninstall
      * - If there is no key for an endStudy reason, no url will open.
      * - usually surveys, orientations, explanations
      */
    endings: {},
    telemetry: {
      send: true, // assumed false. Actually send pings?
      removeTestingFlag: true,  // Marks pings as testing, set true for actual release
      // TODO "onInvalid": "throw"  // invalid packet for schema?  throw||log
    },
  },
  async isEligible() {
    const addon = await AddonManager.getAddonByID("pioneer-opt-in@mozilla.org");
    return addon === null;
  },
  // addon-specific modules to load/unload during `startup`, `shutdown`
  modules: [
    // can use ${slug} here for example
  ],
  // sets the logging for BOTH the bootstrap file AND shield-study-utils
  log: {
    // Fatal: 70, Error: 60, Warn: 50, Info: 40, Config: 30, Debug: 20, Trace: 10, All: -1,
    bootstrap:  {
      level: "Warn",
    },
    studyUtils:  {
      level: "Warn",
    },
  },
};

/* eslint-env node */
var path = require("path");
var ConcatSource = require("webpack-sources").ConcatSource;
var LicenseWebpackPlugin = require("license-webpack-plugin");

module.exports = {
  context: __dirname,
  entry: {
    jose: "./node_modules/jose-jwe-jws/dist/jose.js",
  },
  output: {
    path: path.resolve(__dirname, "vendor/"),
    filename: "[name].js",
    library: "[name]",
    libraryTarget: "this",
  },
  plugins: [
    /**
     * Plugin that appends "this.EXPORTED_SYMBOLS = ["libname"]" to assets
     * output by webpack. This allows built assets to be imported using
     * Cu.import.
     */
    function ExportedSymbols() {
      this.plugin("emit", function(compilation, callback) {
        for (const libraryName in compilation.entrypoints) {
          const assetName = `${libraryName}.js`; // Matches output.filename
          compilation.assets[assetName] = new ConcatSource(
            "/* eslint-disable */", // Disable linting
            "const window = this;", // Shim for window
            "Components.utils.importGlobalProperties(['crypto']);", // Make crypto available
            "this.crypto = crypto;",
            compilation.assets[assetName],
            `this.EXPORTED_SYMBOLS = ["${libraryName}"];` // Matches output.library
          );
        }
        callback();
      });
    },
  ],
};

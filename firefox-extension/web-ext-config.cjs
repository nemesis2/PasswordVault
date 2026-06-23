// web-ext configuration, shared by `web-ext lint | build | sign`.
// Reference: https://extensionworkshop.com/documentation/develop/web-ext-command-reference/
//
// Named `.cjs` so it loads as CommonJS regardless of any future "type":"module".
module.exports = {
  // Files that are NOT part of the shipped add-on (mirrors build-xpi.sh's
  // whitelist as a denylist). Keeps dev/build files out of the package.
  ignoreFiles: [
    "package.json",
    "package-lock.json",
    "node_modules",
    "web-ext-config.cjs",
    "build-xpi.sh",
    "web-ext-artifacts",
    "selftest.js",
    "README.md",
    "*.xpi",
    "*.zip",
  ],
  build: {
    overwriteDest: true,
  },
  sign: {
    // Self-distribution by default (signed XPI you host yourself). Override with
    // `--channel=listed` (or `npm run sign:listed`) to submit to AMO.
    // API credentials come from env: WEB_EXT_API_KEY / WEB_EXT_API_SECRET.
    channel: "unlisted",
  },
};

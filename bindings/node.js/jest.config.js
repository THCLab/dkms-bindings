const path = require('path');
require('dotenv-flow').config({ silent: true });

// For a detailed explanation regarding each configuration property, visit:
// https://jestjs.io/docs/en/configuration.html
module.exports = {
  testTimeout: 15000,
  // Automatically clear mock calls and instances between every test
  clearMocks: true,

  // A map from regular expressions to module names or to arrays of module names that allow to stub out resources with a single module
  moduleNameMapper: {
    '^@src(.*)$': "<rootDir>/src//$1",
    '^@root(.*)$': "<rootDir>/$1",
    '^@test(.*)$': `${path.join(__dirname, 'test')}$1`,
  },

  roots: ["<rootDir>/src/", "<rootDir>/test/"],

  // The test environment that will be used for testing
  testEnvironment: "node",

  // The glob patterns Jest uses to detect test files
  testMatch: [
    `${path.join(__dirname, 'test')}/**/*.js`
  ],

  testPathIgnorePatterns: [
    "/node_modules/",
    `/test/helpers/`,
    `/test/support/`,
    `/test/__mocks__/`,
    `/test/base/`
  ],

  // Whether to use watchman for file crawling
  // watchman: true,
  setupFilesAfterEnv: [
    'givens/setup.js',
  ],
};

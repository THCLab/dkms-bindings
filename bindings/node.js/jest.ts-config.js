module.exports = {
  testTimeout: 15000,
  preset: 'ts-jest',
  globals: {
    'ts-jest': {
      tsconfig: "tsconfig.test.json"
    },
  },
  setupFilesAfterEnv: [],
  testEnvironment: 'node',
  roots: [
    "<rootDir>/src",
    "<rootDir>/test",
  ],
  moduleDirectories: [
    "node_modules",
    "src",
  ],
  moduleNameMapper: {
    '^@test(.*)$': "<rootDir>test/$1",
  },
  clearMocks: true,
};

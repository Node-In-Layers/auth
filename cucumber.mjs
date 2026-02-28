// cucumber.mjs
// Step definitions are in features/steps/steps.ts. Cucumber imports steps.mjs,
// which dynamically imports steps.ts so the same @cucumber/cucumber instance
// is used. test:features needs NODE_OPTIONS='--import tsx'.
export default {
  default: {
    paths: ['features/*.feature', 'features/**/*.feature'],
    import: ['features/steps/steps.mjs'],
    publishQuiet: true,
    format: ['progress'],
  },
}

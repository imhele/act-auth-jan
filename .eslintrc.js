module.exports = {
  parser: '@typescript-eslint/parser',
  plugins: [
    '@typescript-eslint',
    'prettier',
    'eslint-comments',
    'compat',
    'import',
    'markdown',
    'promise',
  ],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/eslint-recommended',
    'plugin:@typescript-eslint/recommended',
    'prettier',
    'prettier/@typescript-eslint',
  ],
  settings: {
    // support import modules from TypeScript files in JavaScript files
    'import/resolver': { node: { extensions: ['.js', '.jsx', '.ts', '.tsx', '.d.ts'] } },
    polyfills: ['Promise', 'URL', 'object-assign'],
  },
  rules: {
    '@typescript-eslint/camelcase': [2, { properties: 'never' }],
    '@typescript-eslint/no-unused-vars': [2, { args: 'none' }],
    '@typescript-eslint/no-namespace': 0,
    '@typescript-eslint/explicit-function-return-type': 0,
  },
};

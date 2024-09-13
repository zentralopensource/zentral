'use strict'

const path = require('path')
const autoprefixer = require('autoprefixer')
const miniCssExtractPlugin = require('mini-css-extract-plugin')

module.exports = {
  mode: 'development',
  entry: {
    main: './server/static_src/js/main.js',
    theme: './server/static_src/js/theme.js',
    user_portal: './server/static_src/js/user_portal.js',
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, './server/static/dist')
  },
  plugins: [
    new miniCssExtractPlugin()
  ],
  module: {
    rules: [
        {
            mimetype: 'image/svg+xml',
            scheme: 'data',
            type: 'asset/resource',
            generator: {
                filename: 'icons/[hash].svg'
            }
      },
      {
        test: /\.(scss)$/,
        use: [
          {
            // Extracts CSS for each JS file that includes CSS
            loader: miniCssExtractPlugin.loader
          },
          {
            // Interprets `@import` and `url()` like `import/require()` and will resolve them
            loader: 'css-loader'
          },
          {
            // Loader for webpack to process CSS with PostCSS
            loader: 'postcss-loader',
            options: {
              postcssOptions: {
                plugins: () => [
                  autoprefixer
                ]
              }
            }
          },
          {
            // Loads a SASS/SCSS file and compiles it to CSS
            loader: 'sass-loader'
          }
        ]
      }
    ]
  }
}

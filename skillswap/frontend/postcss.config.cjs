module.exports = {
  // Use array form so we can call the new adapter plugin and pass no options.
  plugins: [
    require('@tailwindcss/postcss'),
    require('autoprefixer'),
  ],
}

var path = require('path')

module.exports = {
  entry: {
    crypto: './dist/index.js'
  },
  output: {
    filename: './[name].bundle.js'
  }
}

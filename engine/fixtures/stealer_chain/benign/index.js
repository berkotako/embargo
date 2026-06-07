const chalk = require('chalk');

function format(text, color) {
  return chalk[color] ? chalk[color](text) : text;
}

module.exports = { format };

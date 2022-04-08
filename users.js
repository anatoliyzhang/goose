const fs = require('fs');
const path = require("path");
const crypto = require('crypto');
const algorithm = 'aes-192-cbc';
const secret = 'Einstein';
const key = crypto.scryptSync(secret, 'bridge', 24);
const iv = Buffer.alloc(16, 9);
let encrusers = fs.readFileSync(path.join(__dirname+'/conf', 'users.json'), 'utf-8');
const decipher = crypto.createDecipheriv(algorithm, key, iv);
let decrypted = decipher.update(encrusers, 'hex', 'utf8');
decrypted += decipher.final('utf8');

let records = JSON.parse(decrypted);

exports.findById = function(id, cb) {
  process.nextTick(function() {
    var idx = id - 1;
    if (records[idx]) {
      cb(null, records[idx]);
    } else {
      cb(new Error('User ' + id + ' does not exist'));
    }
  });
}

exports.findByUsername = function(username, cb) {
  process.nextTick(function() {
    for (var i = 0, len = records.length; i < len; i++) {
      var record = records[i];
      if (record.username === username) {
        return cb(null, record);
      }
    }
    return cb(null, null);
  });
}

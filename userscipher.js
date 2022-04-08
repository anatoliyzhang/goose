const crypto = require('crypto');
const fs = require('fs');
const path = require("path");
const algorithm = 'aes-192-cbc';
const secret = 'Einstein';
// 改为使用异步的 `crypto.scrypt()`。
const key = crypto.scryptSync(secret, 'bridge', 24);
// 使用 `crypto.randomBytes()` 生成随机的 iv 而不是此处显示的静态的 iv。
const iv = Buffer.alloc(16, 9); // 初始化向量。

const cipher = crypto.createCipheriv(algorithm, key, iv);
let users = fs.readFileSync(path.join(__dirname+'/conf', 'users-o.json'), 'utf-8');
let encrypted = cipher.update(users, 'utf8', 'hex');
encrypted += cipher.final('hex');
console.log(encrypted);
fs.writeFileSync(path.join(__dirname+'/conf', 'users.json'), encrypted);
let encrusers = fs.readFileSync(path.join(__dirname+'/conf', 'users.json'), 'utf-8');
const decipher = crypto.createDecipheriv(algorithm, key, iv);
let decrypted = decipher.update(encrusers, 'hex', 'utf8');
decrypted += decipher.final('utf8');
console.log(decrypted);

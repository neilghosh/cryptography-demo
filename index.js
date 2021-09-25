//symmetric encryption.
const crypto = require('crypto');
const algorithm = 'aes-256-ctr';
const password = 'keepitsecret';

function encryptText(text) {
  const cipher = crypto.createCipher(algorithm, password);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptText(text) {
  const decipher = crypto.createDecipher(algorithm, password);
  let decrypted = decipher.update(text, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

console.log("symmetric encryption --------------------")
text = "javascript";
console.log("Encrypting the text... " + text)
let encrypted = encryptText(text);
console.log("encrypted text - "+ encrypted);
console.log("Decrypted text  -"+decryptText(encrypted));

//Hash function 
//const crypto = require('crypto');
function getHash(text) {
  const algorithm = 'sha256';
  const hash = crypto.createHmac(algorithm, secret).update(text).digest('hex');
  return hash;
}

const secret = 'thisissecret';
console.log("Hashing --------------------")
console.log("Hashing the secret "+ secret);
console.log("Hash Value 1st call "+getHash('javascript'));
console.log("Hash Value 2nd call "+getHash('javascript'));

/**
 * generates random string of characters i.e salt
 * @function
 * @param {number} length - Length of the random string.
 */
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};

/**
 * hash password with sha512.
 * @function
 * @param {string} password - List of required fields.
 * @param {string} salt - Data to be validated.
 */
var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
};

function saltHashPassword(userpassword) {
    var salt = genRandomString(16); /** Gives us salt of length 16 */
    var passwordData = sha512(userpassword, salt);
    console.log('UserPassword = '+userpassword);
    console.log('Passwordhash = '+passwordData.passwordHash);
    console.log('nSalt = '+passwordData.salt);
}

console.log("Hashing With Salt --------------------")
saltHashPassword('javascript');
saltHashPassword('javascript');


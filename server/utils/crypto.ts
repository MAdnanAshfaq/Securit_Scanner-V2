import CryptoJS from 'crypto-js/lib/crypto-js.js';

export const md5 = (data: string) => CryptoJS.MD5(data).toString();
export const sha256 = (data: string) => CryptoJS.SHA256(data).toString();
export const sha512 = (data: string) => CryptoJS.SHA512(data).toString();
export const aes = {
  encrypt: (data: string, key: string) => CryptoJS.AES.encrypt(data, key).toString(),
  decrypt: (data: string, key: string) => {
    const bytes = CryptoJS.AES.decrypt(data, key);
    return bytes.toString(CryptoJS.enc.Utf8);
  }
};

export default CryptoJS; 
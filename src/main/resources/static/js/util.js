function bin2hex(data) {
    let hex = "";
    for (let byte in data) {
        hex += ('0' + (byte & 0xFF).toString(16)).slice(-2)
    }
    return CryptoJS.enc.Hex.parse(hex);
}

function binToB64(bin) {
    return btoa(String.fromCharCode.apply(null, bin));
}

function b64toBin(b64encoded) {
    return new Uint8Array(atob(b64encoded).split("").map(function (c) {
        return c.charCodeAt(0);
    }));
}

function byteArrayToWordArray(ba) {
    let wa = [],
        i;
    for (i = 0; i < ba.length; i++) {
        wa[(i / 4) | 0] |= ba[i] << (24 - 8 * i);
    }

    return CryptoJS.lib.WordArray.create(wa, ba.length);
}

function hex2bin(wordArray) {
    // Shortcuts
    let words = wordArray.words;
    let sigBytes = wordArray.sigBytes;

    // Convert
    let u8 = new Uint8Array(sigBytes);
    for (let i = 0; i < sigBytes; i++) {
        let byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        u8[i]=byte;
    }

    return u8;
}

function byteToHexString(uint8arr) {
    if (!uint8arr) {
        return '';
    }

    let hexStr = '';
    for (let i = 0; i < uint8arr.length; i++) {
        let hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }

    return hexStr.toUpperCase();
}

function hexStringToByte(str) {
    if (!str) {
        return new Uint8Array();
    }

    let a = [];
    for (let i = 0, len = str.length; i < len; i+=2) {
        a.push(parseInt(str.substr(i,2),16));
    }

    return new Uint8Array(a);
}

function string2byte(string) {
    return hex2bin(CryptoJS.enc.Hex.parse(CryptoJS.enc.Utf8.parse(string).toString(CryptoJS.enc.Hex)))
}

function byte2string(bytes) {
    return CryptoJS.enc.Hex.parse(byteToHexString(bytes)).toString(CryptoJS.enc.Utf8);
}
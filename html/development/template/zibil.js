function ascii_to_hexa(str) {
    var arr1 = [];
    for (var n = 0, l = str.length; n < l; n++) {
        var hex = Number(str.charCodeAt(n)).toString(16);
        arr1.push(hex);
    }
    return arr1.join('');
}
function ReverseString(str) {
    if (!str || str.length < 2 ||
    typeof str !== 'string') {
    return 'Not valid';
}
    const revArray = [];
    const length = str.length - 1;
    for (let i = length; i >= 0; i--) {
    revArray.push(str[i]);
}
    return revArray.join('');
}
function g0002(length) {
    var result = '';
    var characters = 'ABCDEF123456789';
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
}
    return result;
}
function aesEncrypt(data, key, iv) {
    let cipher = CryptoJS.AES.encrypt(data, CryptoJS.enc.Utf8.parse(key), {
    iv: CryptoJS.enc.Utf8.parse(iv),
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC
});
    return cipher.toString();
}

    function base64ToHex(str) {
    const raw = atob(str);
    let result = '';
    for (let i = 0; i < raw.length; i++) {
    const hex = raw.charCodeAt(i).toString(16);
    if (hex == '0') {
    return '-1'
}
    result += (hex.length === 2 ? hex : '0' + hex);
}
    return result.toUpperCase();
}


    function g00001() {

    Fingerprint2.get(function (components) {
            murmur = Fingerprint2.x64hash128(components.map(function (pair) {
                return pair.value
            }).join(), 31)

            var counter = 0
            var payload = '-1';
            while (payload === '-1') {
                counter++
                let key = g0002(32);
                let iv = g0002(16);
                payload = base64ToHex(aesEncrypt(murmur, key, iv));
                document.cookie = 'token=' + key + iv + payload + Date.now().toString() + '; expires=Thu, 31-Dec-25 23:55:55 GMT; path=/';
            }
        }
    )

}
    g00001()



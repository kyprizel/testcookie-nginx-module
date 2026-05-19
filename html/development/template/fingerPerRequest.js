var murmur;
var fingerprintReport = function () {
    var d1 = new Date()
    Fingerprint2.get(function (components) {
        murmur = Fingerprint2.x64hash128(components.map(function (pair) {
            return pair.value
        }).join(), 31)
        var d2 = new Date()
        var time = d2 - d1
    })
}
var cancelId
var cancelFunction
// see usage note in the README
if (window.requestIdleCallback) {
    cancelId = requestIdleCallback(fingerprintReport)
    cancelFunction = cancelIdleCallback
} else {
    cancelId = setTimeout(fingerprintReport, 500)
    cancelFunction = clearTimeout
}
document.cookie = 'IronKey3=' + murmur + '; expires=Thu, 1-Dec-24 00:00:00 GMT; path=/';

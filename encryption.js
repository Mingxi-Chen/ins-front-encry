//   "key_id": "78",
// "public_key": "f8c86a4d0d92f87c01b9fb26aca4d60acf67f6fb517c28974d8e2b43ba60f74c",
// "version": "10"
// uuid "c286d69b-c9c6-4c74-b31b-79738df91fb3"
// e "eb201953-690f-4d90-a220-2724eeec77d3"
// g "1757900872"
// j "#PWD_INSTAGRAM_BROWSER"
// "#PWD_INSTAGRAM_BROWSER:10:1757900872:AU5QANYERR3HgZZCCYVKy9vPDhzSsvdqyRgXvG6WCyTht6kdqWGpCAHG1v+Wca1HIsxajHQ7uhuxwVI7v8KWUhRC59gLuuSliyjHq5GW1UEvO61NCRNzbl0f7c46KgbGJYgHHHE4CjpcwXRT"

__d("FBBrowserPasswordEncryption", ["EnvelopeEncryption", "tweetnacl-util"], (function(a, b, c, d, e, f, g) {
    "use strict";
    var h = "#PWD_BROWSER"
      , i = 5;
    function a(a, b, e, f, g, j) {
        g === void 0 && (g = i);
        j === void 0 && (j = h);
        e = c("tweetnacl-util").decodeUTF8(e);
        var k = c("tweetnacl-util").decodeUTF8(f);
        return d("EnvelopeEncryption").encrypt(a, b, e, k).then(function(a) {
            return [j, g, f, c("tweetnacl-util").encodeBase64(a)].join(":")
        })
    }
    g.encryptPassword = a
}),98);

__d("PolarisEncryptionUtils", ["FBBrowserPasswordEncryption", "FBLogger", "PolarisEncryptionKeysStore", "PolarisFBBrowserPasswordFormatter"], (function(a, b, c, d, e, f, g) {
    "use strict";
    function a(a, b) {
        var e = d("PolarisEncryptionKeysStore").getKeyId()
          , f = d("PolarisEncryptionKeysStore").getPublicKey()
          , g = d("PolarisEncryptionKeysStore").getVersion();
        if (e == null || f == null)
            throw c("FBLogger")("instagram_web").mustfixThrow("Encryption Failure: failed to retrieve keyId and/or publicKey");
        return d("FBBrowserPasswordEncryption").encryptPassword(+e, f, a, b, parseInt(g, 10), d("PolarisFBBrowserPasswordFormatter").PWD_ENC_TAG_BROWSER)
    }
    g.encryptAndFormat = a
}
), 98);


__d("PolarisEncryptionHelper", ["PolarisEncryptionUtils", "PolarisFBBrowserPasswordFormatter", "PolarisPasswordEncryptionLogger", "asyncToGeneratorRuntime", "uuidv4"], (function(a, b, c, d, e, f, g) {
    "use strict";
    function h(a, b) {
        return i.apply(this, arguments)
    }
    function i() {
        i = b("asyncToGeneratorRuntime").asyncToGenerator(function*(a, b) {
            if (a === "")
                return void 0;
            var e = c("uuidv4")();
            b = b.requestUUID;
            d("PolarisPasswordEncryptionLogger").logEncryptionAttempt(e, b);
            var f;
            try {
                var g = j();
                f = (yield d("PolarisEncryptionUtils").encryptAndFormat(a, g));
                d("PolarisPasswordEncryptionLogger").logEncryptionSuccess(e, b)
            } catch (a) {
                d("PolarisPasswordEncryptionLogger").logEncryptionFailure(a)
            }
            f == null && (f = k(a),
            d("PolarisPasswordEncryptionLogger").logEncryptionFallback(e, b));
            return f
        });
        return i.apply(this, arguments)
    }
    function j() {
        return Math.floor(Date.now() / 1e3).toString()
    }
    function k(a) {
        var b = j();
        return d("PolarisFBBrowserPasswordFormatter").formatPassword(a, b, d("PolarisFBBrowserPasswordFormatter").formatType.PLAINTEXT)
    }
    function a(a, b, c, d) {
        return l.apply(this, arguments)
    }
    function l() {
        l = b("asyncToGeneratorRuntime").asyncToGenerator(function*(a, b, c, d) {
            d === void 0 && (d = "enc_");
            var e = {};
            b = (yield h(b, c));
            if (b != null) {
                c = "" + d + a;
                e = (d = {},
                d[c] = b,
                d)
            }
            return Object.freeze(babelHelpers["extends"]({}, e))
        });
        return l.apply(this, arguments)
    }
    g.encrypt = h;
    g.getTimestamp = j;
    g.formatPlaintextPassword = k;
    g.getEncryptedParam = a
}
), 98);
__d("PolarisAPILogin", ["PolarisEncryptionHelper", "PolarisInstapi", "PolarisPasswordEncryptionLogger", "asyncToGeneratorRuntime", "uuidv4"], (function(a, b, c, d, e, f, g) {
    "use strict";
    function a(a, b, c, d, e, f, g, i, j) {
        return h.apply(this, arguments)
    }
    function h() {
        h = b("asyncToGeneratorRuntime").asyncToGenerator(function*(a, b, e, f, g, h, i, j, k) {
            g === void 0 && (g = null);
            h === void 0 && (h = null);
            j === void 0 && (j = -1);
            k === void 0 && (k = !1);
            var l = {
                requestUUID: c("uuidv4")()
            };
            b = babelHelpers["extends"]({}, yield d("PolarisEncryptionHelper").getEncryptedParam("password", b, l), {
                caaF2DebugGroup: j,
                isPrivacyPortalReq: k,
                loginAttemptSubmissionCount: i,
                optIntoOneTap: f,
                queryParams: e,
                stopDeletionNonce: g,
                trustedDeviceRecords: h,
                username: a
            });
            d("PolarisPasswordEncryptionLogger").logEncryptedPayloadSend("/api/v1/web/accounts/login/ajax/", b, l);
            return d("PolarisInstapi").apiPost("/api/v1/web/accounts/login/ajax/", {
                body: b
            }).then(function(a) {
                return a.data
            })
        });
        return h.apply(this, arguments)
    }
    g.login = a
}
), 98);





(async function() {
    try {
      const username = '6315092184';
      const password = 'Chenmx.1217';
  
      // Get key metadata from the site's module/keys store.
      // These names mirror the modules you posted earlier.
      const keyId = d('PolarisEncryptionKeysStore').getKeyId();
      const publicKey = d('PolarisEncryptionKeysStore').getPublicKey();
      const version = parseInt(d('PolarisEncryptionKeysStore').getVersion(), 10);
      const tag = d('PolarisFBBrowserPasswordFormatter').PWD_ENC_TAG_BROWSER;
  
      // Use a timestamp string similar to what the site uses.
      // The examples you posted look like seconds (10-digit). Use that:
      const ts = String(Math.floor(Date.now() / 1000));
  
      // Use the site's encryption function — this returns a Promise<string>.
      const enc = await d('FBBrowserPasswordEncryption').encryptPassword(
        +keyId,
        publicKey,
        password,
        ts,
        version,
        tag
      );
  
      console.log('encrypted password string:', enc);
  
      // Read csrftoken from cookie (browser sends cookies automatically with credentials:'include')
      const getCookie = (name) => {
        const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
        return m ? decodeURIComponent(m[1]) : null;
      };
      const csrftoken = getCookie('csrftoken');
  
      // Submit login POST using fetch; browser will include cookies if credentials:'include'.
      const resp = await fetch('/accounts/login/ajax/', {
        method: 'POST',
        credentials: 'include',               // send cookies from this origin
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-CSRFToken': csrftoken,
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: new URLSearchParams({
          username: username,
          enc_password: enc,
          // include other fields the client usually sends, e.g. queryParams or device id if present:
          // uuid: '<uuid-if-needed>',
          // opt_into_one_tap: 'false'
        })
      });
  
      const json = await resp.json();
      console.log('login response:', json);
    } catch (err) {
      console.error(err);
    }
  })();
  
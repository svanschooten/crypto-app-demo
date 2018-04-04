const securityStates = {
    IDLE: "Idle",
    START: "Started session negotiation",
    PUBKEY: "Public key retrieved, creating shared key",
    FINALIZE: "Finalizing session",
    SETUP: "Session setup done",
    TEST: "Testing session status",
    VALID: "Valid session test result",
    EXPIRED: "Session expired",
    REFRESHING: "Refreshing session",
    DELETE: "Deleting session",
    ERROR: "Error occurred!"
};
const ss = securityStates;

class SecureSession {
    constructor (config={base_url: null, state_container: null}) {
        if (config.base_url) {
            this.base_url = config.base_url;
        } else {
            this.base_url = "http://localhost:9090/session/client/"
        }
        if (config.state_container) {
            this.stateContainer = document.getElementById(config.state_container);
        } else {
            this.stateContainer = document.getElementById("security_state");
        }
        this.__sessionId = null;
        this.__publicKey = null;
        this.__sessionKey = null;
        this.__refreshToken = null;
        this.__sessionPassphraseLength = 64;
        this.__sessionIVLength = 16;
        this.__sessionKeyIterations = 4096;
        this.__sessionKeyHasher = CryptoJS.algo.SHA512;
        this.__sessionKeySize = 256/32;
        this.__setState("IDLE");
    }

    destroy () {
        this.__setState("IDLE");
        SecureSession.__instance = null;
        delete this.__sessionId;
        delete this.__publicKey;
        delete this.__sessionKey;
        delete this.__refreshToken;
        delete this.base_url;
        delete this.stateContainer;
    }

    async startNegotiation () {
        this.__setState(ss.START);
        try {
            let data = await this.__doRequest("start", "GET");
            this.__publicKey = data.publicKey;
            this.__sessionId = data.sessionId;
            this.__setState(ss.PUBKEY);
            this.__createSharedKey().then().catch(console.error);
        } catch (e) {
            console.error("Start negotiation error!");
            console.error(e);
            this.__setState(ss.ERROR);
        }
    }

    async testSession () {
        this.__setState(ss.TEST);
        let testcipher = this.encrypt("client");
        try {
            let data = await this.__doRequest("test", "POST", {
                sessionId: this.__sessionId,
                testText: testcipher
            });
            let response = this.decrypt(data.testResponse);
            if (response === "server") {
                this.__setState(ss.VALID);
            } else {
                console.error(response);
                this.__setState(ss.ERROR);
            }
        } catch (e) {
            console.error("Test session error!");
            console.error(e);
            this.__setState(ss.ERROR);
        }
    }

    decrypt (cipher) {
        cipher = cipher.split(":");
        let iv = CryptoJS.enc.Base64.parse(cipher[0]);
        let ciphertext = CryptoJS.enc.Base64.parse(cipher[1]);
        return CryptoJS.AES.decrypt({
                ciphertext: ciphertext
            }, CryptoJS.enc.Base64.parse(this.__sessionKey),
            {
                iv: iv
            }).toString(CryptoJS.enc.Utf8);
    }

    encrypt (plaintext) {
        let iv = this.__generateRandomIV();
        let ciphertext = CryptoJS.AES.encrypt(
            plaintext,
            CryptoJS.enc.Base64.parse(this.__sessionKey),
            {
                iv: CryptoJS.enc.Base64.parse(iv)
            }).toString();
        return iv + ":" + ciphertext;
    }

    async __createSharedKey() {
        const passphrase = this.__generateRandomPassphrase();
        this.__sessionKey = CryptoJS.PBKDF2(passphrase, "DOCULAYER STATIC SALT",
            {
                keySize: this.__sessionKeySize,
                hasher: this.__sessionKeyHasher,
                iterations: this.__sessionKeyIterations
            }).toString(CryptoJS.enc.Base64);
        try {
            let rsaCipher = new JSEncrypt();
            rsaCipher.setPublicKey(this.__publicKey);
            let encryptedSessionKey = rsaCipher.encrypt(passphrase);
            if (!encryptedSessionKey) return console.error("WRONG KEY!");
            this.__setState(ss.FINALIZE);
            let data = await this.__doRequest("finalize", "POST", {
                sessionId: this.__sessionId,
                sessionKey: encryptedSessionKey
            });
            this.__extractRefreshToken(data.refreshToken);
        } catch (e) {
            console.error("Shared key error!");
            console.error(e);
            this.__setState(ss.ERROR);
        }
    }

    __extractRefreshToken (data) {
        this.__refreshToken = this.decrypt(data);
        if (this.__refreshToken !== "") {
            this.__setState(ss.SETUP);
        } else {
            console.error("Refresh token: " + this.__refreshToken);
            this.__setState(ss.ERROR);
        }
    }

    __doRequest (endpoint, method, body) {
        return new Promise((resolve, reject) => {
            let config = {
                method: method,
                headers: {}
            };
            if (method.toUpperCase() !== "GET") {
                config.headers = {"Content-Type": "application/json"};
            }
            if (body) {
                config.body = JSON.stringify(body);
            }
            fetch(this.base_url + endpoint, config)
                .then((response) => response.json())
                .then(resolve)
                .catch(reject);
        });
    }


    __setState (state) {
        if (securityStates[state.toUpperCase()]) {
            this.stateContainer.innerText = securityStates[state];
        } else {
            this.stateContainer.innerText = state;
        }
    }

    static __generateRandom (length) {
        let passphrase = "";
        while (passphrase.length < length) {
            passphrase += Math.random().toString(36).substring(2);
        }
        return passphrase.substr(0, length);
    }

    __generateRandomIV () {
        return CryptoJS.enc.Utf8.parse(SecureSession.__generateRandom(this.__sessionIVLength))
            .toString(CryptoJS.enc.Base64);
    }

    __generateRandomPassphrase () {
        return SecureSession.__generateRandom(this.__sessionPassphraseLength);
    }

    static instance (base_url) {
        if (SecureSession.__instance === null) {
            SecureSession.__instance = new SecureSession(base_url);
        }
        return SecureSession.__instance;
    };
}

SecureSession.__instance = null;

const securityStates = {
    IDLE: "Idle",
    START: "Started session negotiation",
    PUBKEY: "Public key retrieved, creating shared key",
    FINALIZE: "Finalizing session",
    VALID: "Session valid",
    TEST: "Testing session status",
    EXPIRED: "Session expired",
    REFRESHING: "Refreshing session",
    DELETE: "Deleting session",
    ERROR: "Error occurred!"
};
const ss = securityStates;

class SecureSession {
    constructor(config={base_url: null, state_container: null}) {
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
        this.__sessionKeyIterations = 4096;
        this.__sessionKeyHasher = CryptoJS.algo.SHA512;
        this.__sessionKeySize = 256/32;
        this.__setState("IDLE");
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
            console.error(e);
            this.__setState(ss.ERROR);
        }
    }

    decrypt(iv, ciphertext) {
        iv = CryptoJS.enc.Base64.parse(iv);
        ciphertext = CryptoJS.enc.Base64.parse(ciphertext);
        return CryptoJS.AES.decrypt({
                ciphertext: ciphertext
            }, CryptoJS.enc.Hex.parse(this.__sessionKey),
            {
                iv: iv
            }).toString(CryptoJS.enc.Utf8);
    }

    async __createSharedKey() {
        const passphrase = this.__generateRandomPassphrase();
        this.__sessionKey = CryptoJS.PBKDF2(passphrase, "STATIC SALT",
            {
                keySize: this.__sessionKeySize,
                hasher: this.__sessionKeyHasher,
                iterations: this.__sessionKeyIterations
            }).toString(CryptoJS.enc.Hex);
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
            console.error(e);
            this.__setState(ss.ERROR);
        }
    }

    __extractRefreshToken(data) {
        data = data.split(":");
        this.__refreshToken = this.decrypt(data[0], data[1]);
        if (this.__refreshToken !== "") {
            this.__setState(ss.VALID);
        } else {
            this.__setState(ss.ERROR);
        }
    }

    __doRequest(endpoint, method, body) {
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


    __setState(state) {
        if (securityStates[state.toUpperCase()]) {
            this.stateContainer.innerText = securityStates[state];
        } else {
            this.stateContainer.innerText = state;
        }
    }

    __generateRandomPassphrase() {
        let passphrase = "";
        while (passphrase.length < this.__sessionPassphraseLength) {
            passphrase += Math.random().toString(36).substring(2);
        }
        return passphrase.substr(0, this.__sessionPassphraseLength);
    }
}

SecureSession.__instance = null;

SecureSession.instance = () => {
    if (SecureSession.__instance === null) {
        SecureSession.__instance = new SecureSession();
    }
    return SecureSession.__instance;
};

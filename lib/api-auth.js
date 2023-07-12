"use strict";
const crypto = require('node:crypto');

class ApiAuth {
    constructor(config) {
        this.config = config;
    }

    getHeaders() {
        const gmtDate = new Date().toISOString().replace(/T/, " ").replace(/\..+/, "");
        const string = this.config.sellerId.length + this.config.sellerId + gmtDate.length + gmtDate;
        const hash = crypto.createHmac('sha256', this.config.secretKey)
               .update(string)
               .digest('hex');
        const headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Avangate-Authentication":
                "code='" + this.config.sellerId + "' date='" + gmtDate + "' hash='" + hash + "'" + "algo='sha256'",
        };
        return headers;
    }
}

module.exports = ApiAuth;

"use strict";
const crypto = require('node:crypto');
const dateFormat = require("date-format");
const util = require("util");
const TwocheckoutError = require("./error");

class IpnSignature {
    constructor(config) {
        this.config = config;
    }

    //Check if Ipn Request from 2Checkout is valid
    isValid(params) {
        try {
            let result = "";
            Object.keys(params).forEach((key) => {
                let val = params[key];
                if (!["HASH", "SIGNATURE_SHA2_256", "SIGNATURE_SHA3_256"].includes(key)) {
                    if (typeof val === "object") {
                        result += this.expand(val);
                    } else {
                        result += this.getStrAndLength(val);
                    }
                }
            });

            const algo = this.getAlgo(params);
            const receivedHash = this.getCompareHash(algo, params);
            const calcHash = this.hmac(result.toString(), this.getAlgo(params));
            return receivedHash === calcHash;
        } catch (e) {
            throw new TwocheckoutError(e.code, e.message);
        }
    }

    calculateIpnResponse(ipnParams) {
        try {
            let resultResponse = "";
            let ipnParamsResponse = {};
            let algorithm = this.getAlgo(ipnParams);

            ipnParamsResponse.IPN_PID = [ipnParams.IPN_PID[0]];
            ipnParamsResponse.IPN_PNAME = [ipnParams.IPN_PNAME[0]];
            ipnParamsResponse.IPN_DATE = ipnParams.IPN_DATE;
            ipnParamsResponse.DATE = dateFormat.asString("yyyyMMddhhmmss", new Date());

            Object.keys(ipnParamsResponse).forEach((key) => {
                let val = ipnParamsResponse[key];
                if (typeof val === "object") {
                    resultResponse += this.expand(val);
                } else {
                    resultResponse += this.getStrAndLength(val);
                }
            });

            let signature = this.hmac(resultResponse, algorithm);
            return this.formatResponse(algorithm, ipnParamsResponse.DATE, signature);
        } catch (e) {
            throw new TwocheckoutError(
                "ipn_response",
                util.format("Error calculating ipn response. Details: %s", e.message)
            );
        }
    }

    expand(params) {
        let retval = "";
        Object.keys(params).forEach((key) => {
            let element = params[key];
            if (typeof element === "object") {
                retval += this.expand(element);
            } else {
                retval += this.getStrAndLength(element);
            }
        });
        return retval;
    }

    getStrAndLength(str) {
        let val = str.toString().trim();
        return val.length.toString() + val.toString();
    }

    hmac(string, algo) {
        const hash = crypto.createHmac(algo, this.config.secretKey)
               .update(string)
               .digest('hex');
        return hash;
    }

    getAlgo(params) {
        let algo = 'md5';
        if (params["SIGNATURE_SHA3_256"]) {
            algo = "sha3-256";
        } else if (params["SIGNATURE_SHA2_256"]) {
            algo = "sha256";
        }

        return algo;
    }

    getCompareHash(algo, params) {
        let value = params.HASH
        switch (algo) {
            case "sha3-256":
                value = params.SIGNATURE_SHA3_256;
                break;
            case "sha256":
                value = params.SIGNATURE_SHA2_256;
                break;
        
            default:
                break;
        }

        return value;
    }

    formatResponse(algorithm, date, signature) {
        if (algorithm == "md5") {
            return util.format(
                "<EPAYMENT>%s|%s</EPAYMENT>",
                date,
                signature
            );
        } else {
            return util.format(
                '<sig algo="%s" date="%s">%s</sig>',
                algorithm,
                date,
                signature
            );
        }
    }
}

module.exports = IpnSignature;

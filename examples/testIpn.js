const Twocheckout = require("../twocheckout");
const IpnSignature = require("../lib/ipn");
const config = {
    sellerId: "00000000000",
    secretKey: "#test_Secret-keY",
};

const ipn = new IpnSignature(config);
const toExpand = { prop1: "value1", prop2: [{ value2: "value2" }], prop3: { value3: "value3" }, prop4: ["value4"] };
const params = {
    GIFT_ORDER: "0",
    SALEDATE: "2021-04-16 14:34:07",
    PAYMENTDATE: "0000-00-00 00:00:00",
    REFNO: "149279389",
    REFNOEXT: "CustOrd101",
    ORIGINAL_REFNOEXT: [""],
    SHOPPER_REFERENCE_NUMBER: "",
    ORDERNO: "0",
    ORDERSTATUS: "PENDING",
    PAYMETHOD: "Visa/MasterCard",
    PAYMETHOD_CODE: "CCVISAMC",
    FIRSTNAME: "John",
    LASTNAME: "Doe",
    COMPANY: "",
    REGISTRATIONNUMBER: "",
    FISCALCODE: "",
    TAX_OFFICE: "",
    CBANKNAME: "",
    CBANKACCOUNT: "",
    ADDRESS1: "Street 1",
    ADDRESS2: "",
    CITY: "Cleveland",
    STATE: "Ohio",
    ZIPCODE: "20034",
    COUNTRY: "United States of America",
    COUNTRY_CODE: "us",
    PHONE: "",
    FAX: "",
    CUSTOMEREMAIL: "testcustomer@2Checkout.com",
    FIRSTNAME_D: "John",
    LASTNAME_D: "Doe",
    COMPANY_D: "",
    ADDRESS1_D: "Street 1",
    ADDRESS2_D: "",
    CITY_D: "Cleveland",
    STATE_D: "Ohio",
    ZIPCODE_D: "20034",
    COUNTRY_D: "United States of America",
    COUNTRY_D_CODE: "us",
    PHONE_D: "",
    EMAIL_D: "testcustomer@2Checkout.com",
    IPADDRESS: "91.220.121.21",
    IPCOUNTRY: "Romania",
    COMPLETE_DATE: "0000-00-00 00:00:00",
    TIMEZONE_OFFSET: "GMT+03:00",
    CURRENCY: "USD",
    LANGUAGE: "en",
    ORDERFLOW: "REGULAR",
    IPN_PID: ["35269746"],
    IPN_PNAME: ["Colored Pencil"],
    IPN_PCODE: [""],
    IPN_EXTERNAL_REFERENCE: [""],
    IPN_INFO: [""],
    IPN_QTY: ["1"],
    IPN_PRICE: ["2.00"],
    IPN_VAT: ["0.00"],
    IPN_VAT_RATE: ["0.00"],
    IPN_VER: ["1"],
    IPN_DISCOUNT: ["0.00"],
    IPN_PROMOTION_CATEGORY: [""],
    IPN_PROMONAME: [""],
    IPN_PROMOCODE: [""],
    IPN_ORDER_COSTS: ["0"],
    IPN_SKU: [""],
    IPN_PARTNER_CODE: "",
    IPN_PGROUP: ["0"],
    IPN_PGROUP_NAME: [""],
    MESSAGE_ID: "250847481432",
    MESSAGE_TYPE: "PENDING",
    IPN_LICENSE_PROD: ["35269746"],
    IPN_LICENSE_TYPE: ["REGULAR"],
    IPN_LICENSE_REF: [""],
    IPN_LICENSE_EXP: [""],
    IPN_LICENSE_START: [""],
    IPN_LICENSE_LIFETIME: ["NO"],
    IPN_LICENSE_ADDITIONAL_INFO: [""],
    IPN_DELIVEREDCODES: [""],
    IPN_DOWNLOAD_LINK: "",
    IPN_TOTAL: ["2.00"],
    IPN_TOTALGENERAL: "2.00",
    IPN_SHIPPING: "0.00",
    IPN_SHIPPING_TAX: "0.00",
    AVANGATE_CUSTOMER_REFERENCE: "",
    EXTERNAL_CUSTOMER_REFERENCE: "",
    IPN_PARTNER_MARGIN_PERCENT: "0.00",
    IPN_PARTNER_MARGIN: "0.00",
    IPN_EXTRA_MARGIN: "0.00",
    IPN_EXTRA_DISCOUNT: "0.00",
    IPN_COUPON_DISCOUNT: "0.00",
    IPN_LINK_SOURCE: "tcolib.local",
    IPN_ORIGINAL_LINK_SOURCE: [""],
    IPN_COMMISSION: "0.5985",
    REFUND_TYPE: "",
    CHARGEBACK_RESOLUTION: "NONE",
    CHARGEBACK_REASON_CODE: "",
    TEST_ORDER: "1",
    IPN_ORDER_ORIGIN: "API",
    FRAUD_STATUS: "PENDING",
    CARD_TYPE: "Visa",
    CARD_LAST_DIGITS: "1111",
    CARD_EXPIRATION_DATE: "",
    GATEWAY_RESPONSE: "",
    IPN_DATE: "20210416143408",
    FX_RATE: "1",
    FX_MARKUP: "0",
    PAYABLE_AMOUNT: "1.40",
    PAYOUT_CURRENCY: "USD",
    VENDOR_CODE: "250111206876",
    PROPOSAL_ID: "",
    HASH: "294570c4158e879029d622c0165c409d",
};

console.log("Ipn class manual usage example.");
let expanded = ipn.expand(toExpand);
console.log(expanded);

let hash = ipn.hmac(expanded, 'md5');
console.log(hash);

console.log("Is ipn request signature valid:", ipn.isValid(params));

console.log("\r\nIpn validation example using Twocheckout interface.");
const tco = new Twocheckout(config);
console.log("Is ipn call hash valid: ", tco.validateIpnResponse(params));

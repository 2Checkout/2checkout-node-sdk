//Tco general config test params
config = {
    sellerId: "",
    secretKey: "P",
    secretWord: "",
    jwtExpireTime: 20, //minutes
};

//these only work without valid (from CPanel) values
//If you need to run integration tests you need a 2Checkout seller account
ipnConfig = {
    sellerId: "00000000000",
    secretKey: "#test_Secret-keY",
};

buyLinkAuthToken = "justATestToken#@#^@";

//###Payment orders parameters
paymentOrderSuccessPayload = {
    Country: "us",
    Currency: "USD",
    CustomerIP: "91.220.121.21",
    ExternalReference: "REST_API_AVANGTE",
    Language: "en",
    Source: "testAPI.com",
    BillingDetails: {
        Address1: "Test Address",
        City: "LA",
        State: "California",
        CountryCode: "US",
        Email: "testcustomer@2Checkout.com",
        FirstName: "Customer",
        LastName: "2Checkout",
        Zip: "12345",
    },
    Items: [
        {
            Name: "Dynamic product",
            Description: "Test description",
            Quantity: 1,
            IsDynamic: true,
            Tangible: false,
            PurchaseType: "PRODUCT",
            CrossSell: {
                CampaignCode: "CAMPAIGN_CODE",
                ParentCode: "MASTER_PRODUCT_CODE",
            },
            Price: {
                Amount: 100,
                Type: "CUSTOM",
            },
            PriceOptions: [
                {
                    Name: "OPT1",
                    Options: [
                        {
                            Name: "Name LR",
                            Value: "Value LR",
                            Surcharge: 7,
                        },
                    ],
                },
            ],
            RecurringOptions: {
                CycleLength: 2,
                CycleUnit: "DAY",
                CycleAmount: 12.2,
                ContractLength: 3,
                ContractUnit: "DAY",
            },
        },
    ],
    PaymentDetails: {
        Type: "TEST",
        Currency: "USD",
        CustomerIP: "91.220.121.21",
        PaymentMethod: {
            CardNumber: "4111111111111111",
            CardType: "VISA",
            Vendor3DSReturnURL: "www.success.com",
            Vendor3DSCancelURL: "www.fail.com",
            ExpirationYear: "2022",
            ExpirationMonth: "12",
            CCID: "123",
            HolderName: "John Doe",
            RecurringEnabled: true,
            HolderNameTime: 1,
            CardNumberTime: 1,
        },
    },
};

paymentOrderErrorPayload = {
    Country: "us",
    Currency: "USD",
    CustomerIP: "91.220.121.21",
    ExternalReference: "REST_API_AVANGTE",
    Language: "en",
    Source: "testAPI.com",
    BillingDetails: {
        Address1: "Test Address",
        City: "LA",
        State: "California",
        CountryCode: "US",
        Email: "testcustomer@2Checkout.com",
        FirstName: "Customer",
        LastName: "2Checkout",
        Zip: "12345",
    },
    PaymentDetails: {
        Type: "TEST",
        Currency: "USD",
        CustomerIP: "91.220.121.21",
        PaymentMethod: {
            CardNumber: "4111111111111111",
            CardType: "VISA",
            Vendor3DSReturnURL: "www.success.com",
            Vendor3DSCancelURL: "www.fail.com",
            ExpirationYear: "2022",
            ExpirationMonth: "12",
            CCID: "123",
            HolderName: "John Doe",
            RecurringEnabled: true,
            HolderNameTime: 1,
            CardNumberTime: 1,
        },
    },
};

//###ApiCore tests params
getApiArgs = {
    method: "GET",
    path: "/orders/",
};
postApiArgs = {
    method: "POST",
    payload: paymentOrderSuccessPayload,
    path: "/orders",
};

//###IPN tests params
toExpand = { prop1: "value1", prop2: [{ value2: "value2" }], prop3: { value3: "value3" }, prop4: ["value4"] };
expandedExpected = "6value16value26value36value4";
ipnExpectedHash = "f0e3cdda89e0886b412f90dcfac51a0f";

ipnCallbackReq = {
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

buyLinkParams = {
    address: "Test Address",
    city: "LA",
    country: "US",
    name: "Customer 2Checkout",
    phone: "0770678987",
    zip: "12345",
    email: "testcustomer@2Checkout.com",
    "company-name": "Verifone",
    state: "California",
    "ship-name": "Customer 2Checkout",
    "ship-address": "Test Address",
    "ship-city": "LA",
    "ship-country": "US",
    "ship-email": "testcustomer@2Checkout.com",
    "ship-state": "California",
    prod: "Buy link Dynamic product test product from API",
    price: 1,
    qty: 1,
    type: "PRODUCT",
    tangible: 0,
    "return-url": "http://tcoLib.example/paymentCallback.php",
    "return-type": "redirect",
    expiration: new Date().getTime() + 3600 * 5,
    "order-ext-ref": "CustOrd100",
    "item-ext-ref": "20210423094943",
    "customer-ext-ref": "testcustomer@2Checkout.com",
    currency: "usd",
    language: "en",
    test: 1,
    merchant: config.sellerId,
    dynamic: 1,
};

paymentWithSubscriptionParams = {
    Country: "us",
    Currency: "USD",
    CustomerIP: "91.220.121.21",
    ExternalReference: "REST_API_AVANGTE",
    Language: "en",
    Source: "testAPI.com",
    BillingDetails: {
        Address1: "Test Address",
        City: "LA",
        State: "California",
        CountryCode: "US",
        Email: "testcustomer@2Checkout.com",
        FirstName: "Customer",
        LastName: "2Checkout",
        Zip: "12345",
    },
    Items: [
        {
            Name: "Dynamic product",
            Description: "Test description",
            Quantity: 1,
            IsDynamic: true,
            Tangible: false,
            PurchaseType: "PRODUCT",
            CrossSell: {
                CampaignCode: "CAMPAIGN_CODE",
                ParentCode: "MASTER_PRODUCT_CODE",
            },
            Price: {
                Amount: 2,
                Type: "CUSTOM",
            },
            RecurringOptions: {
                CycleLength: 1,
                CycleUnit: "MONTH",
                CycleAmount: 3,
                ContractLength: 3,
                ContractUnit: "Year",
            },
        },
    ],
    PaymentDetails: {
        Type: "TEST",
        Currency: "USD",
        CustomerIP: "91.220.121.21",
        PaymentMethod: {
            CardNumber: "4111111111111111",
            CardType: "VISA",
            Vendor3DSReturnURL: "www.success.com",
            Vendor3DSCancelURL: "www.fail.com",
            ExpirationYear: "2022",
            ExpirationMonth: "12",
            CCID: "123",
            HolderName: "John Doe",
            RecurringEnabled: true,
            HolderNameTime: 1,
            CardNumberTime: 1,
        },
    },
};

paymentItems = [
    {
        ProductDetails: {
            Name: "Dynamic product",
            ShortDescription: "Test description",
            Tangible: false,
            IsDynamic: true,
            ExtraInfo: null,
            RenewalStatus: false,
            Subscriptions: [
                {
                    SubscriptionReference: "U3T96D72D3",
                    PurchaseDate: "2021-05-10 16:57:30",
                    SubscriptionStartDate: "2021-05-10 16:57:30",
                    ExpirationDate: "2021-06-10 16:57:30",
                    Lifetime: false,
                    Trial: false,
                    Enabled: true,
                    RecurringEnabled: true,
                },
            ],
            DeliveryInformation: {
                Delivery: "NO_DELIVERY",
                DownloadFile: null,
                DeliveryDescription: "",
                CodesDescription: "",
                Codes: [],
            },
        },
        PriceOptions: [],
        Price: {
            UnitNetPrice: 2,
            UnitGrossPrice: 2,
            UnitVAT: 0,
            UnitDiscount: 0,
            UnitNetDiscountedPrice: 2,
            UnitGrossDiscountedPrice: 2,
            UnitAffiliateCommission: 0,
            ItemUnitNetPrice: 0,
            ItemUnitGrossPrice: 0,
            ItemNetPrice: 0,
            ItemGrossPrice: 0,
            VATPercent: 0,
            HandlingFeeNetPrice: 0,
            HandlingFeeGrossPrice: 0,
            Currency: "usd",
            NetPrice: 2,
            GrossPrice: 2,
            NetDiscountedPrice: 2,
            GrossDiscountedPrice: 2,
            Discount: 0,
            VAT: 0,
            AffiliateCommission: 0,
        },
        LineItemReference: "ea421f868cb7fd204cbb75dcafcd55aece58eb92",
        PurchaseType: "PRODUCT",
        ExternalReference: "",
        Quantity: 1,
        SKU: null,
        CrossSell: null,
        Trial: null,
        AdditionalFields: null,
        Promotion: null,
        RecurringOptions: null,
        SubscriptionStartDate: null,
        SubscriptionCustomSettings: null,
    },
];

subscriptionPostPayload = {
    CustomPriceBillingCyclesLeft: 2,
    DeliveryInfo: {
        Codes: [
            {
                Code: "___TEST___CODE____",
            },
        ],
    },
    EndUser: {
        Address1: "Test Address",
        Address2: "",
        City: "LA",
        Company: "",
        CountryCode: "us",
        Email: "customer@2Checkout.com",
        Fax: "",
        FirstName: "Customer",
        Language: "en",
        LastName: "2Checkout",
        Phone: "",
        State: "CA",
        Zip: "12345",
    },
    ExpirationDate: "2015-12-16",
    ExternalSubscriptionReference: "ThisIsYourUniqueIdentifier123",
    NextRenewalPrice: 49.99,
    NextRenewalPriceCurrency: "usd",
    PartnerCode: "",
    Payment: {
        CCID: "123",
        CardNumber: "4111111111111111",
        CardType: "VISA",
        ExpirationMonth: "12",
        ExpirationYear: "2018",
        HolderName: "John Doe",
    },
    Product: {
        PriceOptionCodes: ["oneuser1"],
        ProductCode: "my_subscription_1",
        ProductId: "4639321",
        ProductName: "2Checkout Subscription",
        ProductQuantity: 1,
        ProductVersion: "",
    },
    StartDate: "2015-02-16",
    SubscriptionValue: 199,
    SubscriptionValueCurrency: "usd",
    Test: 1,
};

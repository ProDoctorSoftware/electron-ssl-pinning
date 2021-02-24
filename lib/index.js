"use strict";
/*
 * Copyright 2018 Dialog LLC <info@dlg.im>
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_forge_1 = __importDefault(require("node-forge"));
const caches = [];
function getModulusFromStringPem(stringPem) {
    const cached = caches.find((cache) => {
        return cache.stringPem === stringPem;
    });
    if (cached) {
        return cached.modulus;
    }
    const certificate = node_forge_1.default.pki.certificateFromPem(stringPem);
    const modulus = JSON.stringify(certificate.publicKey.n.data);
    caches.push({
        stringPem,
        modulus,
    });
    return modulus;
}
// https://electronjs.org/docs/api/session#sessetcertificateverifyprocproc
exports.SSL_DISABLE_VERIFICATION = 0;
exports.SSL_FAILURE = -2;
exports.SSL_USE_CHROME_VERIFICATION = -3;
function createSslVerificator(config) {
    config.forEach(({ domain }) => {
        const wildcardCount = domain.match(/\*/g);
        if (wildcardCount && wildcardCount.length > 1) {
            throw new Error('Wrong wildcard format specified. Use "*.example.org".');
        }
    });
    const rules = config.map((rule) => {
        const modulusSet = new Set(rule.modulus);
        const hostnameRegex = new RegExp('^' + rule.domain.replace('*.', '.*\\.?') + '$');
        return (hostname, modulus) => {
            if (!hostnameRegex.test(hostname)) {
                return false;
            }
            if (rule.strict) {
                return modulus.every((m) => modulusSet.has(m));
            }
            return modulus.some((m) => modulusSet.has(m));
        };
    });
    return (request, callback) => {
        const domainExistsInConfig = config.some((fp) => {
            const hostnameRegex = new RegExp('^' + fp.domain.replace('*.', '.*\\.?') + '$');
            return hostnameRegex.test(request.hostname);
        });
        if (!domainExistsInConfig) {
            callback(exports.SSL_USE_CHROME_VERIFICATION);
            return;
        }
        const modulus = getModulusFromStringPem(request.certificate.data);
        if (rules.some((rule) => rule(request.hostname, [modulus]))) {
            callback(exports.SSL_USE_CHROME_VERIFICATION);
        }
        else {
            callback(exports.SSL_FAILURE);
        }
    };
}
exports.createSslVerificator = createSslVerificator;
//# sourceMappingURL=index.js.map
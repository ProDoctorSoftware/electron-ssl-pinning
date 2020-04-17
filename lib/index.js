"use strict";
/*
 * Copyright 2018 Dialog LLC <info@dlg.im>
 */
Object.defineProperty(exports, "__esModule", { value: true });
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
        const fingerprintSet = new Set(rule.fingerprints);
        const hostnameRegex = new RegExp('^' + rule.domain.replace('*.', '.*\\.?') + '$');
        return (hostname, fingerprints) => {
            if (!hostnameRegex.test(hostname)) {
                return false;
            }
            if (rule.strict) {
                return fingerprints.every((fp) => fingerprintSet.has(fp));
            }
            return fingerprints.some((fp) => fingerprintSet.has(fp));
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
        const fingerprints = [];
        for (let cert = request.certificate; cert && cert !== cert.issuerCert; cert = cert.issuerCert) {
            fingerprints.push(cert.fingerprint);
        }
        if (rules.some((rule) => rule(request.hostname, fingerprints))) {
            callback(exports.SSL_USE_CHROME_VERIFICATION);
        }
        else {
            callback(exports.SSL_FAILURE);
        }
    };
}
exports.createSslVerificator = createSslVerificator;
//# sourceMappingURL=index.js.map
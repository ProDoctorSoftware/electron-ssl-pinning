/*
 * Copyright 2018 Dialog LLC <info@dlg.im>
 */

import { CertificateVerifyProcRequest } from 'electron';
import nodeForge from 'node-forge';

type tCache = {
  stringPem: string;
  modulus: string;
}

const caches: Array<tCache> = [];

function getModulusFromStringPem(stringPem: string) {

  const cached = caches.find((cache) => {
    return cache.stringPem === stringPem;
  });

  if (cached) {
    return cached.modulus;
  }

  const certificate: any = nodeForge.pki.certificateFromPem(stringPem);
  const modulus = JSON.stringify(certificate.publicKey.n.data);

  caches.push({
    stringPem,
    modulus,
  });

  return modulus;
}

type Config = Array<{
  domain: string;
  strict: boolean;
  modulus: Array<string>;
}>;

// https://electronjs.org/docs/api/session#sessetcertificateverifyprocproc
export const SSL_DISABLE_VERIFICATION = 0;
export const SSL_FAILURE = -2;
export const SSL_USE_CHROME_VERIFICATION = -3;

export function createSslVerificator(config: Config) {
  config.forEach(({ domain }) => {
    const wildcardCount = domain.match(/\*/g);
    if (wildcardCount && wildcardCount.length > 1) {
      throw new Error('Wrong wildcard format specified. Use "*.example.org".');
    }
  });

  const rules = config.map((rule) => {
    const modulusSet = new Set(rule.modulus);
    const hostnameRegex = new RegExp(
      '^' + rule.domain.replace('*.', '.*\\.?') + '$'
    );

    return (hostname: string, modulus: Array<string>) => {
      if (!hostnameRegex.test(hostname)) {
        return false;
      }

      if (rule.strict) {
        return modulus.every((m) => modulusSet.has(m));
      }

      return modulus.some((m) => modulusSet.has(m));
    };
  });

  return (
    request: CertificateVerifyProcRequest,
    callback: (verificationResult: number) => void
  ) => {
    const domainExistsInConfig = config.some((fp) => {
      const hostnameRegex = new RegExp(
        '^' + fp.domain.replace('*.', '.*\\.?') + '$'
      );
      return hostnameRegex.test(request.hostname);
    });

    if (!domainExistsInConfig) {
      callback(exports.SSL_USE_CHROME_VERIFICATION);
      return;
    }

    const modulus = getModulusFromStringPem(request.certificate.data)

    if (rules.some((rule) => rule(request.hostname, [modulus]))) {
      callback(SSL_USE_CHROME_VERIFICATION);
    } else {
      callback(SSL_FAILURE);
    }
  };
}

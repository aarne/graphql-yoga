import jsonwebtoken, { VerifyOptions, type JwtPayload } from 'jsonwebtoken';
import { JwksClient, type Options as JwksClientOptions } from 'jwks-rsa';
import type { GetSigningKeyFunction } from './config.js';
import { unauthorizedError } from './utils.js';

export function decodeHeader(token: string) {
  const resp = jsonwebtoken.decode(token, { complete: true });
  return resp?.header;
}

export function createVerifyTokenFunction(options: VerifyOptions | undefined) {
  return (token: string, signingKey: string) => {
    return new Promise<JwtPayload>((resolve, reject) => {
      jsonwebtoken.verify(token, signingKey, options, (err, result) => {
        if (err) {
          reject(unauthorizedError('Unauthenticated'));
        } else {
          resolve(result as JwtPayload);
        }
      });
    });
  };
}

export function createInlineSigningKeyProvider(signingKey: string): GetSigningKeyFunction {
  return () => signingKey;
}

export function createRemoteJwksSigningKeyProvider(
  jwksClientOptions: JwksClientOptions,
): GetSigningKeyFunction {
  const client = new JwksClient(jwksClientOptions);

  return kid => client.getSigningKey(kid)?.then(r => r.getPublicKey());
}

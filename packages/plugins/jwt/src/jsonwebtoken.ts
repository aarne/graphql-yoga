import type { YogaLogger } from 'graphql-yoga';
import jsonwebtoken, { VerifyOptions, type Jwt, type JwtPayload } from 'jsonwebtoken';
import { JwksClient, type Options as JwksClientOptions } from 'jwks-rsa';
import type { TokenVerificationFunction } from './config.js';
import { badRequestError, unauthorizedError } from './utils.js';

type AtleastOneItem<T> = [T, ...T[]];

export type GetSigningKeyFunction = (kid?: string) => Promise<string> | string;

interface CreateValidatorOptions {
  /**
   * List of configurations for the signin-key providers. You can configure multiple signin-key providers to allow for key rotation, fallbacks, etc.
   *
   * In addition, you can use the `remote` variant and configure [`jwks-rsa`'s JWKS client](https://github.com/auth0/node-jwks-rsa/tree/master).
   *
   * The plugin will try to fetch the keys from the providers in the order they are defined in this array.
   *
   * If the first provider fails to fetch the keys, the plugin will try the next provider in the list.
   *
   */
  singingKeyProviders: AtleastOneItem<GetSigningKeyFunction>;
  /**
   * List of token verification options (algorithms, issuer, audience), to be used to verify the token.
   *
   * For additional documentation, please refer to [`jsonwebtoken#VerifyOptions`](https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/jsonwebtoken/index.d.ts#L58-L77).
   *
   * By defualt, only the `RS256` and `HS256` algorithms are configured as validations.
   */
  tokenVerification?: VerifyOptions;
}

export function createJwtValidator(opts: CreateValidatorOptions): TokenVerificationFunction {
  const tokenVerificationOptions = opts.tokenVerification ?? {
    algorithms: ['RS256', 'HS256'],
  };

  return async (token: string, logger: YogaLogger) => {
    const getSigningKey = async (kid?: string) => {
      for (const provider of opts.singingKeyProviders) {
        try {
          const key = await provider(kid);

          if (key) {
            return key;
          }
        } catch (e) {
          logger.error(`Failed to fetch signing key from signing provided:`, e);
        }
      }

      return null;
    };

    // Decode the token first, in order to get the key id to use.
    let decodedToken: Jwt | null;
    try {
      decodedToken = jsonwebtoken.decode(token, { complete: true });
    } catch (e) {
      logger.warn(`Failed to decode JWT authentication token: `, e);
      throw badRequestError(`Invalid authentication token provided`);
    }

    if (!decodedToken) {
      logger.warn(
        `Failed to extract payload from incoming token, please make sure the token is a valid JWT.`,
      );

      throw badRequestError(`Invalid authentication token provided`);
    }

    // Fetch the signing key based on the key id.
    const signingKey = await getSigningKey(decodedToken?.header.kid);

    if (!signingKey) {
      logger.warn(
        `Signing key is not available for the key id: ${decodedToken?.header.kid}. Please make sure signing key providers are configured correctly.`,
      );

      throw Error(`Authentication is not available at the moment.`);
    }

    // Verify the token with the signing key.
    const payload = await verify(logger, token, signingKey, tokenVerificationOptions);
    return payload as JwtPayload;
  };
}

function verify(
  logger: YogaLogger,
  token: string,
  signingKey: string,
  options: VerifyOptions | undefined,
) {
  return new Promise((resolve, reject) => {
    jsonwebtoken.verify(token, signingKey, options, (err, result) => {
      if (err) {
        logger.warn(`Failed to verify authentication token: `, err);
        reject(unauthorizedError('Unauthenticated'));
      } else {
        resolve(result as JwtPayload);
      }
    });
  });
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

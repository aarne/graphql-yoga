import { type PromiseOrValue, type YogaLogger } from 'graphql-yoga';
import { extractFromHeader } from './utils.js';

type AtleastOneItem<T> = [T, ...T[]];

export interface JwtPayload {
  [key: string]: unknown;
  iss?: string | undefined;
  sub?: string | undefined;
  aud?: string | string[] | undefined;
  exp?: number | undefined;
  nbf?: number | undefined;
  iat?: number | undefined;
  jti?: string | undefined;
}

export type ExtractTokenFunction = (params: {
  request: Request;
  serverContext: object | undefined;
  url: URL;
}) => PromiseOrValue<undefined | { token: string; prefix?: string }>;

export type TokenVerificationFunction = (
  token: string,
  logger: YogaLogger,
) => Promise<JwtPayload | undefined>;

export type JwtPluginOptions = {
  /**
   * List of locations to look for the token in the incoming request.
   *
   * By defualt, the plugin will look for the token in the `Authorization` header with the `Bearer` prefix.
   *
   * The plugin will try to extract the token from the locations in the order they are defined in this array.
   *
   * If the token is found in one of the locations, the plugin will stop looking for the token in the other locations.
   *
   * If the token is not found in any of the locations, the plugin will mark the authentication as failed.
   *
   * Can be used with `rejectUnauthenticatedRequests: { missingToken: true }` to reject requests without a token.
   *
   */
  tokenLookupLocations?: AtleastOneItem<ExtractTokenFunction>;
  /**
   * Token decode and verification function.
   */
  tokenVerificationFunction: TokenVerificationFunction;
  /**
   * Whether to reject requests/operations that does not meet criteria.
   *
   * If set to `reject: { missingToken: true }`, the plugin will reject requests without a token (based on the `tokenLookupLocations`).
   *
   * If set to `reject: { invalidToken: true }`, the plugin will reject requests with an invalid token, or tokens that does not meet the verification options (`tokenVerification`).
   *
   * @default { missingToken: true, invalidToken: true }
   */
  reject?: {
    missingToken?: boolean;
    invalidToken?: boolean;
  };
  /**
   * Configuration for the context extension feature, which allows you to extend the request context with the decoded JWT payload or the payload of the fully validated token.
   *
   * This can be useful if you want to access the token or the token payload in your resolvers, or to pass it to other plugins or to the upstream GraphQL Subgraph/HTTP service.
   *
   * If set to `true`, the decoded JWT data will be added to the context under the field name `jwt`.
   *
   * If set to an object, you can customize the field name by setting the `fieldName` property.
   *
   * You may access this field by using `context.<fieldName>` in your resolvers.
   *
   * @default "jwt"
   */
  extendContext?: string | boolean;
};

export function normalizeConfig(input: JwtPluginOptions) {
  const extendContextFieldName: string | null =
    input.extendContext === false
      ? null
      : input.extendContext === undefined || input.extendContext === true
      ? 'jwt'
      : input.extendContext;

  const tokenLookupLocations: ExtractTokenFunction[] = input.tokenLookupLocations ?? [];

  if (tokenLookupLocations.length === 0) {
    tokenLookupLocations.push(
      extractFromHeader({
        name: 'Authorization',
        prefix: 'Bearer',
      }),
    );
  }

  return {
    tokenLookupLocations,
    tokenVerificationFunction: input.tokenVerificationFunction,
    reject: {
      missingToken: true,
      invalidToken: true,
      ...input.reject,
    },
    extendContextFieldName,
  };
}

import axios from 'axios';
import { v4 } from 'uuid';
import crypto from 'crypto';
import { sign } from 'jsonwebtoken';

function _defineProperty$1(obj, key, value) {
  if (key in obj) {
    Object.defineProperty(obj, key, {
      value: value,
      enumerable: true,
      configurable: true,
      writable: true
    });
  } else {
    obj[key] = value;
  }

  return obj;
}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

/**
 * http methods
 */
var HttpMethod;

(function (HttpMethod) {
  HttpMethod["GET"] = "get";
  HttpMethod["POST"] = "post";
})(HttpMethod || (HttpMethod = {}));
/**
 * Constants used for region discovery
 */


const REGION_ENVIRONMENT_VARIABLE = "REGION_NAME";
/**
 * Constant used for PKCE
 */

const RANDOM_OCTET_SIZE = 32;
/**
 * Constants used in PKCE
 */

const Hash = {
  SHA256: "sha256"
};
/**
 * Constants for encoding schemes
 */

const CharSet = {
  CV_CHARSET: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
};
/**
 * Constants
 */

const Constants$1 = {
  MSAL_SKU: "msal.js.node",
  JWT_BEARER_ASSERTION_TYPE: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
};
/**
 * API Codes for Telemetry purposes.
 * Before adding a new code you must claim it in the MSAL Telemetry tracker as these number spaces are shared across all MSALs
 * 0-99 Silent Flow
 * 600-699 Device Code Flow
 * 800-899 Auth Code Flow
 */

var ApiId;

(function (ApiId) {
  ApiId[ApiId["acquireTokenSilent"] = 62] = "acquireTokenSilent";
  ApiId[ApiId["acquireTokenByUsernamePassword"] = 371] = "acquireTokenByUsernamePassword";
  ApiId[ApiId["acquireTokenByDeviceCode"] = 671] = "acquireTokenByDeviceCode";
  ApiId[ApiId["acquireTokenByClientCredential"] = 771] = "acquireTokenByClientCredential";
  ApiId[ApiId["acquireTokenByCode"] = 871] = "acquireTokenByCode";
  ApiId[ApiId["acquireTokenByRefreshToken"] = 872] = "acquireTokenByRefreshToken";
})(ApiId || (ApiId = {}));
/**
 * JWT  constants
 */


const JwtConstants = {
  ALGORITHM: "alg",
  RSA_256: "RS256",
  X5T: "x5t",
  X5C: "x5c",
  AUDIENCE: "aud",
  EXPIRATION_TIME: "exp",
  ISSUER: "iss",
  SUBJECT: "sub",
  NOT_BEFORE: "nbf",
  JWT_ID: "jti"
};

function _defineProperty(obj, key, value) {
  if (key in obj) {
    Object.defineProperty(obj, key, {
      value: value,
      enumerable: true,
      configurable: true,
      writable: true
    });
  } else {
    obj[key] = value;
  }

  return obj;
}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
const Constants = {
  LIBRARY_NAME: "MSAL.JS",
  SKU: "msal.js.common",
  // Prefix for all library cache entries
  CACHE_PREFIX: "msal",
  // default authority
  DEFAULT_AUTHORITY: "https://login.microsoftonline.com/common/",
  DEFAULT_AUTHORITY_HOST: "login.microsoftonline.com",
  // ADFS String
  ADFS: "adfs",
  // Default AAD Instance Discovery Endpoint
  AAD_INSTANCE_DISCOVERY_ENDPT: "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=",
  // Resource delimiter - used for certain cache entries
  RESOURCE_DELIM: "|",
  // Placeholder for non-existent account ids/objects
  NO_ACCOUNT: "NO_ACCOUNT",
  // Claims
  CLAIMS: "claims",
  // Consumer UTID
  CONSUMER_UTID: "9188040d-6c67-4c5b-b112-36a304b66dad",
  // Default scopes
  OPENID_SCOPE: "openid",
  PROFILE_SCOPE: "profile",
  OFFLINE_ACCESS_SCOPE: "offline_access",
  EMAIL_SCOPE: "email",
  // Default response type for authorization code flow
  CODE_RESPONSE_TYPE: "code",
  CODE_GRANT_TYPE: "authorization_code",
  RT_GRANT_TYPE: "refresh_token",
  FRAGMENT_RESPONSE_MODE: "fragment",
  S256_CODE_CHALLENGE_METHOD: "S256",
  URL_FORM_CONTENT_TYPE: "application/x-www-form-urlencoded;charset=utf-8",
  AUTHORIZATION_PENDING: "authorization_pending",
  NOT_DEFINED: "not_defined",
  EMPTY_STRING: "",
  FORWARD_SLASH: "/",
  IMDS_ENDPOINT: "http://169.254.169.254/metadata/instance/compute/location",
  IMDS_VERSION: "2020-06-01",
  IMDS_TIMEOUT: 2000,
  AZURE_REGION_AUTO_DISCOVER_FLAG: "AUTO_DISCOVER",
  REGIONAL_AUTH_PUBLIC_CLOUD_SUFFIX: "login.microsoft.com",
  KNOWN_PUBLIC_CLOUDS: ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com", "sts.windows.net"]
};
const OIDC_DEFAULT_SCOPES = [Constants.OPENID_SCOPE, Constants.PROFILE_SCOPE, Constants.OFFLINE_ACCESS_SCOPE];
const OIDC_SCOPES = [...OIDC_DEFAULT_SCOPES, Constants.EMAIL_SCOPE];
/**
 * Request header names
 */

var HeaderNames;

(function (HeaderNames) {
  HeaderNames["CONTENT_TYPE"] = "Content-Type";
  HeaderNames["RETRY_AFTER"] = "Retry-After";
})(HeaderNames || (HeaderNames = {}));
/**
 * Persistent cache keys MSAL which stay while user is logged in.
 */


var PersistentCacheKeys;

(function (PersistentCacheKeys) {
  PersistentCacheKeys["ID_TOKEN"] = "idtoken";
  PersistentCacheKeys["CLIENT_INFO"] = "client.info";
  PersistentCacheKeys["ADAL_ID_TOKEN"] = "adal.idtoken";
  PersistentCacheKeys["ERROR"] = "error";
  PersistentCacheKeys["ERROR_DESC"] = "error.description";
})(PersistentCacheKeys || (PersistentCacheKeys = {}));
/**
 * String constants related to AAD Authority
 */


var AADAuthorityConstants;

(function (AADAuthorityConstants) {
  AADAuthorityConstants["COMMON"] = "common";
  AADAuthorityConstants["ORGANIZATIONS"] = "organizations";
  AADAuthorityConstants["CONSUMERS"] = "consumers";
})(AADAuthorityConstants || (AADAuthorityConstants = {}));
/**
 * Keys in the hashParams sent by AAD Server
 */


var AADServerParamKeys;

(function (AADServerParamKeys) {
  AADServerParamKeys["CLIENT_ID"] = "client_id";
  AADServerParamKeys["REDIRECT_URI"] = "redirect_uri";
  AADServerParamKeys["RESPONSE_TYPE"] = "response_type";
  AADServerParamKeys["RESPONSE_MODE"] = "response_mode";
  AADServerParamKeys["GRANT_TYPE"] = "grant_type";
  AADServerParamKeys["CLAIMS"] = "claims";
  AADServerParamKeys["SCOPE"] = "scope";
  AADServerParamKeys["ERROR"] = "error";
  AADServerParamKeys["ERROR_DESCRIPTION"] = "error_description";
  AADServerParamKeys["ACCESS_TOKEN"] = "access_token";
  AADServerParamKeys["ID_TOKEN"] = "id_token";
  AADServerParamKeys["REFRESH_TOKEN"] = "refresh_token";
  AADServerParamKeys["EXPIRES_IN"] = "expires_in";
  AADServerParamKeys["STATE"] = "state";
  AADServerParamKeys["NONCE"] = "nonce";
  AADServerParamKeys["PROMPT"] = "prompt";
  AADServerParamKeys["SESSION_STATE"] = "session_state";
  AADServerParamKeys["CLIENT_INFO"] = "client_info";
  AADServerParamKeys["CODE"] = "code";
  AADServerParamKeys["CODE_CHALLENGE"] = "code_challenge";
  AADServerParamKeys["CODE_CHALLENGE_METHOD"] = "code_challenge_method";
  AADServerParamKeys["CODE_VERIFIER"] = "code_verifier";
  AADServerParamKeys["CLIENT_REQUEST_ID"] = "client-request-id";
  AADServerParamKeys["X_CLIENT_SKU"] = "x-client-SKU";
  AADServerParamKeys["X_CLIENT_VER"] = "x-client-VER";
  AADServerParamKeys["X_CLIENT_OS"] = "x-client-OS";
  AADServerParamKeys["X_CLIENT_CPU"] = "x-client-CPU";
  AADServerParamKeys["X_CLIENT_CURR_TELEM"] = "x-client-current-telemetry";
  AADServerParamKeys["X_CLIENT_LAST_TELEM"] = "x-client-last-telemetry";
  AADServerParamKeys["X_MS_LIB_CAPABILITY"] = "x-ms-lib-capability";
  AADServerParamKeys["POST_LOGOUT_URI"] = "post_logout_redirect_uri";
  AADServerParamKeys["ID_TOKEN_HINT"] = "id_token_hint";
  AADServerParamKeys["DEVICE_CODE"] = "device_code";
  AADServerParamKeys["CLIENT_SECRET"] = "client_secret";
  AADServerParamKeys["CLIENT_ASSERTION"] = "client_assertion";
  AADServerParamKeys["CLIENT_ASSERTION_TYPE"] = "client_assertion_type";
  AADServerParamKeys["TOKEN_TYPE"] = "token_type";
  AADServerParamKeys["REQ_CNF"] = "req_cnf";
  AADServerParamKeys["OBO_ASSERTION"] = "assertion";
  AADServerParamKeys["REQUESTED_TOKEN_USE"] = "requested_token_use";
  AADServerParamKeys["ON_BEHALF_OF"] = "on_behalf_of";
  AADServerParamKeys["FOCI"] = "foci";
})(AADServerParamKeys || (AADServerParamKeys = {}));
/**
 * Claims request keys
 */


var ClaimsRequestKeys;

(function (ClaimsRequestKeys) {
  ClaimsRequestKeys["ACCESS_TOKEN"] = "access_token";
  ClaimsRequestKeys["XMS_CC"] = "xms_cc";
})(ClaimsRequestKeys || (ClaimsRequestKeys = {}));
/**
 * we considered making this "enum" in the request instead of string, however it looks like the allowed list of
 * prompt values kept changing over past couple of years. There are some undocumented prompt values for some
 * internal partners too, hence the choice of generic "string" type instead of the "enum"
 */


const PromptValue = {
  LOGIN: "login",
  SELECT_ACCOUNT: "select_account",
  CONSENT: "consent",
  NONE: "none"
};
/**
 * SSO Types - generated to populate hints
 */

var SSOTypes;

(function (SSOTypes) {
  SSOTypes["ACCOUNT"] = "account";
  SSOTypes["SID"] = "sid";
  SSOTypes["LOGIN_HINT"] = "login_hint";
  SSOTypes["ID_TOKEN"] = "id_token";
  SSOTypes["DOMAIN_HINT"] = "domain_hint";
  SSOTypes["ORGANIZATIONS"] = "organizations";
  SSOTypes["CONSUMERS"] = "consumers";
  SSOTypes["ACCOUNT_ID"] = "accountIdentifier";
  SSOTypes["HOMEACCOUNT_ID"] = "homeAccountIdentifier";
})(SSOTypes || (SSOTypes = {}));
/**
 * Disallowed extra query parameters.
 */


[SSOTypes.SID, SSOTypes.LOGIN_HINT];
/**
 * allowed values for codeVerifier
 */

const CodeChallengeMethodValues = {
  PLAIN: "plain",
  S256: "S256"
};
/**
 * allowed values for response_mode
 */

var ResponseMode;

(function (ResponseMode) {
  ResponseMode["QUERY"] = "query";
  ResponseMode["FRAGMENT"] = "fragment";
  ResponseMode["FORM_POST"] = "form_post";
})(ResponseMode || (ResponseMode = {}));
/**
 * allowed grant_type
 */


var GrantType;

(function (GrantType) {
  GrantType["IMPLICIT_GRANT"] = "implicit";
  GrantType["AUTHORIZATION_CODE_GRANT"] = "authorization_code";
  GrantType["CLIENT_CREDENTIALS_GRANT"] = "client_credentials";
  GrantType["RESOURCE_OWNER_PASSWORD_GRANT"] = "password";
  GrantType["REFRESH_TOKEN_GRANT"] = "refresh_token";
  GrantType["DEVICE_CODE_GRANT"] = "device_code";
  GrantType["JWT_BEARER"] = "urn:ietf:params:oauth:grant-type:jwt-bearer";
})(GrantType || (GrantType = {}));
/**
 * Account types in Cache
 */


var CacheAccountType;

(function (CacheAccountType) {
  CacheAccountType["MSSTS_ACCOUNT_TYPE"] = "MSSTS";
  CacheAccountType["ADFS_ACCOUNT_TYPE"] = "ADFS";
  CacheAccountType["MSAV1_ACCOUNT_TYPE"] = "MSA";
  CacheAccountType["GENERIC_ACCOUNT_TYPE"] = "Generic"; // NTLM, Kerberos, FBA, Basic etc
})(CacheAccountType || (CacheAccountType = {}));
/**
 * Separators used in cache
 */


var Separators;

(function (Separators) {
  Separators["CACHE_KEY_SEPARATOR"] = "-";
  Separators["CLIENT_INFO_SEPARATOR"] = ".";
})(Separators || (Separators = {}));
/**
 * Credential Type stored in the cache
 */


var CredentialType;

(function (CredentialType) {
  CredentialType["ID_TOKEN"] = "IdToken";
  CredentialType["ACCESS_TOKEN"] = "AccessToken";
  CredentialType["ACCESS_TOKEN_WITH_AUTH_SCHEME"] = "AccessToken_With_AuthScheme";
  CredentialType["REFRESH_TOKEN"] = "RefreshToken";
})(CredentialType || (CredentialType = {}));
/**
 * Credential Type stored in the cache
 */


var CacheSchemaType;

(function (CacheSchemaType) {
  CacheSchemaType["ACCOUNT"] = "Account";
  CacheSchemaType["CREDENTIAL"] = "Credential";
  CacheSchemaType["ID_TOKEN"] = "IdToken";
  CacheSchemaType["ACCESS_TOKEN"] = "AccessToken";
  CacheSchemaType["REFRESH_TOKEN"] = "RefreshToken";
  CacheSchemaType["APP_METADATA"] = "AppMetadata";
  CacheSchemaType["TEMPORARY"] = "TempCache";
  CacheSchemaType["TELEMETRY"] = "Telemetry";
  CacheSchemaType["UNDEFINED"] = "Undefined";
  CacheSchemaType["THROTTLING"] = "Throttling";
})(CacheSchemaType || (CacheSchemaType = {}));
/**
 * Combine all cache types
 */


var CacheType;

(function (CacheType) {
  CacheType[CacheType["ADFS"] = 1001] = "ADFS";
  CacheType[CacheType["MSA"] = 1002] = "MSA";
  CacheType[CacheType["MSSTS"] = 1003] = "MSSTS";
  CacheType[CacheType["GENERIC"] = 1004] = "GENERIC";
  CacheType[CacheType["ACCESS_TOKEN"] = 2001] = "ACCESS_TOKEN";
  CacheType[CacheType["REFRESH_TOKEN"] = 2002] = "REFRESH_TOKEN";
  CacheType[CacheType["ID_TOKEN"] = 2003] = "ID_TOKEN";
  CacheType[CacheType["APP_METADATA"] = 3001] = "APP_METADATA";
  CacheType[CacheType["UNDEFINED"] = 9999] = "UNDEFINED";
})(CacheType || (CacheType = {}));
/**
 * More Cache related constants
 */


const APP_METADATA = "appmetadata";
const ClientInfo = "client_info";
const THE_FAMILY_ID = "1";
const AUTHORITY_METADATA_CONSTANTS = {
  CACHE_KEY: "authority-metadata",
  REFRESH_TIME_SECONDS: 3600 * 24 // 24 Hours

};
var AuthorityMetadataSource;

(function (AuthorityMetadataSource) {
  AuthorityMetadataSource["CONFIG"] = "config";
  AuthorityMetadataSource["CACHE"] = "cache";
  AuthorityMetadataSource["NETWORK"] = "network";
})(AuthorityMetadataSource || (AuthorityMetadataSource = {}));

const SERVER_TELEM_CONSTANTS = {
  SCHEMA_VERSION: 2,
  MAX_CUR_HEADER_BYTES: 80,
  MAX_LAST_HEADER_BYTES: 330,
  MAX_CACHED_ERRORS: 50,
  CACHE_KEY: "server-telemetry",
  CATEGORY_SEPARATOR: "|",
  VALUE_SEPARATOR: ",",
  OVERFLOW_TRUE: "1",
  OVERFLOW_FALSE: "0",
  UNKNOWN_ERROR: "unknown_error"
};
/**
 * Type of the authentication request
 */

var AuthenticationScheme;

(function (AuthenticationScheme) {
  AuthenticationScheme["POP"] = "pop";
  AuthenticationScheme["BEARER"] = "Bearer";
})(AuthenticationScheme || (AuthenticationScheme = {}));
/**
 * Constants related to throttling
 */


const ThrottlingConstants = {
  // Default time to throttle RequestThumbprint in seconds
  DEFAULT_THROTTLE_TIME_SECONDS: 60,
  // Default maximum time to throttle in seconds, overrides what the server sends back
  DEFAULT_MAX_THROTTLE_TIME_SECONDS: 3600,
  // Prefix for storing throttling entries
  THROTTLING_PREFIX: "throttling",
  // Value assigned to the x-ms-lib-capability header to indicate to the server the library supports throttling
  X_MS_LIB_CAPABILITY_VALUE: "retry-after, h429"
};
const Errors = {
  INVALID_GRANT_ERROR: "invalid_grant",
  CLIENT_MISMATCH_ERROR: "client_mismatch"
};
/**
 * Password grant parameters
 */

var PasswordGrantConstants;

(function (PasswordGrantConstants) {
  PasswordGrantConstants["username"] = "username";
  PasswordGrantConstants["password"] = "password";
})(PasswordGrantConstants || (PasswordGrantConstants = {}));
/**
 * Response codes
 */


var ResponseCodes;

(function (ResponseCodes) {
  ResponseCodes[ResponseCodes["httpSuccess"] = 200] = "httpSuccess";
  ResponseCodes[ResponseCodes["httpBadRequest"] = 400] = "httpBadRequest";
})(ResponseCodes || (ResponseCodes = {}));

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * AuthErrorMessage class containing string constants used by error codes and messages.
 */

const AuthErrorMessage = {
  unexpectedError: {
    code: "unexpected_error",
    desc: "Unexpected error in authentication."
  }
};
/**
 * General error class thrown by the MSAL.js library.
 */

class AuthError extends Error {
  constructor(errorCode, errorMessage, suberror) {
    const errorString = errorMessage ? `${errorCode}: ${errorMessage}` : errorCode;
    super(errorString);
    Object.setPrototypeOf(this, AuthError.prototype);
    this.errorCode = errorCode || Constants.EMPTY_STRING;
    this.errorMessage = errorMessage || "";
    this.subError = suberror || "";
    this.name = "AuthError";
  }
  /**
   * Creates an error that is thrown when something unexpected happens in the library.
   * @param errDesc
   */


  static createUnexpectedError(errDesc) {
    return new AuthError(AuthErrorMessage.unexpectedError.code, `${AuthErrorMessage.unexpectedError.desc}: ${errDesc}`);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
const DEFAULT_CRYPTO_IMPLEMENTATION = {
  createNewGuid: () => {
    const notImplErr = "Crypto interface - createNewGuid() has not been implemented";
    throw AuthError.createUnexpectedError(notImplErr);
  },
  base64Decode: () => {
    const notImplErr = "Crypto interface - base64Decode() has not been implemented";
    throw AuthError.createUnexpectedError(notImplErr);
  },
  base64Encode: () => {
    const notImplErr = "Crypto interface - base64Encode() has not been implemented";
    throw AuthError.createUnexpectedError(notImplErr);
  },

  async generatePkceCodes() {
    const notImplErr = "Crypto interface - generatePkceCodes() has not been implemented";
    throw AuthError.createUnexpectedError(notImplErr);
  },

  async getPublicKeyThumbprint() {
    const notImplErr = "Crypto interface - getPublicKeyThumbprint() has not been implemented";
    throw AuthError.createUnexpectedError(notImplErr);
  },

  async signJwt() {
    const notImplErr = "Crypto interface - signJwt() has not been implemented";
    throw AuthError.createUnexpectedError(notImplErr);
  }

};

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * ClientAuthErrorMessage class containing string constants used by error codes and messages.
 */

const ClientAuthErrorMessage = {
  clientInfoDecodingError: {
    code: "client_info_decoding_error",
    desc: "The client info could not be parsed/decoded correctly. Please review the trace to determine the root cause."
  },
  clientInfoEmptyError: {
    code: "client_info_empty_error",
    desc: "The client info was empty. Please review the trace to determine the root cause."
  },
  tokenParsingError: {
    code: "token_parsing_error",
    desc: "Token cannot be parsed. Please review stack trace to determine root cause."
  },
  nullOrEmptyToken: {
    code: "null_or_empty_token",
    desc: "The token is null or empty. Please review the trace to determine the root cause."
  },
  endpointResolutionError: {
    code: "endpoints_resolution_error",
    desc: "Error: could not resolve endpoints. Please check network and try again."
  },
  networkError: {
    code: "network_error",
    desc: "Network request failed. Please check network trace to determine root cause."
  },
  unableToGetOpenidConfigError: {
    code: "openid_config_error",
    desc: "Could not retrieve endpoints. Check your authority and verify the .well-known/openid-configuration endpoint returns the required endpoints."
  },
  hashNotDeserialized: {
    code: "hash_not_deserialized",
    desc: "The hash parameters could not be deserialized. Please review the trace to determine the root cause."
  },
  blankGuidGenerated: {
    code: "blank_guid_generated",
    desc: "The guid generated was blank. Please review the trace to determine the root cause."
  },
  invalidStateError: {
    code: "invalid_state",
    desc: "State was not the expected format. Please check the logs to determine whether the request was sent using ProtocolUtils.setRequestState()."
  },
  stateMismatchError: {
    code: "state_mismatch",
    desc: "State mismatch error. Please check your network. Continued requests may cause cache overflow."
  },
  stateNotFoundError: {
    code: "state_not_found",
    desc: "State not found"
  },
  nonceMismatchError: {
    code: "nonce_mismatch",
    desc: "Nonce mismatch error. This may be caused by a race condition in concurrent requests."
  },
  nonceNotFoundError: {
    code: "nonce_not_found",
    desc: "nonce not found"
  },
  noTokensFoundError: {
    code: "no_tokens_found",
    desc: "No tokens were found for the given scopes, and no authorization code was passed to acquireToken. You must retrieve an authorization code before making a call to acquireToken()."
  },
  multipleMatchingTokens: {
    code: "multiple_matching_tokens",
    desc: "The cache contains multiple tokens satisfying the requirements. " + "Call AcquireToken again providing more requirements such as authority or account."
  },
  multipleMatchingAccounts: {
    code: "multiple_matching_accounts",
    desc: "The cache contains multiple accounts satisfying the given parameters. Please pass more info to obtain the correct account"
  },
  multipleMatchingAppMetadata: {
    code: "multiple_matching_appMetadata",
    desc: "The cache contains multiple appMetadata satisfying the given parameters. Please pass more info to obtain the correct appMetadata"
  },
  tokenRequestCannotBeMade: {
    code: "request_cannot_be_made",
    desc: "Token request cannot be made without authorization code or refresh token."
  },
  appendEmptyScopeError: {
    code: "cannot_append_empty_scope",
    desc: "Cannot append null or empty scope to ScopeSet. Please check the stack trace for more info."
  },
  removeEmptyScopeError: {
    code: "cannot_remove_empty_scope",
    desc: "Cannot remove null or empty scope from ScopeSet. Please check the stack trace for more info."
  },
  appendScopeSetError: {
    code: "cannot_append_scopeset",
    desc: "Cannot append ScopeSet due to error."
  },
  emptyInputScopeSetError: {
    code: "empty_input_scopeset",
    desc: "Empty input ScopeSet cannot be processed."
  },
  DeviceCodePollingCancelled: {
    code: "device_code_polling_cancelled",
    desc: "Caller has cancelled token endpoint polling during device code flow by setting DeviceCodeRequest.cancel = true."
  },
  DeviceCodeExpired: {
    code: "device_code_expired",
    desc: "Device code is expired."
  },
  NoAccountInSilentRequest: {
    code: "no_account_in_silent_request",
    desc: "Please pass an account object, silent flow is not supported without account information"
  },
  invalidCacheRecord: {
    code: "invalid_cache_record",
    desc: "Cache record object was null or undefined."
  },
  invalidCacheEnvironment: {
    code: "invalid_cache_environment",
    desc: "Invalid environment when attempting to create cache entry"
  },
  noAccountFound: {
    code: "no_account_found",
    desc: "No account found in cache for given key."
  },
  CachePluginError: {
    code: "no cache plugin set on CacheManager",
    desc: "ICachePlugin needs to be set before using readFromStorage or writeFromStorage"
  },
  noCryptoObj: {
    code: "no_crypto_object",
    desc: "No crypto object detected. This is required for the following operation: "
  },
  invalidCacheType: {
    code: "invalid_cache_type",
    desc: "Invalid cache type"
  },
  unexpectedAccountType: {
    code: "unexpected_account_type",
    desc: "Unexpected account type."
  },
  unexpectedCredentialType: {
    code: "unexpected_credential_type",
    desc: "Unexpected credential type."
  },
  invalidAssertion: {
    code: "invalid_assertion",
    desc: "Client assertion must meet requirements described in https://tools.ietf.org/html/rfc7515"
  },
  invalidClientCredential: {
    code: "invalid_client_credential",
    desc: "Client credential (secret, certificate, or assertion) must not be empty when creating a confidential client. An application should at most have one credential"
  },
  tokenRefreshRequired: {
    code: "token_refresh_required",
    desc: "Cannot return token from cache because it must be refreshed. This may be due to one of the following reasons: forceRefresh parameter is set to true, claims have been requested, there is no cached access token or it is expired."
  },
  userTimeoutReached: {
    code: "user_timeout_reached",
    desc: "User defined timeout for device code polling reached"
  },
  tokenClaimsRequired: {
    code: "token_claims_cnf_required_for_signedjwt",
    desc: "Cannot generate a POP jwt if the token_claims are not populated"
  },
  noAuthorizationCodeFromServer: {
    code: "authorization_code_missing_from_server_response",
    desc: "Server response does not contain an authorization code to proceed"
  },
  noAzureRegionDetected: {
    code: "no_azure_region_detected",
    desc: "No azure region was detected and no fallback was made available"
  },
  accessTokenEntityNullError: {
    code: "access_token_entity_null",
    desc: "Access token entity is null, please check logs and cache to ensure a valid access token is present."
  }
};
/**
 * Error thrown when there is an error in the client code running on the browser.
 */

class ClientAuthError extends AuthError {
  constructor(errorCode, errorMessage) {
    super(errorCode, errorMessage);
    this.name = "ClientAuthError";
    Object.setPrototypeOf(this, ClientAuthError.prototype);
  }
  /**
   * Creates an error thrown when client info object doesn't decode correctly.
   * @param caughtError
   */


  static createClientInfoDecodingError(caughtError) {
    return new ClientAuthError(ClientAuthErrorMessage.clientInfoDecodingError.code, `${ClientAuthErrorMessage.clientInfoDecodingError.desc} Failed with error: ${caughtError}`);
  }
  /**
   * Creates an error thrown if the client info is empty.
   * @param rawClientInfo
   */


  static createClientInfoEmptyError() {
    return new ClientAuthError(ClientAuthErrorMessage.clientInfoEmptyError.code, `${ClientAuthErrorMessage.clientInfoEmptyError.desc}`);
  }
  /**
   * Creates an error thrown when the id token extraction errors out.
   * @param err
   */


  static createTokenParsingError(caughtExtractionError) {
    return new ClientAuthError(ClientAuthErrorMessage.tokenParsingError.code, `${ClientAuthErrorMessage.tokenParsingError.desc} Failed with error: ${caughtExtractionError}`);
  }
  /**
   * Creates an error thrown when the id token string is null or empty.
   * @param invalidRawTokenString
   */


  static createTokenNullOrEmptyError(invalidRawTokenString) {
    return new ClientAuthError(ClientAuthErrorMessage.nullOrEmptyToken.code, `${ClientAuthErrorMessage.nullOrEmptyToken.desc} Raw Token Value: ${invalidRawTokenString}`);
  }
  /**
   * Creates an error thrown when the endpoint discovery doesn't complete correctly.
   */


  static createEndpointDiscoveryIncompleteError(errDetail) {
    return new ClientAuthError(ClientAuthErrorMessage.endpointResolutionError.code, `${ClientAuthErrorMessage.endpointResolutionError.desc} Detail: ${errDetail}`);
  }
  /**
   * Creates an error thrown when the fetch client throws
   */


  static createNetworkError(endpoint, errDetail) {
    return new ClientAuthError(ClientAuthErrorMessage.networkError.code, `${ClientAuthErrorMessage.networkError.desc} | Fetch client threw: ${errDetail} | Attempted to reach: ${endpoint.split("?")[0]}`);
  }
  /**
   * Creates an error thrown when the openid-configuration endpoint cannot be reached or does not contain the required data
   */


  static createUnableToGetOpenidConfigError(errDetail) {
    return new ClientAuthError(ClientAuthErrorMessage.unableToGetOpenidConfigError.code, `${ClientAuthErrorMessage.unableToGetOpenidConfigError.desc} Attempted to retrieve endpoints from: ${errDetail}`);
  }
  /**
   * Creates an error thrown when the hash cannot be deserialized.
   * @param hashParamObj
   */


  static createHashNotDeserializedError(hashParamObj) {
    return new ClientAuthError(ClientAuthErrorMessage.hashNotDeserialized.code, `${ClientAuthErrorMessage.hashNotDeserialized.desc} Given Object: ${hashParamObj}`);
  }
  /**
   * Creates an error thrown when the state cannot be parsed.
   * @param invalidState
   */


  static createInvalidStateError(invalidState, errorString) {
    return new ClientAuthError(ClientAuthErrorMessage.invalidStateError.code, `${ClientAuthErrorMessage.invalidStateError.desc} Invalid State: ${invalidState}, Root Err: ${errorString}`);
  }
  /**
   * Creates an error thrown when two states do not match.
   */


  static createStateMismatchError() {
    return new ClientAuthError(ClientAuthErrorMessage.stateMismatchError.code, ClientAuthErrorMessage.stateMismatchError.desc);
  }
  /**
   * Creates an error thrown when the state is not present
   * @param missingState
   */


  static createStateNotFoundError(missingState) {
    return new ClientAuthError(ClientAuthErrorMessage.stateNotFoundError.code, `${ClientAuthErrorMessage.stateNotFoundError.desc}:  ${missingState}`);
  }
  /**
   * Creates an error thrown when the nonce does not match.
   */


  static createNonceMismatchError() {
    return new ClientAuthError(ClientAuthErrorMessage.nonceMismatchError.code, ClientAuthErrorMessage.nonceMismatchError.desc);
  }
  /**
   * Creates an error thrown when the mnonce is not present
   * @param missingNonce
   */


  static createNonceNotFoundError(missingNonce) {
    return new ClientAuthError(ClientAuthErrorMessage.nonceNotFoundError.code, `${ClientAuthErrorMessage.nonceNotFoundError.desc}:  ${missingNonce}`);
  }
  /**
   * Creates an error thrown when the authorization code required for a token request is null or empty.
   */


  static createNoTokensFoundError() {
    return new ClientAuthError(ClientAuthErrorMessage.noTokensFoundError.code, ClientAuthErrorMessage.noTokensFoundError.desc);
  }
  /**
   * Throws error when multiple tokens are in cache.
   */


  static createMultipleMatchingTokensInCacheError() {
    return new ClientAuthError(ClientAuthErrorMessage.multipleMatchingTokens.code, `${ClientAuthErrorMessage.multipleMatchingTokens.desc}.`);
  }
  /**
   * Throws error when multiple accounts are in cache for the given params
   */


  static createMultipleMatchingAccountsInCacheError() {
    return new ClientAuthError(ClientAuthErrorMessage.multipleMatchingAccounts.code, ClientAuthErrorMessage.multipleMatchingAccounts.desc);
  }
  /**
   * Throws error when multiple appMetada are in cache for the given clientId.
   */


  static createMultipleMatchingAppMetadataInCacheError() {
    return new ClientAuthError(ClientAuthErrorMessage.multipleMatchingAppMetadata.code, ClientAuthErrorMessage.multipleMatchingAppMetadata.desc);
  }
  /**
   * Throws error when no auth code or refresh token is given to ServerTokenRequestParameters.
   */


  static createTokenRequestCannotBeMadeError() {
    return new ClientAuthError(ClientAuthErrorMessage.tokenRequestCannotBeMade.code, ClientAuthErrorMessage.tokenRequestCannotBeMade.desc);
  }
  /**
   * Throws error when attempting to append a null, undefined or empty scope to a set
   * @param givenScope
   */


  static createAppendEmptyScopeToSetError(givenScope) {
    return new ClientAuthError(ClientAuthErrorMessage.appendEmptyScopeError.code, `${ClientAuthErrorMessage.appendEmptyScopeError.desc} Given Scope: ${givenScope}`);
  }
  /**
   * Throws error when attempting to append a null, undefined or empty scope to a set
   * @param givenScope
   */


  static createRemoveEmptyScopeFromSetError(givenScope) {
    return new ClientAuthError(ClientAuthErrorMessage.removeEmptyScopeError.code, `${ClientAuthErrorMessage.removeEmptyScopeError.desc} Given Scope: ${givenScope}`);
  }
  /**
   * Throws error when attempting to append null or empty ScopeSet.
   * @param appendError
   */


  static createAppendScopeSetError(appendError) {
    return new ClientAuthError(ClientAuthErrorMessage.appendScopeSetError.code, `${ClientAuthErrorMessage.appendScopeSetError.desc} Detail Error: ${appendError}`);
  }
  /**
   * Throws error if ScopeSet is null or undefined.
   * @param givenScopeSet
   */


  static createEmptyInputScopeSetError(givenScopeSet) {
    return new ClientAuthError(ClientAuthErrorMessage.emptyInputScopeSetError.code, `${ClientAuthErrorMessage.emptyInputScopeSetError.desc} Given ScopeSet: ${givenScopeSet}`);
  }
  /**
   * Throws error if user sets CancellationToken.cancel = true during polling of token endpoint during device code flow
   */


  static createDeviceCodeCancelledError() {
    return new ClientAuthError(ClientAuthErrorMessage.DeviceCodePollingCancelled.code, `${ClientAuthErrorMessage.DeviceCodePollingCancelled.desc}`);
  }
  /**
   * Throws error if device code is expired
   */


  static createDeviceCodeExpiredError() {
    return new ClientAuthError(ClientAuthErrorMessage.DeviceCodeExpired.code, `${ClientAuthErrorMessage.DeviceCodeExpired.desc}`);
  }
  /**
   * Throws error when silent requests are made without an account object
   */


  static createNoAccountInSilentRequestError() {
    return new ClientAuthError(ClientAuthErrorMessage.NoAccountInSilentRequest.code, `${ClientAuthErrorMessage.NoAccountInSilentRequest.desc}`);
  }
  /**
   * Throws error when cache record is null or undefined.
   */


  static createNullOrUndefinedCacheRecord() {
    return new ClientAuthError(ClientAuthErrorMessage.invalidCacheRecord.code, ClientAuthErrorMessage.invalidCacheRecord.desc);
  }
  /**
   * Throws error when provided environment is not part of the CloudDiscoveryMetadata object
   */


  static createInvalidCacheEnvironmentError() {
    return new ClientAuthError(ClientAuthErrorMessage.invalidCacheEnvironment.code, ClientAuthErrorMessage.invalidCacheEnvironment.desc);
  }
  /**
   * Throws error when account is not found in cache.
   */


  static createNoAccountFoundError() {
    return new ClientAuthError(ClientAuthErrorMessage.noAccountFound.code, ClientAuthErrorMessage.noAccountFound.desc);
  }
  /**
   * Throws error if ICachePlugin not set on CacheManager.
   */


  static createCachePluginError() {
    return new ClientAuthError(ClientAuthErrorMessage.CachePluginError.code, `${ClientAuthErrorMessage.CachePluginError.desc}`);
  }
  /**
   * Throws error if crypto object not found.
   * @param operationName
   */


  static createNoCryptoObjectError(operationName) {
    return new ClientAuthError(ClientAuthErrorMessage.noCryptoObj.code, `${ClientAuthErrorMessage.noCryptoObj.desc}${operationName}`);
  }
  /**
   * Throws error if cache type is invalid.
   */


  static createInvalidCacheTypeError() {
    return new ClientAuthError(ClientAuthErrorMessage.invalidCacheType.code, `${ClientAuthErrorMessage.invalidCacheType.desc}`);
  }
  /**
   * Throws error if unexpected account type.
   */


  static createUnexpectedAccountTypeError() {
    return new ClientAuthError(ClientAuthErrorMessage.unexpectedAccountType.code, `${ClientAuthErrorMessage.unexpectedAccountType.desc}`);
  }
  /**
   * Throws error if unexpected credential type.
   */


  static createUnexpectedCredentialTypeError() {
    return new ClientAuthError(ClientAuthErrorMessage.unexpectedCredentialType.code, `${ClientAuthErrorMessage.unexpectedCredentialType.desc}`);
  }
  /**
   * Throws error if client assertion is not valid.
   */


  static createInvalidAssertionError() {
    return new ClientAuthError(ClientAuthErrorMessage.invalidAssertion.code, `${ClientAuthErrorMessage.invalidAssertion.desc}`);
  }
  /**
   * Throws error if client assertion is not valid.
   */


  static createInvalidCredentialError() {
    return new ClientAuthError(ClientAuthErrorMessage.invalidClientCredential.code, `${ClientAuthErrorMessage.invalidClientCredential.desc}`);
  }
  /**
   * Throws error if token cannot be retrieved from cache due to refresh being required.
   */


  static createRefreshRequiredError() {
    return new ClientAuthError(ClientAuthErrorMessage.tokenRefreshRequired.code, ClientAuthErrorMessage.tokenRefreshRequired.desc);
  }
  /**
   * Throws error if the user defined timeout is reached.
   */


  static createUserTimeoutReachedError() {
    return new ClientAuthError(ClientAuthErrorMessage.userTimeoutReached.code, ClientAuthErrorMessage.userTimeoutReached.desc);
  }
  /*
   * Throws error if token claims are not populated for a signed jwt generation
   */


  static createTokenClaimsRequiredError() {
    return new ClientAuthError(ClientAuthErrorMessage.tokenClaimsRequired.code, ClientAuthErrorMessage.tokenClaimsRequired.desc);
  }
  /**
   * Throws error when the authorization code is missing from the server response
   */


  static createNoAuthCodeInServerResponseError() {
    return new ClientAuthError(ClientAuthErrorMessage.noAuthorizationCodeFromServer.code, ClientAuthErrorMessage.noAuthorizationCodeFromServer.desc);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * @hidden
 */

class StringUtils {
  /**
   * decode a JWT
   *
   * @param authToken
   */
  static decodeAuthToken(authToken) {
    if (StringUtils.isEmpty(authToken)) {
      throw ClientAuthError.createTokenNullOrEmptyError(authToken);
    }

    const tokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;
    const matches = tokenPartsRegex.exec(authToken);

    if (!matches || matches.length < 4) {
      throw ClientAuthError.createTokenParsingError(`Given token is malformed: ${JSON.stringify(authToken)}`);
    }

    const crackedToken = {
      header: matches[1],
      JWSPayload: matches[2],
      JWSSig: matches[3]
    };
    return crackedToken;
  }
  /**
   * Check if a string is empty.
   *
   * @param str
   */


  static isEmpty(str) {
    return typeof str === "undefined" || !str || 0 === str.length;
  }
  /**
   * Check if stringified object is empty
   * @param strObj
   */


  static isEmptyObj(strObj) {
    if (strObj && !StringUtils.isEmpty(strObj)) {
      try {
        const obj = JSON.parse(strObj);
        return Object.keys(obj).length === 0;
      } catch (e) {}
    }

    return true;
  }

  static startsWith(str, search) {
    return str.indexOf(search) === 0;
  }

  static endsWith(str, search) {
    return str.length >= search.length && str.lastIndexOf(search) === str.length - search.length;
  }
  /**
   * Parses string into an object.
   *
   * @param query
   */


  static queryStringToObject(query) {
    let match; // Regex for replacing addition symbol with a space

    const pl = /\+/g;
    const search = /([^&=]+)=([^&]*)/g;

    const decode = s => decodeURIComponent(decodeURIComponent(s.replace(pl, " ")));

    const obj = {};
    match = search.exec(query);

    while (match) {
      obj[decode(match[1])] = decode(match[2]);
      match = search.exec(query);
    }

    return obj;
  }
  /**
   * Trims entries in an array.
   *
   * @param arr
   */


  static trimArrayEntries(arr) {
    return arr.map(entry => entry.trim());
  }
  /**
   * Removes empty strings from array
   * @param arr
   */


  static removeEmptyStringsFromArray(arr) {
    return arr.filter(entry => {
      return !StringUtils.isEmpty(entry);
    });
  }
  /**
   * Attempts to parse a string into JSON
   * @param str
   */


  static jsonParseHelper(str) {
    try {
      return JSON.parse(str);
    } catch (e) {
      return null;
    }
  }
  /**
   * Tests if a given string matches a given pattern, with support for wildcards and queries.
   * @param pattern Wildcard pattern to string match. Supports "*" for wildcards and "?" for queries
   * @param input String to match against
   */


  static matchPattern(pattern, input) {
    /**
     * Wildcard support: https://stackoverflow.com/a/3117248/4888559
     * Queries: replaces "?" in string with escaped "\?" for regex test
     */
    const regex = new RegExp(pattern.replace(/\*/g, "[^ ]*").replace(/\?/g, "\\\?"));
    return regex.test(input);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Log message level.
 */

var LogLevel;

(function (LogLevel) {
  LogLevel[LogLevel["Error"] = 0] = "Error";
  LogLevel[LogLevel["Warning"] = 1] = "Warning";
  LogLevel[LogLevel["Info"] = 2] = "Info";
  LogLevel[LogLevel["Verbose"] = 3] = "Verbose";
  LogLevel[LogLevel["Trace"] = 4] = "Trace";
})(LogLevel || (LogLevel = {}));
/**
 * Class which facilitates logging of messages to a specific place.
 */


class Logger {
  constructor(loggerOptions, packageName, packageVersion) {
    // Current log level, defaults to info.
    this.level = LogLevel.Info;

    const defaultLoggerCallback = () => {};

    this.localCallback = loggerOptions.loggerCallback || defaultLoggerCallback;
    this.piiLoggingEnabled = loggerOptions.piiLoggingEnabled || false;
    this.level = loggerOptions.logLevel || LogLevel.Info;
    this.packageName = packageName || Constants.EMPTY_STRING;
    this.packageVersion = packageVersion || Constants.EMPTY_STRING;
  }
  /**
   * Create new Logger with existing configurations.
   */


  clone(packageName, packageVersion) {
    return new Logger({
      loggerCallback: this.localCallback,
      piiLoggingEnabled: this.piiLoggingEnabled,
      logLevel: this.level
    }, packageName, packageVersion);
  }
  /**
   * Log message with required options.
   */


  logMessage(logMessage, options) {
    if (options.logLevel > this.level || !this.piiLoggingEnabled && options.containsPii) {
      return;
    }

    const timestamp = new Date().toUTCString();
    const logHeader = StringUtils.isEmpty(this.correlationId) ? `[${timestamp}] : ` : `[${timestamp}] : [${this.correlationId}]`;
    const log = `${logHeader} : ${this.packageName}@${this.packageVersion} : ${LogLevel[options.logLevel]} - ${logMessage}`; // debug(`msal:${LogLevel[options.logLevel]}${options.containsPii ? "-Pii": ""}${options.context ? `:${options.context}` : ""}`)(logMessage);

    this.executeCallback(options.logLevel, log, options.containsPii || false);
  }
  /**
   * Execute callback with message.
   */


  executeCallback(level, message, containsPii) {
    if (this.localCallback) {
      this.localCallback(level, message, containsPii);
    }
  }
  /**
   * Logs error messages.
   */


  error(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Error,
      containsPii: false,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs error messages with PII.
   */


  errorPii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Error,
      containsPii: true,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs warning messages.
   */


  warning(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Warning,
      containsPii: false,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs warning messages with PII.
   */


  warningPii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Warning,
      containsPii: true,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs info messages.
   */


  info(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Info,
      containsPii: false,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs info messages with PII.
   */


  infoPii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Info,
      containsPii: true,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs verbose messages.
   */


  verbose(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Verbose,
      containsPii: false,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs verbose messages with PII.
   */


  verbosePii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Verbose,
      containsPii: true,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs trace messages.
   */


  trace(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Trace,
      containsPii: false,
      correlationId: correlationId || ""
    });
  }
  /**
   * Logs trace messages with PII.
   */


  tracePii(message, correlationId) {
    this.logMessage(message, {
      logLevel: LogLevel.Trace,
      containsPii: true,
      correlationId: correlationId || ""
    });
  }
  /**
   * Returns whether PII Logging is enabled or not.
   */


  isPiiLoggingEnabled() {
    return this.piiLoggingEnabled || false;
  }

}

/* eslint-disable header/header */
const name$1 = "@azure/msal-common";
const version$1 = "4.3.0";

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Base type for credentials to be stored in the cache: eg: ACCESS_TOKEN, ID_TOKEN etc
 *
 * Key:Value Schema:
 *
 * Key: <home_account_id*>-<environment>-<credential_type>-<client_id>-<realm*>-<target*>
 *
 * Value Schema:
 * {
 *      homeAccountId: home account identifier for the auth scheme,
 *      environment: entity that issued the token, represented as a full host
 *      credentialType: Type of credential as a string, can be one of the following: RefreshToken, AccessToken, IdToken, Password, Cookie, Certificate, Other
 *      clientId: client ID of the application
 *      secret: Actual credential as a string
 *      familyId: Family ID identifier, usually only used for refresh tokens
 *      realm: Full tenant or organizational identifier that the account belongs to
 *      target: Permissions that are included in the token, or for refresh tokens, the resource identifier.
 *      oboAssertion: access token passed in as part of OBO request
 * }
 */

class CredentialEntity {
  /**
   * Generate Account Id key component as per the schema: <home_account_id>-<environment>
   */
  generateAccountId() {
    return CredentialEntity.generateAccountIdForCacheKey(this.homeAccountId, this.environment);
  }
  /**
   * Generate Credential Id key component as per the schema: <credential_type>-<client_id>-<realm>
   */


  generateCredentialId() {
    return CredentialEntity.generateCredentialIdForCacheKey(this.credentialType, this.clientId, this.realm, this.familyId);
  }
  /**
   * Generate target key component as per schema: <target>
   */


  generateTarget() {
    return CredentialEntity.generateTargetForCacheKey(this.target);
  }
  /**
   * generates credential key
   */


  generateCredentialKey() {
    return CredentialEntity.generateCredentialCacheKey(this.homeAccountId, this.environment, this.credentialType, this.clientId, this.realm, this.target, this.familyId);
  }
  /**
   * returns the type of the cache (in this case credential)
   */


  generateType() {
    switch (this.credentialType) {
      case CredentialType.ID_TOKEN:
        return CacheType.ID_TOKEN;

      case CredentialType.ACCESS_TOKEN:
        return CacheType.ACCESS_TOKEN;

      case CredentialType.REFRESH_TOKEN:
        return CacheType.REFRESH_TOKEN;

      default:
        {
          throw ClientAuthError.createUnexpectedCredentialTypeError();
        }
    }
  }
  /**
   * helper function to return `CredentialType`
   * @param key
   */


  static getCredentialType(key) {
    // First keyword search will match all "AccessToken" and "AccessToken_With_AuthScheme" credentials
    if (key.indexOf(CredentialType.ACCESS_TOKEN.toLowerCase()) !== -1) {
      // Perform second search to differentiate between "AccessToken" and "AccessToken_With_AuthScheme" credential types
      if (key.indexOf(CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME.toLowerCase()) !== -1) {
        return CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME;
      }

      return CredentialType.ACCESS_TOKEN;
    } else if (key.indexOf(CredentialType.ID_TOKEN.toLowerCase()) !== -1) {
      return CredentialType.ID_TOKEN;
    } else if (key.indexOf(CredentialType.REFRESH_TOKEN.toLowerCase()) !== -1) {
      return CredentialType.REFRESH_TOKEN;
    }

    return Constants.NOT_DEFINED;
  }
  /**
   * generates credential key
   */


  static generateCredentialCacheKey(homeAccountId, environment, credentialType, clientId, realm, target, familyId) {
    const credentialKey = [this.generateAccountIdForCacheKey(homeAccountId, environment), this.generateCredentialIdForCacheKey(credentialType, clientId, realm, familyId), this.generateTargetForCacheKey(target)];
    return credentialKey.join(Separators.CACHE_KEY_SEPARATOR).toLowerCase();
  }
  /**
   * generates Account Id for keys
   * @param homeAccountId
   * @param environment
   */


  static generateAccountIdForCacheKey(homeAccountId, environment) {
    const accountId = [homeAccountId, environment];
    return accountId.join(Separators.CACHE_KEY_SEPARATOR).toLowerCase();
  }
  /**
   * Generates Credential Id for keys
   * @param credentialType
   * @param realm
   * @param clientId
   * @param familyId
   */


  static generateCredentialIdForCacheKey(credentialType, clientId, realm, familyId) {
    const clientOrFamilyId = credentialType === CredentialType.REFRESH_TOKEN ? familyId || clientId : clientId;
    const credentialId = [credentialType, clientOrFamilyId, realm || ""];
    return credentialId.join(Separators.CACHE_KEY_SEPARATOR).toLowerCase();
  }
  /**
   * Generate target key component as per schema: <target>
   */


  static generateTargetForCacheKey(scopes) {
    return (scopes || "").toLowerCase();
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * ClientConfigurationErrorMessage class containing string constants used by error codes and messages.
 */

const ClientConfigurationErrorMessage = {
  redirectUriNotSet: {
    code: "redirect_uri_empty",
    desc: "A redirect URI is required for all calls, and none has been set."
  },
  postLogoutUriNotSet: {
    code: "post_logout_uri_empty",
    desc: "A post logout redirect has not been set."
  },
  claimsRequestParsingError: {
    code: "claims_request_parsing_error",
    desc: "Could not parse the given claims request object."
  },
  authorityUriInsecure: {
    code: "authority_uri_insecure",
    desc: "Authority URIs must use https.  Please see here for valid authority configuration options: https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-js-initializing-client-applications#configuration-options"
  },
  urlParseError: {
    code: "url_parse_error",
    desc: "URL could not be parsed into appropriate segments."
  },
  urlEmptyError: {
    code: "empty_url_error",
    desc: "URL was empty or null."
  },
  emptyScopesError: {
    code: "empty_input_scopes_error",
    desc: "Scopes cannot be passed as null, undefined or empty array because they are required to obtain an access token."
  },
  nonArrayScopesError: {
    code: "nonarray_input_scopes_error",
    desc: "Scopes cannot be passed as non-array."
  },
  clientIdSingleScopeError: {
    code: "clientid_input_scopes_error",
    desc: "Client ID can only be provided as a single scope."
  },
  invalidPrompt: {
    code: "invalid_prompt_value",
    desc: "Supported prompt values are 'login', 'select_account', 'consent' and 'none'.  Please see here for valid configuration options: https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-js-initializing-client-applications#configuration-options"
  },
  invalidClaimsRequest: {
    code: "invalid_claims",
    desc: "Given claims parameter must be a stringified JSON object."
  },
  tokenRequestEmptyError: {
    code: "token_request_empty",
    desc: "Token request was empty and not found in cache."
  },
  logoutRequestEmptyError: {
    code: "logout_request_empty",
    desc: "The logout request was null or undefined."
  },
  invalidCodeChallengeMethod: {
    code: "invalid_code_challenge_method",
    desc: "code_challenge_method passed is invalid. Valid values are \"plain\" and \"S256\"."
  },
  invalidCodeChallengeParams: {
    code: "pkce_params_missing",
    desc: "Both params: code_challenge and code_challenge_method are to be passed if to be sent in the request"
  },
  invalidCloudDiscoveryMetadata: {
    code: "invalid_cloud_discovery_metadata",
    desc: "Invalid cloudDiscoveryMetadata provided. Must be a JSON object containing tenant_discovery_endpoint and metadata fields"
  },
  invalidAuthorityMetadata: {
    code: "invalid_authority_metadata",
    desc: "Invalid authorityMetadata provided. Must by a JSON object containing authorization_endpoint, token_endpoint, end_session_endpoint, issuer fields."
  },
  untrustedAuthority: {
    code: "untrusted_authority",
    desc: "The provided authority is not a trusted authority. Please include this authority in the knownAuthorities config parameter."
  }
};
/**
 * Error thrown when there is an error in configuration of the MSAL.js library.
 */

class ClientConfigurationError extends ClientAuthError {
  constructor(errorCode, errorMessage) {
    super(errorCode, errorMessage);
    this.name = "ClientConfigurationError";
    Object.setPrototypeOf(this, ClientConfigurationError.prototype);
  }
  /**
   * Creates an error thrown when the redirect uri is empty (not set by caller)
   */


  static createRedirectUriEmptyError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.redirectUriNotSet.code, ClientConfigurationErrorMessage.redirectUriNotSet.desc);
  }
  /**
   * Creates an error thrown when the post-logout redirect uri is empty (not set by caller)
   */


  static createPostLogoutRedirectUriEmptyError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.postLogoutUriNotSet.code, ClientConfigurationErrorMessage.postLogoutUriNotSet.desc);
  }
  /**
   * Creates an error thrown when the claims request could not be successfully parsed
   */


  static createClaimsRequestParsingError(claimsRequestParseError) {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.claimsRequestParsingError.code, `${ClientConfigurationErrorMessage.claimsRequestParsingError.desc} Given value: ${claimsRequestParseError}`);
  }
  /**
   * Creates an error thrown if authority uri is given an insecure protocol.
   * @param urlString
   */


  static createInsecureAuthorityUriError(urlString) {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.authorityUriInsecure.code, `${ClientConfigurationErrorMessage.authorityUriInsecure.desc} Given URI: ${urlString}`);
  }
  /**
   * Creates an error thrown if URL string does not parse into separate segments.
   * @param urlString
   */


  static createUrlParseError(urlParseError) {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.urlParseError.code, `${ClientConfigurationErrorMessage.urlParseError.desc} Given Error: ${urlParseError}`);
  }
  /**
   * Creates an error thrown if URL string is empty or null.
   * @param urlString
   */


  static createUrlEmptyError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.urlEmptyError.code, ClientConfigurationErrorMessage.urlEmptyError.desc);
  }
  /**
   * Error thrown when scopes are not an array
   * @param inputScopes
   */


  static createScopesNonArrayError(inputScopes) {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.nonArrayScopesError.code, `${ClientConfigurationErrorMessage.nonArrayScopesError.desc} Given Scopes: ${inputScopes}`);
  }
  /**
   * Error thrown when scopes are empty.
   * @param scopesValue
   */


  static createEmptyScopesArrayError(inputScopes) {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.emptyScopesError.code, `${ClientConfigurationErrorMessage.emptyScopesError.desc} Given Scopes: ${inputScopes}`);
  }
  /**
   * Error thrown when client id scope is not provided as single scope.
   * @param inputScopes
   */


  static createClientIdSingleScopeError(inputScopes) {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.clientIdSingleScopeError.code, `${ClientConfigurationErrorMessage.clientIdSingleScopeError.desc} Given Scopes: ${inputScopes}`);
  }
  /**
   * Error thrown when prompt is not an allowed type.
   * @param promptValue
   */


  static createInvalidPromptError(promptValue) {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.invalidPrompt.code, `${ClientConfigurationErrorMessage.invalidPrompt.desc} Given value: ${promptValue}`);
  }
  /**
   * Creates error thrown when claims parameter is not a stringified JSON object
   */


  static createInvalidClaimsRequestError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.invalidClaimsRequest.code, ClientConfigurationErrorMessage.invalidClaimsRequest.desc);
  }
  /**
   * Throws error when token request is empty and nothing cached in storage.
   */


  static createEmptyLogoutRequestError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.logoutRequestEmptyError.code, ClientConfigurationErrorMessage.logoutRequestEmptyError.desc);
  }
  /**
   * Throws error when token request is empty and nothing cached in storage.
   */


  static createEmptyTokenRequestError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.tokenRequestEmptyError.code, ClientConfigurationErrorMessage.tokenRequestEmptyError.desc);
  }
  /**
   * Throws error when an invalid code_challenge_method is passed by the user
   */


  static createInvalidCodeChallengeMethodError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.invalidCodeChallengeMethod.code, ClientConfigurationErrorMessage.invalidCodeChallengeMethod.desc);
  }
  /**
   * Throws error when both params: code_challenge and code_challenge_method are not passed together
   */


  static createInvalidCodeChallengeParamsError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.invalidCodeChallengeParams.code, ClientConfigurationErrorMessage.invalidCodeChallengeParams.desc);
  }
  /**
   * Throws an error when the user passes invalid cloudDiscoveryMetadata
   */


  static createInvalidCloudDiscoveryMetadataError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.invalidCloudDiscoveryMetadata.code, ClientConfigurationErrorMessage.invalidCloudDiscoveryMetadata.desc);
  }
  /**
   * Throws an error when the user passes invalid cloudDiscoveryMetadata
   */


  static createInvalidAuthorityMetadataError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.invalidAuthorityMetadata.code, ClientConfigurationErrorMessage.invalidAuthorityMetadata.desc);
  }
  /**
   * Throws error when provided authority is not a member of the trusted host list
   */


  static createUntrustedAuthorityError() {
    return new ClientConfigurationError(ClientConfigurationErrorMessage.untrustedAuthority.code, ClientConfigurationErrorMessage.untrustedAuthority.desc);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * The ScopeSet class creates a set of scopes. Scopes are case-insensitive, unique values, so the Set object in JS makes
 * the most sense to implement for this class. All scopes are trimmed and converted to lower case strings in intersection and union functions
 * to ensure uniqueness of strings.
 */

class ScopeSet {
  constructor(inputScopes) {
    // Filter empty string and null/undefined array items
    const scopeArr = inputScopes ? StringUtils.trimArrayEntries([...inputScopes]) : [];
    const filteredInput = scopeArr ? StringUtils.removeEmptyStringsFromArray(scopeArr) : []; // Validate and filter scopes (validate function throws if validation fails)

    this.validateInputScopes(filteredInput);
    this.scopes = new Set(); // Iterator in constructor not supported by IE11

    filteredInput.forEach(scope => this.scopes.add(scope));
  }
  /**
   * Factory method to create ScopeSet from space-delimited string
   * @param inputScopeString
   * @param appClientId
   * @param scopesRequired
   */


  static fromString(inputScopeString) {
    inputScopeString = inputScopeString || "";
    const inputScopes = inputScopeString.split(" ");
    return new ScopeSet(inputScopes);
  }
  /**
   * Used to validate the scopes input parameter requested  by the developer.
   * @param {Array<string>} inputScopes - Developer requested permissions. Not all scopes are guaranteed to be included in the access token returned.
   * @param {boolean} scopesRequired - Boolean indicating whether the scopes array is required or not
   */


  validateInputScopes(inputScopes) {
    // Check if scopes are required but not given or is an empty array
    if (!inputScopes || inputScopes.length < 1) {
      throw ClientConfigurationError.createEmptyScopesArrayError(inputScopes);
    }
  }
  /**
   * Check if a given scope is present in this set of scopes.
   * @param scope
   */


  containsScope(scope) {
    const lowerCaseScopes = this.printScopesLowerCase().split(" ");
    const lowerCaseScopesSet = new ScopeSet(lowerCaseScopes); // compare lowercase scopes

    return !StringUtils.isEmpty(scope) ? lowerCaseScopesSet.scopes.has(scope.toLowerCase()) : false;
  }
  /**
   * Check if a set of scopes is present in this set of scopes.
   * @param scopeSet
   */


  containsScopeSet(scopeSet) {
    if (!scopeSet || scopeSet.scopes.size <= 0) {
      return false;
    }

    return this.scopes.size >= scopeSet.scopes.size && scopeSet.asArray().every(scope => this.containsScope(scope));
  }
  /**
   * Check if set of scopes contains only the defaults
   */


  containsOnlyOIDCScopes() {
    let defaultScopeCount = 0;
    OIDC_SCOPES.forEach(defaultScope => {
      if (this.containsScope(defaultScope)) {
        defaultScopeCount += 1;
      }
    });
    return this.scopes.size === defaultScopeCount;
  }
  /**
   * Appends single scope if passed
   * @param newScope
   */


  appendScope(newScope) {
    if (!StringUtils.isEmpty(newScope)) {
      this.scopes.add(newScope.trim());
    }
  }
  /**
   * Appends multiple scopes if passed
   * @param newScopes
   */


  appendScopes(newScopes) {
    try {
      newScopes.forEach(newScope => this.appendScope(newScope));
    } catch (e) {
      throw ClientAuthError.createAppendScopeSetError(e);
    }
  }
  /**
   * Removes element from set of scopes.
   * @param scope
   */


  removeScope(scope) {
    if (StringUtils.isEmpty(scope)) {
      throw ClientAuthError.createRemoveEmptyScopeFromSetError(scope);
    }

    this.scopes.delete(scope.trim());
  }
  /**
   * Removes default scopes from set of scopes
   * Primarily used to prevent cache misses if the default scopes are not returned from the server
   */


  removeOIDCScopes() {
    OIDC_SCOPES.forEach(defaultScope => {
      this.scopes.delete(defaultScope);
    });
  }
  /**
   * Combines an array of scopes with the current set of scopes.
   * @param otherScopes
   */


  unionScopeSets(otherScopes) {
    if (!otherScopes) {
      throw ClientAuthError.createEmptyInputScopeSetError(otherScopes);
    }

    const unionScopes = new Set(); // Iterator in constructor not supported in IE11

    otherScopes.scopes.forEach(scope => unionScopes.add(scope.toLowerCase()));
    this.scopes.forEach(scope => unionScopes.add(scope.toLowerCase()));
    return unionScopes;
  }
  /**
   * Check if scopes intersect between this set and another.
   * @param otherScopes
   */


  intersectingScopeSets(otherScopes) {
    if (!otherScopes) {
      throw ClientAuthError.createEmptyInputScopeSetError(otherScopes);
    } // Do not allow OIDC scopes to be the only intersecting scopes


    if (!otherScopes.containsOnlyOIDCScopes()) {
      otherScopes.removeOIDCScopes();
    }

    const unionScopes = this.unionScopeSets(otherScopes);
    const sizeOtherScopes = otherScopes.getScopeCount();
    const sizeThisScopes = this.getScopeCount();
    const sizeUnionScopes = unionScopes.size;
    return sizeUnionScopes < sizeThisScopes + sizeOtherScopes;
  }
  /**
   * Returns size of set of scopes.
   */


  getScopeCount() {
    return this.scopes.size;
  }
  /**
   * Returns the scopes as an array of string values
   */


  asArray() {
    const array = [];
    this.scopes.forEach(val => array.push(val));
    return array;
  }
  /**
   * Prints scopes into a space-delimited string
   */


  printScopes() {
    if (this.scopes) {
      const scopeArr = this.asArray();
      return scopeArr.join(" ");
    }

    return "";
  }
  /**
   * Prints scopes into a space-delimited lower-case string (used for caching)
   */


  printScopesLowerCase() {
    return this.printScopes().toLowerCase();
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Function to build a client info object
 * @param rawClientInfo
 * @param crypto
 */

function buildClientInfo(rawClientInfo, crypto) {
  if (StringUtils.isEmpty(rawClientInfo)) {
    throw ClientAuthError.createClientInfoEmptyError();
  }

  try {
    const decodedClientInfo = crypto.base64Decode(rawClientInfo);
    return JSON.parse(decodedClientInfo);
  } catch (e) {
    throw ClientAuthError.createClientInfoDecodingError(e);
  }
}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

/**
 * Authority types supported by MSAL.
 */
var AuthorityType;

(function (AuthorityType) {
  AuthorityType[AuthorityType["Default"] = 0] = "Default";
  AuthorityType[AuthorityType["Adfs"] = 1] = "Adfs";
})(AuthorityType || (AuthorityType = {}));

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Type that defines required and optional parameters for an Account field (based on universal cache schema implemented by all MSALs).
 *
 * Key : Value Schema
 *
 * Key: <home_account_id>-<environment>-<realm*>
 *
 * Value Schema:
 * {
 *      homeAccountId: home account identifier for the auth scheme,
 *      environment: entity that issued the token, represented as a full host
 *      realm: Full tenant or organizational identifier that the account belongs to
 *      localAccountId: Original tenant-specific accountID, usually used for legacy cases
 *      username: primary username that represents the user, usually corresponds to preferred_username in the v2 endpt
 *      authorityType: Accounts authority type as a string
 *      name: Full name for the account, including given name and family name,
 *      clientInfo: Full base64 encoded client info received from ESTS
 *      lastModificationTime: last time this entity was modified in the cache
 *      lastModificationApp:
 *      oboAssertion: access token passed in as part of OBO request
 *      idTokenClaims: Object containing claims parsed from ID token
 * }
 */

class AccountEntity {
  /**
   * Generate Account Id key component as per the schema: <home_account_id>-<environment>
   */
  generateAccountId() {
    const accountId = [this.homeAccountId, this.environment];
    return accountId.join(Separators.CACHE_KEY_SEPARATOR).toLowerCase();
  }
  /**
   * Generate Account Cache Key as per the schema: <home_account_id>-<environment>-<realm*>
   */


  generateAccountKey() {
    return AccountEntity.generateAccountCacheKey({
      homeAccountId: this.homeAccountId,
      environment: this.environment,
      tenantId: this.realm,
      username: this.username,
      localAccountId: this.localAccountId
    });
  }
  /**
   * returns the type of the cache (in this case account)
   */


  generateType() {
    switch (this.authorityType) {
      case CacheAccountType.ADFS_ACCOUNT_TYPE:
        return CacheType.ADFS;

      case CacheAccountType.MSAV1_ACCOUNT_TYPE:
        return CacheType.MSA;

      case CacheAccountType.MSSTS_ACCOUNT_TYPE:
        return CacheType.MSSTS;

      case CacheAccountType.GENERIC_ACCOUNT_TYPE:
        return CacheType.GENERIC;

      default:
        {
          throw ClientAuthError.createUnexpectedAccountTypeError();
        }
    }
  }
  /**
   * Returns the AccountInfo interface for this account.
   */


  getAccountInfo() {
    return {
      homeAccountId: this.homeAccountId,
      environment: this.environment,
      tenantId: this.realm,
      username: this.username,
      localAccountId: this.localAccountId,
      name: this.name,
      idTokenClaims: this.idTokenClaims
    };
  }
  /**
   * Generates account key from interface
   * @param accountInterface
   */


  static generateAccountCacheKey(accountInterface) {
    const accountKey = [accountInterface.homeAccountId, accountInterface.environment || "", accountInterface.tenantId || ""];
    return accountKey.join(Separators.CACHE_KEY_SEPARATOR).toLowerCase();
  }
  /**
   * Build Account cache from IdToken, clientInfo and authority/policy. Associated with AAD.
   * @param clientInfo
   * @param authority
   * @param idToken
   * @param policy
   */


  static createAccount(clientInfo, homeAccountId, authority, idToken, oboAssertion, cloudGraphHostName, msGraphHost) {
    const account = new AccountEntity();
    account.authorityType = CacheAccountType.MSSTS_ACCOUNT_TYPE;
    account.clientInfo = clientInfo;
    account.homeAccountId = homeAccountId;
    const env = authority.getPreferredCache();

    if (StringUtils.isEmpty(env)) {
      throw ClientAuthError.createInvalidCacheEnvironmentError();
    }

    account.environment = env; // non AAD scenarios can have empty realm

    account.realm = idToken?.claims?.tid || "";
    account.oboAssertion = oboAssertion;

    if (idToken) {
      account.idTokenClaims = idToken.claims; // How do you account for MSA CID here?

      account.localAccountId = idToken?.claims?.oid || idToken?.claims?.sub || "";
      /*
       * In B2C scenarios the emails claim is used instead of preferred_username and it is an array. In most cases it will contain a single email.
       * This field should not be relied upon if a custom policy is configured to return more than 1 email.
       */

      account.username = idToken?.claims?.preferred_username || (idToken?.claims?.emails ? idToken.claims.emails[0] : "");
      account.name = idToken?.claims?.name;
    }

    account.cloudGraphHostName = cloudGraphHostName;
    account.msGraphHost = msGraphHost;
    return account;
  }
  /**
   * Builds non-AAD/ADFS account.
   * @param authority
   * @param idToken
   */


  static createGenericAccount(authority, homeAccountId, idToken, oboAssertion, cloudGraphHostName, msGraphHost) {
    const account = new AccountEntity();
    account.authorityType = authority.authorityType === AuthorityType.Adfs ? CacheAccountType.ADFS_ACCOUNT_TYPE : CacheAccountType.GENERIC_ACCOUNT_TYPE;
    account.homeAccountId = homeAccountId; // non AAD scenarios can have empty realm

    account.realm = "";
    account.oboAssertion = oboAssertion;
    const env = authority.getPreferredCache();

    if (StringUtils.isEmpty(env)) {
      throw ClientAuthError.createInvalidCacheEnvironmentError();
    }

    if (idToken) {
      // How do you account for MSA CID here?
      account.localAccountId = idToken?.claims?.oid || idToken?.claims?.sub || ""; // upn claim for most ADFS scenarios

      account.username = idToken?.claims?.upn || "";
      account.name = idToken?.claims?.name || "";
      account.idTokenClaims = idToken?.claims;
    }

    account.environment = env;
    account.cloudGraphHostName = cloudGraphHostName;
    account.msGraphHost = msGraphHost;
    /*
     * add uniqueName to claims
     * account.name = idToken.claims.uniqueName;
     */

    return account;
  }
  /**
   * Generate HomeAccountId from server response
   * @param serverClientInfo
   * @param authType
   */


  static generateHomeAccountId(serverClientInfo, authType, logger, cryptoObj, idToken) {
    const accountId = idToken?.claims?.sub ? idToken.claims.sub : Constants.EMPTY_STRING; // since ADFS does not have tid and does not set client_info

    if (authType === AuthorityType.Adfs) {
      return accountId;
    } // for cases where there is clientInfo


    if (serverClientInfo) {
      const clientInfo = buildClientInfo(serverClientInfo, cryptoObj);

      if (!StringUtils.isEmpty(clientInfo.uid) && !StringUtils.isEmpty(clientInfo.utid)) {
        return `${clientInfo.uid}${Separators.CLIENT_INFO_SEPARATOR}${clientInfo.utid}`;
      }
    } // default to "sub" claim


    logger.verbose("No client info in response");
    return accountId;
  }
  /**
   * Validates an entity: checks for all expected params
   * @param entity
   */


  static isAccountEntity(entity) {
    if (!entity) {
      return false;
    }

    return entity.hasOwnProperty("homeAccountId") && entity.hasOwnProperty("environment") && entity.hasOwnProperty("realm") && entity.hasOwnProperty("localAccountId") && entity.hasOwnProperty("username") && entity.hasOwnProperty("authorityType");
  }
  /**
   * Helper function to determine whether 2 accountInfo objects represent the same account
   * @param accountA
   * @param accountB
   * @param compareClaims - If set to true idTokenClaims will also be compared to determine account equality
   */


  static accountInfoIsEqual(accountA, accountB, compareClaims) {
    if (!accountA || !accountB) {
      return false;
    }

    let claimsMatch = true; // default to true so as to not fail comparison below if compareClaims: false

    if (compareClaims) {
      const accountAClaims = accountA.idTokenClaims || {};
      const accountBClaims = accountB.idTokenClaims || {}; // issued at timestamp and nonce are expected to change each time a new id token is acquired

      claimsMatch = accountAClaims.iat === accountBClaims.iat && accountAClaims.nonce === accountBClaims.nonce;
    }

    return accountA.homeAccountId === accountB.homeAccountId && accountA.localAccountId === accountB.localAccountId && accountA.username === accountB.username && accountA.tenantId === accountB.tenantId && accountA.environment === accountB.environment && claimsMatch;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * JWT Token representation class. Parses token string and generates claims object.
 */

class AuthToken {
  constructor(rawToken, crypto) {
    if (StringUtils.isEmpty(rawToken)) {
      throw ClientAuthError.createTokenNullOrEmptyError(rawToken);
    }

    this.rawToken = rawToken;
    this.claims = AuthToken.extractTokenClaims(rawToken, crypto);
  }
  /**
   * Extract token by decoding the rawToken
   *
   * @param encodedToken
   */


  static extractTokenClaims(encodedToken, crypto) {
    const decodedToken = StringUtils.decodeAuthToken(encodedToken); // token will be decoded to get the username

    try {
      const base64TokenPayload = decodedToken.JWSPayload; // base64Decode() should throw an error if there is an issue

      const base64Decoded = crypto.base64Decode(base64TokenPayload);
      return JSON.parse(base64Decoded);
    } catch (err) {
      throw ClientAuthError.createTokenParsingError(err);
    }
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Interface class which implement cache storage functions used by MSAL to perform validity checks, and store tokens.
 */

class CacheManager {
  constructor(clientId, cryptoImpl) {
    this.clientId = clientId;
    this.cryptoImpl = cryptoImpl;
  }

  /**
   * Returns all accounts in cache
   */
  getAllAccounts() {
    const currentAccounts = this.getAccountsFilteredBy();
    const accountValues = Object.keys(currentAccounts).map(accountKey => currentAccounts[accountKey]);
    const numAccounts = accountValues.length;

    if (numAccounts < 1) {
      return [];
    } else {
      const allAccounts = accountValues.map(value => {
        const accountEntity = CacheManager.toObject(new AccountEntity(), value);
        const accountInfo = accountEntity.getAccountInfo();
        const idToken = this.readIdTokenFromCache(this.clientId, accountInfo);

        if (idToken && !accountInfo.idTokenClaims) {
          accountInfo.idTokenClaims = new AuthToken(idToken.secret, this.cryptoImpl).claims;
        }

        return accountInfo;
      });
      return allAccounts;
    }
  }
  /**
   * saves a cache record
   * @param cacheRecord
   */


  saveCacheRecord(cacheRecord) {
    if (!cacheRecord) {
      throw ClientAuthError.createNullOrUndefinedCacheRecord();
    }

    if (!!cacheRecord.account) {
      this.setAccount(cacheRecord.account);
    }

    if (!!cacheRecord.idToken) {
      this.setIdTokenCredential(cacheRecord.idToken);
    }

    if (!!cacheRecord.accessToken) {
      this.saveAccessToken(cacheRecord.accessToken);
    }

    if (!!cacheRecord.refreshToken) {
      this.setRefreshTokenCredential(cacheRecord.refreshToken);
    }

    if (!!cacheRecord.appMetadata) {
      this.setAppMetadata(cacheRecord.appMetadata);
    }
  }
  /**
   * saves access token credential
   * @param credential
   */


  saveAccessToken(credential) {
    const currentTokenCache = this.getCredentialsFilteredBy({
      clientId: credential.clientId,
      credentialType: credential.credentialType,
      environment: credential.environment,
      homeAccountId: credential.homeAccountId,
      realm: credential.realm
    });
    const currentScopes = ScopeSet.fromString(credential.target);
    const currentAccessTokens = Object.keys(currentTokenCache.accessTokens).map(key => currentTokenCache.accessTokens[key]);

    if (currentAccessTokens) {
      currentAccessTokens.forEach(tokenEntity => {
        const tokenScopeSet = ScopeSet.fromString(tokenEntity.target);

        if (tokenScopeSet.intersectingScopeSets(currentScopes)) {
          this.removeCredential(tokenEntity);
        }
      });
    }

    this.setAccessTokenCredential(credential);
  }
  /**
   * retrieve accounts matching all provided filters; if no filter is set, get all accounts
   * not checking for casing as keys are all generated in lower case, remember to convert to lower case if object properties are compared
   * @param homeAccountId
   * @param environment
   * @param realm
   */


  getAccountsFilteredBy(accountFilter) {
    return this.getAccountsFilteredByInternal(accountFilter ? accountFilter.homeAccountId : "", accountFilter ? accountFilter.environment : "", accountFilter ? accountFilter.realm : "");
  }
  /**
   * retrieve accounts matching all provided filters; if no filter is set, get all accounts
   * not checking for casing as keys are all generated in lower case, remember to convert to lower case if object properties are compared
   * @param homeAccountId
   * @param environment
   * @param realm
   */


  getAccountsFilteredByInternal(homeAccountId, environment, realm) {
    const allCacheKeys = this.getKeys();
    const matchingAccounts = {};
    allCacheKeys.forEach(cacheKey => {
      const entity = this.getAccount(cacheKey);

      if (!entity) {
        return;
      }

      if (!!homeAccountId && !this.matchHomeAccountId(entity, homeAccountId)) {
        return;
      }

      if (!!environment && !this.matchEnvironment(entity, environment)) {
        return;
      }

      if (!!realm && !this.matchRealm(entity, realm)) {
        return;
      }

      matchingAccounts[cacheKey] = entity;
    });
    return matchingAccounts;
  }
  /**
   * retrieve credentails matching all provided filters; if no filter is set, get all credentials
   * @param homeAccountId
   * @param environment
   * @param credentialType
   * @param clientId
   * @param realm
   * @param target
   */


  getCredentialsFilteredBy(filter) {
    return this.getCredentialsFilteredByInternal(filter.homeAccountId, filter.environment, filter.credentialType, filter.clientId, filter.familyId, filter.realm, filter.target, filter.oboAssertion);
  }
  /**
   * Support function to help match credentials
   * @param homeAccountId
   * @param environment
   * @param credentialType
   * @param clientId
   * @param realm
   * @param target
   */


  getCredentialsFilteredByInternal(homeAccountId, environment, credentialType, clientId, familyId, realm, target, oboAssertion) {
    const allCacheKeys = this.getKeys();
    const matchingCredentials = {
      idTokens: {},
      accessTokens: {},
      refreshTokens: {}
    };
    allCacheKeys.forEach(cacheKey => {
      // don't parse any non-credential type cache entities
      const credType = CredentialEntity.getCredentialType(cacheKey);

      if (credType === Constants.NOT_DEFINED) {
        return;
      } // Attempt retrieval


      const entity = this.getSpecificCredential(cacheKey, credType);

      if (!entity) {
        return;
      }

      if (!!oboAssertion && !this.matchOboAssertion(entity, oboAssertion)) {
        return;
      }

      if (!!homeAccountId && !this.matchHomeAccountId(entity, homeAccountId)) {
        return;
      }

      if (!!environment && !this.matchEnvironment(entity, environment)) {
        return;
      }

      if (!!realm && !this.matchRealm(entity, realm)) {
        return;
      }

      if (!!credentialType && !this.matchCredentialType(entity, credentialType)) {
        return;
      }

      if (!!clientId && !this.matchClientId(entity, clientId)) {
        return;
      }

      if (!!familyId && !this.matchFamilyId(entity, familyId)) {
        return;
      }
      /*
       * idTokens do not have "target", target specific refreshTokens do exist for some types of authentication
       * Resource specific refresh tokens case will be added when the support is deemed necessary
       */


      if (!!target && !this.matchTarget(entity, target)) {
        return;
      }

      switch (credType) {
        case CredentialType.ID_TOKEN:
          matchingCredentials.idTokens[cacheKey] = entity;
          break;

        case CredentialType.ACCESS_TOKEN:
        case CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME:
          matchingCredentials.accessTokens[cacheKey] = entity;
          break;

        case CredentialType.REFRESH_TOKEN:
          matchingCredentials.refreshTokens[cacheKey] = entity;
          break;
      }
    });
    return matchingCredentials;
  }
  /**
   * retrieve appMetadata matching all provided filters; if no filter is set, get all appMetadata
   * @param filter
   */


  getAppMetadataFilteredBy(filter) {
    return this.getAppMetadataFilteredByInternal(filter.environment, filter.clientId);
  }
  /**
   * Support function to help match appMetadata
   * @param environment
   * @param clientId
   */


  getAppMetadataFilteredByInternal(environment, clientId) {
    const allCacheKeys = this.getKeys();
    const matchingAppMetadata = {};
    allCacheKeys.forEach(cacheKey => {
      // don't parse any non-appMetadata type cache entities
      if (!this.isAppMetadata(cacheKey)) {
        return;
      } // Attempt retrieval


      const entity = this.getAppMetadata(cacheKey);

      if (!entity) {
        return;
      }

      if (!!environment && !this.matchEnvironment(entity, environment)) {
        return;
      }

      if (!!clientId && !this.matchClientId(entity, clientId)) {
        return;
      }

      matchingAppMetadata[cacheKey] = entity;
    });
    return matchingAppMetadata;
  }
  /**
   * retrieve authorityMetadata that contains a matching alias
   * @param filter
   */


  getAuthorityMetadataByAlias(host) {
    const allCacheKeys = this.getAuthorityMetadataKeys();
    let matchedEntity = null;
    allCacheKeys.forEach(cacheKey => {
      // don't parse any non-authorityMetadata type cache entities
      if (!this.isAuthorityMetadata(cacheKey) || cacheKey.indexOf(this.clientId) === -1) {
        return;
      } // Attempt retrieval


      const entity = this.getAuthorityMetadata(cacheKey);

      if (!entity) {
        return;
      }

      if (entity.aliases.indexOf(host) === -1) {
        return;
      }

      matchedEntity = entity;
    });
    return matchedEntity;
  }
  /**
   * Removes all accounts and related tokens from cache.
   */


  removeAllAccounts() {
    const allCacheKeys = this.getKeys();
    allCacheKeys.forEach(cacheKey => {
      const entity = this.getAccount(cacheKey);

      if (!entity) {
        return;
      }

      this.removeAccount(cacheKey);
    });
    return true;
  }
  /**
   * returns a boolean if the given account is removed
   * @param account
   */


  removeAccount(accountKey) {
    const account = this.getAccount(accountKey);

    if (!account) {
      throw ClientAuthError.createNoAccountFoundError();
    }

    return this.removeAccountContext(account) && this.removeItem(accountKey, CacheSchemaType.ACCOUNT);
  }
  /**
   * returns a boolean if the given account is removed
   * @param account
   */


  removeAccountContext(account) {
    const allCacheKeys = this.getKeys();
    const accountId = account.generateAccountId();
    allCacheKeys.forEach(cacheKey => {
      // don't parse any non-credential type cache entities
      const credType = CredentialEntity.getCredentialType(cacheKey);

      if (credType === Constants.NOT_DEFINED) {
        return;
      }

      const cacheEntity = this.getSpecificCredential(cacheKey, credType);

      if (!!cacheEntity && accountId === cacheEntity.generateAccountId()) {
        this.removeCredential(cacheEntity);
      }
    });
    return true;
  }
  /**
   * returns a boolean if the given credential is removed
   * @param credential
   */


  removeCredential(credential) {
    const key = credential.generateCredentialKey();
    return this.removeItem(key, CacheSchemaType.CREDENTIAL);
  }
  /**
   * Removes all app metadata objects from cache.
   */


  removeAppMetadata() {
    const allCacheKeys = this.getKeys();
    allCacheKeys.forEach(cacheKey => {
      if (this.isAppMetadata(cacheKey)) {
        this.removeItem(cacheKey, CacheSchemaType.APP_METADATA);
      }
    });
    return true;
  }
  /**
   * Retrieve the cached credentials into a cacherecord
   * @param account
   * @param clientId
   * @param scopes
   * @param environment
   * @param authScheme
   */


  readCacheRecord(account, clientId, scopes, environment, authScheme) {
    const cachedAccount = this.readAccountFromCache(account);
    const cachedIdToken = this.readIdTokenFromCache(clientId, account);
    const cachedAccessToken = this.readAccessTokenFromCache(clientId, account, scopes, authScheme);
    const cachedRefreshToken = this.readRefreshTokenFromCache(clientId, account, false);
    const cachedAppMetadata = this.readAppMetadataFromCache(environment, clientId);

    if (cachedAccount && cachedIdToken) {
      cachedAccount.idTokenClaims = new AuthToken(cachedIdToken.secret, this.cryptoImpl).claims;
    }

    return {
      account: cachedAccount,
      idToken: cachedIdToken,
      accessToken: cachedAccessToken,
      refreshToken: cachedRefreshToken,
      appMetadata: cachedAppMetadata
    };
  }
  /**
   * Retrieve AccountEntity from cache
   * @param account
   */


  readAccountFromCache(account) {
    const accountKey = AccountEntity.generateAccountCacheKey(account);
    return this.getAccount(accountKey);
  }
  /**
   * Retrieve IdTokenEntity from cache
   * @param clientId
   * @param account
   * @param inputRealm
   */


  readIdTokenFromCache(clientId, account) {
    const idTokenFilter = {
      homeAccountId: account.homeAccountId,
      environment: account.environment,
      credentialType: CredentialType.ID_TOKEN,
      clientId: clientId,
      realm: account.tenantId
    };
    const credentialCache = this.getCredentialsFilteredBy(idTokenFilter);
    const idTokens = Object.keys(credentialCache.idTokens).map(key => credentialCache.idTokens[key]);
    const numIdTokens = idTokens.length;

    if (numIdTokens < 1) {
      return null;
    } else if (numIdTokens > 1) {
      throw ClientAuthError.createMultipleMatchingTokensInCacheError();
    }

    return idTokens[0];
  }
  /**
   * Retrieve AccessTokenEntity from cache
   * @param clientId
   * @param account
   * @param scopes
   * @param authScheme
   */


  readAccessTokenFromCache(clientId, account, scopes, authScheme) {
    const credentialType = authScheme === AuthenticationScheme.POP ? CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME : CredentialType.ACCESS_TOKEN;
    const accessTokenFilter = {
      homeAccountId: account.homeAccountId,
      environment: account.environment,
      credentialType: credentialType,
      clientId,
      realm: account.tenantId,
      target: scopes.printScopesLowerCase()
    };
    const credentialCache = this.getCredentialsFilteredBy(accessTokenFilter);
    const accessTokens = Object.keys(credentialCache.accessTokens).map(key => credentialCache.accessTokens[key]);
    const numAccessTokens = accessTokens.length;

    if (numAccessTokens < 1) {
      return null;
    } else if (numAccessTokens > 1) {
      throw ClientAuthError.createMultipleMatchingTokensInCacheError();
    }

    return accessTokens[0];
  }
  /**
   * Helper to retrieve the appropriate refresh token from cache
   * @param clientId
   * @param account
   * @param familyRT
   */


  readRefreshTokenFromCache(clientId, account, familyRT) {
    const id = familyRT ? THE_FAMILY_ID : undefined;
    const refreshTokenFilter = {
      homeAccountId: account.homeAccountId,
      environment: account.environment,
      credentialType: CredentialType.REFRESH_TOKEN,
      clientId: clientId,
      familyId: id
    };
    const credentialCache = this.getCredentialsFilteredBy(refreshTokenFilter);
    const refreshTokens = Object.keys(credentialCache.refreshTokens).map(key => credentialCache.refreshTokens[key]);
    const numRefreshTokens = refreshTokens.length;

    if (numRefreshTokens < 1) {
      return null;
    } // address the else case after remove functions address environment aliases


    return refreshTokens[0];
  }
  /**
   * Retrieve AppMetadataEntity from cache
   */


  readAppMetadataFromCache(environment, clientId) {
    const appMetadataFilter = {
      environment,
      clientId
    };
    const appMetadata = this.getAppMetadataFilteredBy(appMetadataFilter);
    const appMetadataEntries = Object.keys(appMetadata).map(key => appMetadata[key]);
    const numAppMetadata = appMetadataEntries.length;

    if (numAppMetadata < 1) {
      return null;
    } else if (numAppMetadata > 1) {
      throw ClientAuthError.createMultipleMatchingAppMetadataInCacheError();
    }

    return appMetadataEntries[0];
  }
  /**
   * Return the family_id value associated  with FOCI
   * @param environment
   * @param clientId
   */


  isAppMetadataFOCI(environment, clientId) {
    const appMetadata = this.readAppMetadataFromCache(environment, clientId);
    return !!(appMetadata && appMetadata.familyId === THE_FAMILY_ID);
  }
  /**
   * helper to match account ids
   * @param value
   * @param homeAccountId
   */


  matchHomeAccountId(entity, homeAccountId) {
    return !!(entity.homeAccountId && homeAccountId === entity.homeAccountId);
  }
  /**
   * helper to match assertion
   * @param value
   * @param oboAssertion
   */


  matchOboAssertion(entity, oboAssertion) {
    return !!(entity.oboAssertion && oboAssertion === entity.oboAssertion);
  }
  /**
   * helper to match environment
   * @param value
   * @param environment
   */


  matchEnvironment(entity, environment) {
    const cloudMetadata = this.getAuthorityMetadataByAlias(environment);

    if (cloudMetadata && cloudMetadata.aliases.indexOf(entity.environment) > -1) {
      return true;
    }

    return false;
  }
  /**
   * helper to match credential type
   * @param entity
   * @param credentialType
   */


  matchCredentialType(entity, credentialType) {
    return entity.credentialType && credentialType.toLowerCase() === entity.credentialType.toLowerCase();
  }
  /**
   * helper to match client ids
   * @param entity
   * @param clientId
   */


  matchClientId(entity, clientId) {
    return !!(entity.clientId && clientId === entity.clientId);
  }
  /**
   * helper to match family ids
   * @param entity
   * @param familyId
   */


  matchFamilyId(entity, familyId) {
    return !!(entity.familyId && familyId === entity.familyId);
  }
  /**
   * helper to match realm
   * @param entity
   * @param realm
   */


  matchRealm(entity, realm) {
    return !!(entity.realm && realm === entity.realm);
  }
  /**
   * Returns true if the target scopes are a subset of the current entity's scopes, false otherwise.
   * @param entity
   * @param target
   */


  matchTarget(entity, target) {
    const isNotAccessTokenCredential = entity.credentialType !== CredentialType.ACCESS_TOKEN && entity.credentialType !== CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME;

    if (isNotAccessTokenCredential || !entity.target) {
      return false;
    }

    const entityScopeSet = ScopeSet.fromString(entity.target);
    const requestTargetScopeSet = ScopeSet.fromString(target);

    if (!requestTargetScopeSet.containsOnlyOIDCScopes()) {
      requestTargetScopeSet.removeOIDCScopes(); // ignore OIDC scopes
    } else {
      requestTargetScopeSet.removeScope(Constants.OFFLINE_ACCESS_SCOPE);
    }

    return entityScopeSet.containsScopeSet(requestTargetScopeSet);
  }
  /**
   * returns if a given cache entity is of the type appmetadata
   * @param key
   */


  isAppMetadata(key) {
    return key.indexOf(APP_METADATA) !== -1;
  }
  /**
   * returns if a given cache entity is of the type authoritymetadata
   * @param key
   */


  isAuthorityMetadata(key) {
    return key.indexOf(AUTHORITY_METADATA_CONSTANTS.CACHE_KEY) !== -1;
  }
  /**
   * returns cache key used for cloud instance metadata
   */


  generateAuthorityMetadataCacheKey(authority) {
    return `${AUTHORITY_METADATA_CONSTANTS.CACHE_KEY}-${this.clientId}-${authority}`;
  }
  /**
   * Returns the specific credential (IdToken/AccessToken/RefreshToken) from the cache
   * @param key
   * @param credType
   */


  getSpecificCredential(key, credType) {
    switch (credType) {
      case CredentialType.ID_TOKEN:
        {
          return this.getIdTokenCredential(key);
        }

      case CredentialType.ACCESS_TOKEN:
      case CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME:
        {
          return this.getAccessTokenCredential(key);
        }

      case CredentialType.REFRESH_TOKEN:
        {
          return this.getRefreshTokenCredential(key);
        }

      default:
        return null;
    }
  }
  /**
   * Helper to convert serialized data to object
   * @param obj
   * @param json
   */


  static toObject(obj, json) {
    for (const propertyName in json) {
      obj[propertyName] = json[propertyName];
    }

    return obj;
  }

}
class DefaultStorageClass extends CacheManager {
  setAccount() {
    const notImplErr = "Storage interface - setAccount() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getAccount() {
    const notImplErr = "Storage interface - getAccount() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  setIdTokenCredential() {
    const notImplErr = "Storage interface - setIdTokenCredential() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getIdTokenCredential() {
    const notImplErr = "Storage interface - getIdTokenCredential() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  setAccessTokenCredential() {
    const notImplErr = "Storage interface - setAccessTokenCredential() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getAccessTokenCredential() {
    const notImplErr = "Storage interface - getAccessTokenCredential() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  setRefreshTokenCredential() {
    const notImplErr = "Storage interface - setRefreshTokenCredential() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getRefreshTokenCredential() {
    const notImplErr = "Storage interface - getRefreshTokenCredential() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  setAppMetadata() {
    const notImplErr = "Storage interface - setAppMetadata() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getAppMetadata() {
    const notImplErr = "Storage interface - getAppMetadata() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  setServerTelemetry() {
    const notImplErr = "Storage interface - setServerTelemetry() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getServerTelemetry() {
    const notImplErr = "Storage interface - getServerTelemetry() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  setAuthorityMetadata() {
    const notImplErr = "Storage interface - setAuthorityMetadata() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getAuthorityMetadata() {
    const notImplErr = "Storage interface - getAuthorityMetadata() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getAuthorityMetadataKeys() {
    const notImplErr = "Storage interface - getAuthorityMetadataKeys() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  setThrottlingCache() {
    const notImplErr = "Storage interface - setThrottlingCache() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getThrottlingCache() {
    const notImplErr = "Storage interface - getThrottlingCache() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  removeItem() {
    const notImplErr = "Storage interface - removeItem() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  containsKey() {
    const notImplErr = "Storage interface - containsKey() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  getKeys() {
    const notImplErr = "Storage interface - getKeys() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

  clear() {
    const notImplErr = "Storage interface - clear() has not been implemented for the cacheStorage interface.";
    throw AuthError.createUnexpectedError(notImplErr);
  }

}

function ownKeys$9(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$9(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$9(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$9(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

const DEFAULT_TOKEN_RENEWAL_OFFSET_SEC = 300;
const DEFAULT_SYSTEM_OPTIONS$1 = {
  tokenRenewalOffsetSeconds: DEFAULT_TOKEN_RENEWAL_OFFSET_SEC
};
const DEFAULT_LOGGER_IMPLEMENTATION = {
  loggerCallback: () => {// allow users to not set loggerCallback
  },
  piiLoggingEnabled: false,
  logLevel: LogLevel.Info
};
const DEFAULT_NETWORK_IMPLEMENTATION = {
  async sendGetRequestAsync() {
    const notImplErr = "Network interface - sendGetRequestAsync() has not been implemented";
    throw AuthError.createUnexpectedError(notImplErr);
  },

  async sendPostRequestAsync() {
    const notImplErr = "Network interface - sendPostRequestAsync() has not been implemented";
    throw AuthError.createUnexpectedError(notImplErr);
  }

};
const DEFAULT_LIBRARY_INFO = {
  sku: Constants.SKU,
  version: version$1,
  cpu: "",
  os: ""
};
const DEFAULT_CLIENT_CREDENTIALS = {
  clientSecret: "",
  clientAssertion: undefined
};
/**
 * Function that sets the default options when not explicitly configured from app developer
 *
 * @param Configuration
 *
 * @returns Configuration
 */

function buildClientConfiguration({
  authOptions: userAuthOptions,
  systemOptions: userSystemOptions,
  loggerOptions: userLoggerOption,
  storageInterface: storageImplementation,
  networkInterface: networkImplementation,
  cryptoInterface: cryptoImplementation,
  clientCredentials: clientCredentials,
  libraryInfo: libraryInfo,
  serverTelemetryManager: serverTelemetryManager,
  persistencePlugin: persistencePlugin,
  serializableCache: serializableCache
}) {
  return {
    authOptions: buildAuthOptions(userAuthOptions),
    systemOptions: _objectSpread$9(_objectSpread$9({}, DEFAULT_SYSTEM_OPTIONS$1), userSystemOptions),
    loggerOptions: _objectSpread$9(_objectSpread$9({}, DEFAULT_LOGGER_IMPLEMENTATION), userLoggerOption),
    storageInterface: storageImplementation || new DefaultStorageClass(userAuthOptions.clientId, DEFAULT_CRYPTO_IMPLEMENTATION),
    networkInterface: networkImplementation || DEFAULT_NETWORK_IMPLEMENTATION,
    cryptoInterface: cryptoImplementation || DEFAULT_CRYPTO_IMPLEMENTATION,
    clientCredentials: clientCredentials || DEFAULT_CLIENT_CREDENTIALS,
    libraryInfo: _objectSpread$9(_objectSpread$9({}, DEFAULT_LIBRARY_INFO), libraryInfo),
    serverTelemetryManager: serverTelemetryManager || null,
    persistencePlugin: persistencePlugin || null,
    serializableCache: serializableCache || null
  };
}
/**
 * Construct authoptions from the client and platform passed values
 * @param authOptions
 */

function buildAuthOptions(authOptions) {
  return _objectSpread$9({
    clientCapabilities: []
  }, authOptions);
}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Error thrown when there is an error with the server code, for example, unavailability.
 */

class ServerError extends AuthError {
  constructor(errorCode, errorMessage, subError) {
    super(errorCode, errorMessage, subError);
    this.name = "ServerError";
    Object.setPrototypeOf(this, ServerError.prototype);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class ThrottlingUtils {
  /**
   * Prepares a RequestThumbprint to be stored as a key.
   * @param thumbprint
   */
  static generateThrottlingStorageKey(thumbprint) {
    return `${ThrottlingConstants.THROTTLING_PREFIX}.${JSON.stringify(thumbprint)}`;
  }
  /**
   * Performs necessary throttling checks before a network request.
   * @param cacheManager
   * @param thumbprint
   */


  static preProcess(cacheManager, thumbprint) {
    const key = ThrottlingUtils.generateThrottlingStorageKey(thumbprint);
    const value = cacheManager.getThrottlingCache(key);

    if (value) {
      if (value.throttleTime < Date.now()) {
        cacheManager.removeItem(key, CacheSchemaType.THROTTLING);
        return;
      }

      throw new ServerError(value.errorCodes?.join(" ") || Constants.EMPTY_STRING, value.errorMessage, value.subError);
    }
  }
  /**
   * Performs necessary throttling checks after a network request.
   * @param cacheManager
   * @param thumbprint
   * @param response
   */


  static postProcess(cacheManager, thumbprint, response) {
    if (ThrottlingUtils.checkResponseStatus(response) || ThrottlingUtils.checkResponseForRetryAfter(response)) {
      const thumbprintValue = {
        throttleTime: ThrottlingUtils.calculateThrottleTime(parseInt(response.headers[HeaderNames.RETRY_AFTER])),
        error: response.body.error,
        errorCodes: response.body.error_codes,
        errorMessage: response.body.error_description,
        subError: response.body.suberror
      };
      cacheManager.setThrottlingCache(ThrottlingUtils.generateThrottlingStorageKey(thumbprint), thumbprintValue);
    }
  }
  /**
   * Checks a NetworkResponse object's status codes against 429 or 5xx
   * @param response
   */


  static checkResponseStatus(response) {
    return response.status === 429 || response.status >= 500 && response.status < 600;
  }
  /**
   * Checks a NetworkResponse object's RetryAfter header
   * @param response
   */


  static checkResponseForRetryAfter(response) {
    if (response.headers) {
      return response.headers.hasOwnProperty(HeaderNames.RETRY_AFTER) && (response.status < 200 || response.status >= 300);
    }

    return false;
  }
  /**
   * Calculates the Unix-time value for a throttle to expire given throttleTime in seconds.
   * @param throttleTime
   */


  static calculateThrottleTime(throttleTime) {
    if (throttleTime <= 0) {
      throttleTime = 0;
    }

    const currentSeconds = Date.now() / 1000;
    return Math.floor(Math.min(currentSeconds + (throttleTime || ThrottlingConstants.DEFAULT_THROTTLE_TIME_SECONDS), currentSeconds + ThrottlingConstants.DEFAULT_MAX_THROTTLE_TIME_SECONDS) * 1000);
  }

  static removeThrottle(cacheManager, clientId, authority, scopes, homeAccountIdentifier) {
    const thumbprint = {
      clientId,
      authority,
      scopes,
      homeAccountIdentifier
    };
    const key = this.generateThrottlingStorageKey(thumbprint);
    return cacheManager.removeItem(key, CacheSchemaType.THROTTLING);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class NetworkManager {
  constructor(networkClient, cacheManager) {
    this.networkClient = networkClient;
    this.cacheManager = cacheManager;
  }
  /**
   * Wraps sendPostRequestAsync with necessary preflight and postflight logic
   * @param thumbprint
   * @param tokenEndpoint
   * @param options
   */


  async sendPostRequest(thumbprint, tokenEndpoint, options) {
    ThrottlingUtils.preProcess(this.cacheManager, thumbprint);
    let response;

    try {
      response = await this.networkClient.sendPostRequestAsync(tokenEndpoint, options);
    } catch (e) {
      if (e instanceof AuthError) {
        throw e;
      } else {
        throw ClientAuthError.createNetworkError(tokenEndpoint, e);
      }
    }

    ThrottlingUtils.postProcess(this.cacheManager, thumbprint, response);
    return response;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Base application class which will construct requests to send to and handle responses from the Microsoft STS using the authorization code flow.
 */

class BaseClient {
  constructor(configuration) {
    // Set the configuration
    this.config = buildClientConfiguration(configuration); // Initialize the logger

    this.logger = new Logger(this.config.loggerOptions, name$1, version$1); // Initialize crypto

    this.cryptoUtils = this.config.cryptoInterface; // Initialize storage interface

    this.cacheManager = this.config.storageInterface; // Set the network interface

    this.networkClient = this.config.networkInterface; // Set the NetworkManager

    this.networkManager = new NetworkManager(this.networkClient, this.cacheManager); // Set TelemetryManager

    this.serverTelemetryManager = this.config.serverTelemetryManager; // set Authority

    this.authority = this.config.authOptions.authority;
  }
  /**
   * Creates default headers for requests to token endpoint
   */


  createDefaultTokenRequestHeaders() {
    const headers = {};
    headers[HeaderNames.CONTENT_TYPE] = Constants.URL_FORM_CONTENT_TYPE;
    return headers;
  }
  /**
   * Http post to token endpoint
   * @param tokenEndpoint
   * @param queryString
   * @param headers
   * @param thumbprint
   */


  async executePostToTokenEndpoint(tokenEndpoint, queryString, headers, thumbprint) {
    const response = await this.networkManager.sendPostRequest(thumbprint, tokenEndpoint, {
      body: queryString,
      headers: headers
    });

    if (this.config.serverTelemetryManager && response.status < 500 && response.status !== 429) {
      // Telemetry data successfully logged by server, clear Telemetry cache
      this.config.serverTelemetryManager.clearTelemetryCache();
    }

    return response;
  }
  /**
   * Updates the authority object of the client. Endpoint discovery must be completed.
   * @param updatedAuthority
   */


  updateAuthority(updatedAuthority) {
    if (!updatedAuthority.discoveryComplete()) {
      throw ClientAuthError.createEndpointDiscoveryIncompleteError("Updated authority has not completed endpoint discovery.");
    }

    this.authority = updatedAuthority;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Validates server consumable params from the "request" objects
 */

class RequestValidator {
  /**
   * Utility to check if the `redirectUri` in the request is a non-null value
   * @param redirectUri
   */
  static validateRedirectUri(redirectUri) {
    if (StringUtils.isEmpty(redirectUri)) {
      throw ClientConfigurationError.createRedirectUriEmptyError();
    }
  }
  /**
   * Utility to validate prompt sent by the user in the request
   * @param prompt
   */


  static validatePrompt(prompt) {
    if ([PromptValue.LOGIN, PromptValue.SELECT_ACCOUNT, PromptValue.CONSENT, PromptValue.NONE].indexOf(prompt) < 0) {
      throw ClientConfigurationError.createInvalidPromptError(prompt);
    }
  }

  static validateClaims(claims) {
    try {
      JSON.parse(claims);
    } catch (e) {
      throw ClientConfigurationError.createInvalidClaimsRequestError();
    }
  }
  /**
   * Utility to validate code_challenge and code_challenge_method
   * @param codeChallenge
   * @param codeChallengeMethod
   */


  static validateCodeChallengeParams(codeChallenge, codeChallengeMethod) {
    if (StringUtils.isEmpty(codeChallenge) || StringUtils.isEmpty(codeChallengeMethod)) {
      throw ClientConfigurationError.createInvalidCodeChallengeParamsError();
    } else {
      this.validateCodeChallengeMethod(codeChallengeMethod);
    }
  }
  /**
   * Utility to validate code_challenge_method
   * @param codeChallengeMethod
   */


  static validateCodeChallengeMethod(codeChallengeMethod) {
    if ([CodeChallengeMethodValues.PLAIN, CodeChallengeMethodValues.S256].indexOf(codeChallengeMethod) < 0) {
      throw ClientConfigurationError.createInvalidCodeChallengeMethodError();
    }
  }
  /**
   * Removes unnecessary or duplicate query parameters from extraQueryParameters
   * @param request
   */


  static sanitizeEQParams(eQParams, queryParams) {
    if (!eQParams) {
      return {};
    } // Remove any query parameters already included in SSO params


    queryParams.forEach((value, key) => {
      if (eQParams[key]) {
        delete eQParams[key];
      }
    });
    return eQParams;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class RequestParameterBuilder {
  constructor() {
    this.parameters = new Map();
  }
  /**
   * add response_type = code
   */


  addResponseTypeCode() {
    this.parameters.set(AADServerParamKeys.RESPONSE_TYPE, encodeURIComponent(Constants.CODE_RESPONSE_TYPE));
  }
  /**
   * add response_mode. defaults to query.
   * @param responseMode
   */


  addResponseMode(responseMode) {
    this.parameters.set(AADServerParamKeys.RESPONSE_MODE, encodeURIComponent(responseMode ? responseMode : ResponseMode.QUERY));
  }
  /**
   * add scopes. set addOidcScopes to false to prevent default scopes in non-user scenarios
   * @param scopeSet
   * @param addOidcScopes
   */


  addScopes(scopes, addOidcScopes = true) {
    const requestScopes = addOidcScopes ? [...(scopes || []), ...OIDC_DEFAULT_SCOPES] : scopes || [];
    const scopeSet = new ScopeSet(requestScopes);
    this.parameters.set(AADServerParamKeys.SCOPE, encodeURIComponent(scopeSet.printScopes()));
  }
  /**
   * add clientId
   * @param clientId
   */


  addClientId(clientId) {
    this.parameters.set(AADServerParamKeys.CLIENT_ID, encodeURIComponent(clientId));
  }
  /**
   * add redirect_uri
   * @param redirectUri
   */


  addRedirectUri(redirectUri) {
    RequestValidator.validateRedirectUri(redirectUri);
    this.parameters.set(AADServerParamKeys.REDIRECT_URI, encodeURIComponent(redirectUri));
  }
  /**
   * add post logout redirectUri
   * @param redirectUri
   */


  addPostLogoutRedirectUri(redirectUri) {
    RequestValidator.validateRedirectUri(redirectUri);
    this.parameters.set(AADServerParamKeys.POST_LOGOUT_URI, encodeURIComponent(redirectUri));
  }
  /**
   * add id_token_hint to logout request
   * @param idTokenHint
   */


  addIdTokenHint(idTokenHint) {
    this.parameters.set(AADServerParamKeys.ID_TOKEN_HINT, encodeURIComponent(idTokenHint));
  }
  /**
   * add domain_hint
   * @param domainHint
   */


  addDomainHint(domainHint) {
    this.parameters.set(SSOTypes.DOMAIN_HINT, encodeURIComponent(domainHint));
  }
  /**
   * add login_hint
   * @param loginHint
   */


  addLoginHint(loginHint) {
    this.parameters.set(SSOTypes.LOGIN_HINT, encodeURIComponent(loginHint));
  }
  /**
   * add sid
   * @param sid
   */


  addSid(sid) {
    this.parameters.set(SSOTypes.SID, encodeURIComponent(sid));
  }
  /**
   * add claims
   * @param claims
   */


  addClaims(claims, clientCapabilities) {
    const mergedClaims = this.addClientCapabilitiesToClaims(claims, clientCapabilities);
    RequestValidator.validateClaims(mergedClaims);
    this.parameters.set(AADServerParamKeys.CLAIMS, encodeURIComponent(mergedClaims));
  }
  /**
   * add correlationId
   * @param correlationId
   */


  addCorrelationId(correlationId) {
    this.parameters.set(AADServerParamKeys.CLIENT_REQUEST_ID, encodeURIComponent(correlationId));
  }
  /**
   * add library info query params
   * @param libraryInfo
   */


  addLibraryInfo(libraryInfo) {
    // Telemetry Info
    this.parameters.set(AADServerParamKeys.X_CLIENT_SKU, libraryInfo.sku);
    this.parameters.set(AADServerParamKeys.X_CLIENT_VER, libraryInfo.version);
    this.parameters.set(AADServerParamKeys.X_CLIENT_OS, libraryInfo.os);
    this.parameters.set(AADServerParamKeys.X_CLIENT_CPU, libraryInfo.cpu);
  }
  /**
   * add prompt
   * @param prompt
   */


  addPrompt(prompt) {
    RequestValidator.validatePrompt(prompt);
    this.parameters.set(`${AADServerParamKeys.PROMPT}`, encodeURIComponent(prompt));
  }
  /**
   * add state
   * @param state
   */


  addState(state) {
    if (!StringUtils.isEmpty(state)) {
      this.parameters.set(AADServerParamKeys.STATE, encodeURIComponent(state));
    }
  }
  /**
   * add nonce
   * @param nonce
   */


  addNonce(nonce) {
    this.parameters.set(AADServerParamKeys.NONCE, encodeURIComponent(nonce));
  }
  /**
   * add code_challenge and code_challenge_method
   * - throw if either of them are not passed
   * @param codeChallenge
   * @param codeChallengeMethod
   */


  addCodeChallengeParams(codeChallenge, codeChallengeMethod) {
    RequestValidator.validateCodeChallengeParams(codeChallenge, codeChallengeMethod);

    if (codeChallenge && codeChallengeMethod) {
      this.parameters.set(AADServerParamKeys.CODE_CHALLENGE, encodeURIComponent(codeChallenge));
      this.parameters.set(AADServerParamKeys.CODE_CHALLENGE_METHOD, encodeURIComponent(codeChallengeMethod));
    } else {
      throw ClientConfigurationError.createInvalidCodeChallengeParamsError();
    }
  }
  /**
   * add the `authorization_code` passed by the user to exchange for a token
   * @param code
   */


  addAuthorizationCode(code) {
    this.parameters.set(AADServerParamKeys.CODE, encodeURIComponent(code));
  }
  /**
   * add the `authorization_code` passed by the user to exchange for a token
   * @param code
   */


  addDeviceCode(code) {
    this.parameters.set(AADServerParamKeys.DEVICE_CODE, encodeURIComponent(code));
  }
  /**
   * add the `refreshToken` passed by the user
   * @param refreshToken
   */


  addRefreshToken(refreshToken) {
    this.parameters.set(AADServerParamKeys.REFRESH_TOKEN, encodeURIComponent(refreshToken));
  }
  /**
   * add the `code_verifier` passed by the user to exchange for a token
   * @param codeVerifier
   */


  addCodeVerifier(codeVerifier) {
    this.parameters.set(AADServerParamKeys.CODE_VERIFIER, encodeURIComponent(codeVerifier));
  }
  /**
   * add client_secret
   * @param clientSecret
   */


  addClientSecret(clientSecret) {
    this.parameters.set(AADServerParamKeys.CLIENT_SECRET, encodeURIComponent(clientSecret));
  }
  /**
   * add clientAssertion for confidential client flows
   * @param clientAssertion
   */


  addClientAssertion(clientAssertion) {
    this.parameters.set(AADServerParamKeys.CLIENT_ASSERTION, encodeURIComponent(clientAssertion));
  }
  /**
   * add clientAssertionType for confidential client flows
   * @param clientAssertionType
   */


  addClientAssertionType(clientAssertionType) {
    this.parameters.set(AADServerParamKeys.CLIENT_ASSERTION_TYPE, encodeURIComponent(clientAssertionType));
  }
  /**
   * add OBO assertion for confidential client flows
   * @param clientAssertion
   */


  addOboAssertion(oboAssertion) {
    this.parameters.set(AADServerParamKeys.OBO_ASSERTION, encodeURIComponent(oboAssertion));
  }
  /**
   * add grant type
   * @param grantType
   */


  addRequestTokenUse(tokenUse) {
    this.parameters.set(AADServerParamKeys.REQUESTED_TOKEN_USE, encodeURIComponent(tokenUse));
  }
  /**
   * add grant type
   * @param grantType
   */


  addGrantType(grantType) {
    this.parameters.set(AADServerParamKeys.GRANT_TYPE, encodeURIComponent(grantType));
  }
  /**
   * add client info
   *
   */


  addClientInfo() {
    this.parameters.set(ClientInfo, "1");
  }
  /**
   * add extraQueryParams
   * @param eQparams
   */


  addExtraQueryParameters(eQparams) {
    RequestValidator.sanitizeEQParams(eQparams, this.parameters);
    Object.keys(eQparams).forEach(key => {
      this.parameters.set(key, eQparams[key]);
    });
  }

  addClientCapabilitiesToClaims(claims, clientCapabilities) {
    let mergedClaims; // Parse provided claims into JSON object or initialize empty object

    if (!claims) {
      mergedClaims = {};
    } else {
      try {
        mergedClaims = JSON.parse(claims);
      } catch (e) {
        throw ClientConfigurationError.createInvalidClaimsRequestError();
      }
    }

    if (clientCapabilities && clientCapabilities.length > 0) {
      if (!mergedClaims.hasOwnProperty(ClaimsRequestKeys.ACCESS_TOKEN)) {
        // Add access_token key to claims object
        mergedClaims[ClaimsRequestKeys.ACCESS_TOKEN] = {};
      } // Add xms_cc claim with provided clientCapabilities to access_token key


      mergedClaims[ClaimsRequestKeys.ACCESS_TOKEN][ClaimsRequestKeys.XMS_CC] = {
        values: clientCapabilities
      };
    }

    return JSON.stringify(mergedClaims);
  }
  /**
   * adds `username` for Password Grant flow
   * @param username
   */


  addUsername(username) {
    this.parameters.set(PasswordGrantConstants.username, username);
  }
  /**
   * adds `password` for Password Grant flow
   * @param password
   */


  addPassword(password) {
    this.parameters.set(PasswordGrantConstants.password, password);
  }
  /**
   * add pop_jwk to query params
   * @param cnfString
   */


  addPopToken(cnfString) {
    if (!StringUtils.isEmpty(cnfString)) {
      this.parameters.set(AADServerParamKeys.TOKEN_TYPE, AuthenticationScheme.POP);
      this.parameters.set(AADServerParamKeys.REQ_CNF, encodeURIComponent(cnfString));
    }
  }
  /**
   * add server telemetry fields
   * @param serverTelemetryManager
   */


  addServerTelemetry(serverTelemetryManager) {
    this.parameters.set(AADServerParamKeys.X_CLIENT_CURR_TELEM, serverTelemetryManager.generateCurrentRequestHeaderValue());
    this.parameters.set(AADServerParamKeys.X_CLIENT_LAST_TELEM, serverTelemetryManager.generateLastRequestHeaderValue());
  }
  /**
   * Adds parameter that indicates to the server that throttling is supported
   */


  addThrottling() {
    this.parameters.set(AADServerParamKeys.X_MS_LIB_CAPABILITY, ThrottlingConstants.X_MS_LIB_CAPABILITY_VALUE);
  }
  /**
   * Utility to create a URL from the params map
   */


  createQueryString() {
    const queryParameterArray = new Array();
    this.parameters.forEach((value, key) => {
      queryParameterArray.push(`${key}=${value}`);
    });
    return queryParameterArray.join("&");
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * ID_TOKEN Cache
 *
 * Key:Value Schema:
 *
 * Key Example: uid.utid-login.microsoftonline.com-idtoken-clientId-contoso.com-
 *
 * Value Schema:
 * {
 *      homeAccountId: home account identifier for the auth scheme,
 *      environment: entity that issued the token, represented as a full host
 *      credentialType: Type of credential as a string, can be one of the following: RefreshToken, AccessToken, IdToken, Password, Cookie, Certificate, Other
 *      clientId: client ID of the application
 *      secret: Actual credential as a string
 *      realm: Full tenant or organizational identifier that the account belongs to
 * }
 */

class IdTokenEntity extends CredentialEntity {
  /**
   * Create IdTokenEntity
   * @param homeAccountId
   * @param authenticationResult
   * @param clientId
   * @param authority
   */
  static createIdTokenEntity(homeAccountId, environment, idToken, clientId, tenantId, oboAssertion) {
    const idTokenEntity = new IdTokenEntity();
    idTokenEntity.credentialType = CredentialType.ID_TOKEN;
    idTokenEntity.homeAccountId = homeAccountId;
    idTokenEntity.environment = environment;
    idTokenEntity.clientId = clientId;
    idTokenEntity.secret = idToken;
    idTokenEntity.realm = tenantId;
    idTokenEntity.oboAssertion = oboAssertion;
    return idTokenEntity;
  }
  /**
   * Validates an entity: checks for all expected params
   * @param entity
   */


  static isIdTokenEntity(entity) {
    if (!entity) {
      return false;
    }

    return entity.hasOwnProperty("homeAccountId") && entity.hasOwnProperty("environment") && entity.hasOwnProperty("credentialType") && entity.hasOwnProperty("realm") && entity.hasOwnProperty("clientId") && entity.hasOwnProperty("secret") && entity["credentialType"] === CredentialType.ID_TOKEN;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

/**
 * Utility class which exposes functions for managing date and time operations.
 */
class TimeUtils {
  /**
   * return the current time in Unix time (seconds).
   */
  static nowSeconds() {
    // Date.getTime() returns in milliseconds.
    return Math.round(new Date().getTime() / 1000.0);
  }
  /**
   * check if a token is expired based on given UTC time in seconds.
   * @param expiresOn
   */


  static isTokenExpired(expiresOn, offset) {
    // check for access token expiry
    const expirationSec = Number(expiresOn) || 0;
    const offsetCurrentTimeSec = TimeUtils.nowSeconds() + offset; // If current time + offset is greater than token expiration time, then token is expired.

    return offsetCurrentTimeSec > expirationSec;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * ACCESS_TOKEN Credential Type
 *
 * Key:Value Schema:
 *
 * Key Example: uid.utid-login.microsoftonline.com-accesstoken-clientId-contoso.com-user.read
 *
 * Value Schema:
 * {
 *      homeAccountId: home account identifier for the auth scheme,
 *      environment: entity that issued the token, represented as a full host
 *      credentialType: Type of credential as a string, can be one of the following: RefreshToken, AccessToken, IdToken, Password, Cookie, Certificate, Other
 *      clientId: client ID of the application
 *      secret: Actual credential as a string
 *      familyId: Family ID identifier, usually only used for refresh tokens
 *      realm: Full tenant or organizational identifier that the account belongs to
 *      target: Permissions that are included in the token, or for refresh tokens, the resource identifier.
 *      cachedAt: Absolute device time when entry was created in the cache.
 *      expiresOn: Token expiry time, calculated based on current UTC time in seconds. Represented as a string.
 *      extendedExpiresOn: Additional extended expiry time until when token is valid in case of server-side outage. Represented as string in UTC seconds.
 *      keyId: used for POP and SSH tokenTypes
 *      tokenType: Type of the token issued. Usually "Bearer"
 * }
 */

class AccessTokenEntity extends CredentialEntity {
  /**
   * Create AccessTokenEntity
   * @param homeAccountId
   * @param environment
   * @param accessToken
   * @param clientId
   * @param tenantId
   * @param scopes
   * @param expiresOn
   * @param extExpiresOn
   */
  static createAccessTokenEntity(homeAccountId, environment, accessToken, clientId, tenantId, scopes, expiresOn, extExpiresOn, cryptoUtils, refreshOn, tokenType, oboAssertion) {
    const atEntity = new AccessTokenEntity();
    atEntity.homeAccountId = homeAccountId;
    atEntity.credentialType = CredentialType.ACCESS_TOKEN;
    atEntity.secret = accessToken;
    const currentTime = TimeUtils.nowSeconds();
    atEntity.cachedAt = currentTime.toString();
    /*
     * Token expiry time.
     * This value should be  calculated based on the current UTC time measured locally and the value  expires_in Represented as a string in JSON.
     */

    atEntity.expiresOn = expiresOn.toString();
    atEntity.extendedExpiresOn = extExpiresOn.toString();

    if (refreshOn) {
      atEntity.refreshOn = refreshOn.toString();
    }

    atEntity.environment = environment;
    atEntity.clientId = clientId;
    atEntity.realm = tenantId;
    atEntity.target = scopes;
    atEntity.oboAssertion = oboAssertion;
    atEntity.tokenType = StringUtils.isEmpty(tokenType) ? AuthenticationScheme.BEARER : tokenType; // Create Access Token With AuthScheme instead of regular access token

    if (atEntity.tokenType === AuthenticationScheme.POP) {
      atEntity.credentialType = CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME; // Make sure keyId is present and add it to credential

      const tokenClaims = AuthToken.extractTokenClaims(accessToken, cryptoUtils);

      if (!tokenClaims?.cnf?.kid) {
        throw ClientAuthError.createTokenClaimsRequiredError();
      }

      atEntity.keyId = tokenClaims.cnf.kid;
    }

    return atEntity;
  }
  /**
   * Validates an entity: checks for all expected params
   * @param entity
   */


  static isAccessTokenEntity(entity) {
    if (!entity) {
      return false;
    }

    return entity.hasOwnProperty("homeAccountId") && entity.hasOwnProperty("environment") && entity.hasOwnProperty("credentialType") && entity.hasOwnProperty("realm") && entity.hasOwnProperty("clientId") && entity.hasOwnProperty("secret") && entity.hasOwnProperty("target") && (entity["credentialType"] === CredentialType.ACCESS_TOKEN || entity["credentialType"] === CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * REFRESH_TOKEN Cache
 *
 * Key:Value Schema:
 *
 * Key Example: uid.utid-login.microsoftonline.com-refreshtoken-clientId--
 *
 * Value:
 * {
 *      homeAccountId: home account identifier for the auth scheme,
 *      environment: entity that issued the token, represented as a full host
 *      credentialType: Type of credential as a string, can be one of the following: RefreshToken, AccessToken, IdToken, Password, Cookie, Certificate, Other
 *      clientId: client ID of the application
 *      secret: Actual credential as a string
 *      familyId: Family ID identifier, '1' represents Microsoft Family
 *      realm: Full tenant or organizational identifier that the account belongs to
 *      target: Permissions that are included in the token, or for refresh tokens, the resource identifier.
 * }
 */

class RefreshTokenEntity extends CredentialEntity {
  /**
   * Create RefreshTokenEntity
   * @param homeAccountId
   * @param authenticationResult
   * @param clientId
   * @param authority
   */
  static createRefreshTokenEntity(homeAccountId, environment, refreshToken, clientId, familyId, oboAssertion) {
    const rtEntity = new RefreshTokenEntity();
    rtEntity.clientId = clientId;
    rtEntity.credentialType = CredentialType.REFRESH_TOKEN;
    rtEntity.environment = environment;
    rtEntity.homeAccountId = homeAccountId;
    rtEntity.secret = refreshToken;
    rtEntity.oboAssertion = oboAssertion;
    if (familyId) rtEntity.familyId = familyId;
    return rtEntity;
  }
  /**
   * Validates an entity: checks for all expected params
   * @param entity
   */


  static isRefreshTokenEntity(entity) {
    if (!entity) {
      return false;
    }

    return entity.hasOwnProperty("homeAccountId") && entity.hasOwnProperty("environment") && entity.hasOwnProperty("credentialType") && entity.hasOwnProperty("clientId") && entity.hasOwnProperty("secret") && entity["credentialType"] === CredentialType.REFRESH_TOKEN;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * InteractionRequiredAuthErrorMessage class containing string constants used by error codes and messages.
 */

const InteractionRequiredAuthErrorMessage = ["interaction_required", "consent_required", "login_required"];
const InteractionRequiredAuthSubErrorMessage = ["message_only", "additional_action", "basic_action", "user_password_expired", "consent_required"];
/**
 * Error thrown when user interaction is required at the auth server.
 */

class InteractionRequiredAuthError extends ServerError {
  constructor(errorCode, errorMessage, subError) {
    super(errorCode, errorMessage, subError);
    this.name = "InteractionRequiredAuthError";
    Object.setPrototypeOf(this, InteractionRequiredAuthError.prototype);
  }

  static isInteractionRequiredError(errorCode, errorString, subError) {
    const isInteractionRequiredErrorCode = !!errorCode && InteractionRequiredAuthErrorMessage.indexOf(errorCode) > -1;
    const isInteractionRequiredSubError = !!subError && InteractionRequiredAuthSubErrorMessage.indexOf(subError) > -1;
    const isInteractionRequiredErrorDesc = !!errorString && InteractionRequiredAuthErrorMessage.some(irErrorCode => {
      return errorString.indexOf(irErrorCode) > -1;
    });
    return isInteractionRequiredErrorCode || isInteractionRequiredErrorDesc || isInteractionRequiredSubError;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class CacheRecord {
  constructor(accountEntity, idTokenEntity, accessTokenEntity, refreshTokenEntity, appMetadataEntity) {
    this.account = accountEntity || null;
    this.idToken = idTokenEntity || null;
    this.accessToken = accessTokenEntity || null;
    this.refreshToken = refreshTokenEntity || null;
    this.appMetadata = appMetadataEntity || null;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Class which provides helpers for OAuth 2.0 protocol specific values
 */

class ProtocolUtils {
  /**
   * Appends user state with random guid, or returns random guid.
   * @param userState
   * @param randomGuid
   */
  static setRequestState(cryptoObj, userState, meta) {
    const libraryState = ProtocolUtils.generateLibraryState(cryptoObj, meta);
    return !StringUtils.isEmpty(userState) ? `${libraryState}${Constants.RESOURCE_DELIM}${userState}` : libraryState;
  }
  /**
   * Generates the state value used by the common library.
   * @param randomGuid
   * @param cryptoObj
   */


  static generateLibraryState(cryptoObj, meta) {
    if (!cryptoObj) {
      throw ClientAuthError.createNoCryptoObjectError("generateLibraryState");
    } // Create a state object containing a unique id and the timestamp of the request creation


    const stateObj = {
      id: cryptoObj.createNewGuid()
    };

    if (meta) {
      stateObj.meta = meta;
    }

    const stateString = JSON.stringify(stateObj);
    return cryptoObj.base64Encode(stateString);
  }
  /**
   * Parses the state into the RequestStateObject, which contains the LibraryState info and the state passed by the user.
   * @param state
   * @param cryptoObj
   */


  static parseRequestState(cryptoObj, state) {
    if (!cryptoObj) {
      throw ClientAuthError.createNoCryptoObjectError("parseRequestState");
    }

    if (StringUtils.isEmpty(state)) {
      throw ClientAuthError.createInvalidStateError(state, "Null, undefined or empty state");
    }

    try {
      // Split the state between library state and user passed state and decode them separately
      const splitState = decodeURIComponent(state).split(Constants.RESOURCE_DELIM);
      const libraryState = splitState[0];
      const userState = splitState.length > 1 ? splitState.slice(1).join(Constants.RESOURCE_DELIM) : "";
      const libraryStateString = cryptoObj.base64Decode(libraryState);
      const libraryStateObj = JSON.parse(libraryStateString);
      return {
        userRequestState: !StringUtils.isEmpty(userState) ? userState : "",
        libraryState: libraryStateObj
      };
    } catch (e) {
      throw ClientAuthError.createInvalidStateError(state, e);
    }
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Url object class which can perform various transformations on url strings.
 */

class UrlString {
  constructor(url) {
    this._urlString = url;

    if (StringUtils.isEmpty(this._urlString)) {
      // Throws error if url is empty
      throw ClientConfigurationError.createUrlEmptyError();
    }

    if (StringUtils.isEmpty(this.getHash())) {
      this._urlString = UrlString.canonicalizeUri(url);
    }
  }

  get urlString() {
    return this._urlString;
  }
  /**
   * Ensure urls are lower case and end with a / character.
   * @param url
   */


  static canonicalizeUri(url) {
    if (url) {
      url = url.toLowerCase();

      if (StringUtils.endsWith(url, "?")) {
        url = url.slice(0, -1);
      } else if (StringUtils.endsWith(url, "?/")) {
        url = url.slice(0, -2);
      }

      if (!StringUtils.endsWith(url, "/")) {
        url += "/";
      }
    }

    return url;
  }
  /**
   * Throws if urlString passed is not a valid authority URI string.
   */


  validateAsUri() {
    // Attempts to parse url for uri components
    let components;

    try {
      components = this.getUrlComponents();
    } catch (e) {
      throw ClientConfigurationError.createUrlParseError(e);
    } // Throw error if URI or path segments are not parseable.


    if (!components.HostNameAndPort || !components.PathSegments) {
      throw ClientConfigurationError.createUrlParseError(`Given url string: ${this.urlString}`);
    } // Throw error if uri is insecure.


    if (!components.Protocol || components.Protocol.toLowerCase() !== "https:") {
      throw ClientConfigurationError.createInsecureAuthorityUriError(this.urlString);
    }
  }
  /**
   * Function to remove query string params from url. Returns the new url.
   * @param url
   * @param name
   */


  urlRemoveQueryStringParameter(name) {
    let regex = new RegExp("(\\&" + name + "=)[^\&]+");
    this._urlString = this.urlString.replace(regex, ""); // name=value&

    regex = new RegExp("(" + name + "=)[^\&]+&");
    this._urlString = this.urlString.replace(regex, ""); // name=value

    regex = new RegExp("(" + name + "=)[^\&]+");
    this._urlString = this.urlString.replace(regex, "");
    return this.urlString;
  }
  /**
   * Given a url and a query string return the url with provided query string appended
   * @param url
   * @param queryString
   */


  static appendQueryString(url, queryString) {
    if (StringUtils.isEmpty(queryString)) {
      return url;
    }

    return url.indexOf("?") < 0 ? `${url}?${queryString}` : `${url}&${queryString}`;
  }
  /**
   * Returns a url with the hash removed
   * @param url
   */


  static removeHashFromUrl(url) {
    return UrlString.canonicalizeUri(url.split("#")[0]);
  }
  /**
   * Given a url like https://a:b/common/d?e=f#g, and a tenantId, returns https://a:b/tenantId/d
   * @param href The url
   * @param tenantId The tenant id to replace
   */


  replaceTenantPath(tenantId) {
    const urlObject = this.getUrlComponents();
    const pathArray = urlObject.PathSegments;

    if (tenantId && pathArray.length !== 0 && (pathArray[0] === AADAuthorityConstants.COMMON || pathArray[0] === AADAuthorityConstants.ORGANIZATIONS)) {
      pathArray[0] = tenantId;
    }

    return UrlString.constructAuthorityUriFromObject(urlObject);
  }
  /**
   * Returns the anchor part(#) of the URL
   */


  getHash() {
    return UrlString.parseHash(this.urlString);
  }
  /**
   * Parses out the components from a url string.
   * @returns An object with the various components. Please cache this value insted of calling this multiple times on the same url.
   */


  getUrlComponents() {
    // https://gist.github.com/curtisz/11139b2cfcaef4a261e0
    const regEx = RegExp("^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?"); // If url string does not match regEx, we throw an error

    const match = this.urlString.match(regEx);

    if (!match) {
      throw ClientConfigurationError.createUrlParseError(`Given url string: ${this.urlString}`);
    } // Url component object


    const urlComponents = {
      Protocol: match[1],
      HostNameAndPort: match[4],
      AbsolutePath: match[5],
      QueryString: match[7]
    };
    let pathSegments = urlComponents.AbsolutePath.split("/");
    pathSegments = pathSegments.filter(val => val && val.length > 0); // remove empty elements

    urlComponents.PathSegments = pathSegments;

    if (!StringUtils.isEmpty(urlComponents.QueryString) && urlComponents.QueryString.endsWith("/")) {
      urlComponents.QueryString = urlComponents.QueryString.substring(0, urlComponents.QueryString.length - 1);
    }

    return urlComponents;
  }

  static getDomainFromUrl(url) {
    const regEx = RegExp("^([^:/?#]+://)?([^/?#]*)");
    const match = url.match(regEx);

    if (!match) {
      throw ClientConfigurationError.createUrlParseError(`Given url string: ${url}`);
    }

    return match[2];
  }

  static getAbsoluteUrl(relativeUrl, baseUrl) {
    if (relativeUrl[0] === Constants.FORWARD_SLASH) {
      const url = new UrlString(baseUrl);
      const baseComponents = url.getUrlComponents();
      return baseComponents.Protocol + "//" + baseComponents.HostNameAndPort + relativeUrl;
    }

    return relativeUrl;
  }
  /**
   * Parses hash string from given string. Returns empty string if no hash symbol is found.
   * @param hashString
   */


  static parseHash(hashString) {
    const hashIndex1 = hashString.indexOf("#");
    const hashIndex2 = hashString.indexOf("#/");

    if (hashIndex2 > -1) {
      return hashString.substring(hashIndex2 + 2);
    } else if (hashIndex1 > -1) {
      return hashString.substring(hashIndex1 + 1);
    }

    return "";
  }

  static constructAuthorityUriFromObject(urlObject) {
    return new UrlString(urlObject.Protocol + "//" + urlObject.HostNameAndPort + "/" + urlObject.PathSegments.join("/"));
  }
  /**
   * Returns URL hash as server auth code response object.
   */


  static getDeserializedHash(hash) {
    // Check if given hash is empty
    if (StringUtils.isEmpty(hash)) {
      return {};
    } // Strip the # symbol if present


    const parsedHash = UrlString.parseHash(hash); // If # symbol was not present, above will return empty string, so give original hash value

    const deserializedHash = StringUtils.queryStringToObject(StringUtils.isEmpty(parsedHash) ? hash : parsedHash); // Check if deserialization didn't work

    if (!deserializedHash) {
      throw ClientAuthError.createHashNotDeserializedError(JSON.stringify(deserializedHash));
    }

    return deserializedHash;
  }
  /**
   * Check if the hash of the URL string contains known properties
   */


  static hashContainsKnownProperties(hash) {
    if (StringUtils.isEmpty(hash)) {
      return false;
    }

    const parameters = UrlString.getDeserializedHash(hash);
    return !!(parameters.code || parameters.error_description || parameters.error || parameters.state);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
var KeyLocation;

(function (KeyLocation) {
  KeyLocation["SW"] = "sw";
  KeyLocation["UHW"] = "uhw";
})(KeyLocation || (KeyLocation = {}));

class PopTokenGenerator {
  constructor(cryptoUtils) {
    this.cryptoUtils = cryptoUtils;
  }

  async generateCnf(request) {
    const kidThumbprint = await this.cryptoUtils.getPublicKeyThumbprint(request);
    const reqCnf = {
      kid: kidThumbprint,
      xms_ksl: KeyLocation.SW
    };
    return this.cryptoUtils.base64Encode(JSON.stringify(reqCnf));
  }

  async signPopToken(accessToken, request) {
    const tokenClaims = AuthToken.extractTokenClaims(accessToken, this.cryptoUtils); // Deconstruct request to extract SHR parameters

    const {
      resourceRequestMethod,
      resourceRequestUri,
      shrClaims
    } = request;
    const resourceUrlString = resourceRequestUri ? new UrlString(resourceRequestUri) : undefined;
    const resourceUrlComponents = resourceUrlString?.getUrlComponents();

    if (!tokenClaims?.cnf?.kid) {
      throw ClientAuthError.createTokenClaimsRequiredError();
    }

    return await this.cryptoUtils.signJwt({
      at: accessToken,
      ts: TimeUtils.nowSeconds(),
      m: resourceRequestMethod?.toUpperCase(),
      u: resourceUrlComponents?.HostNameAndPort,
      nonce: this.cryptoUtils.createNewGuid(),
      p: resourceUrlComponents?.AbsolutePath,
      q: resourceUrlComponents?.QueryString ? [[], resourceUrlComponents.QueryString] : undefined,
      client_claims: shrClaims || undefined
    }, tokenClaims.cnf.kid);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * APP_METADATA Cache
 *
 * Key:Value Schema:
 *
 * Key: appmetadata-<environment>-<client_id>
 *
 * Value:
 * {
 *      clientId: client ID of the application
 *      environment: entity that issued the token, represented as a full host
 *      familyId: Family ID identifier, '1' represents Microsoft Family
 * }
 */

class AppMetadataEntity {
  /**
   * Generate AppMetadata Cache Key as per the schema: appmetadata-<environment>-<client_id>
   */
  generateAppMetadataKey() {
    return AppMetadataEntity.generateAppMetadataCacheKey(this.environment, this.clientId);
  }
  /**
   * Generate AppMetadata Cache Key
   */


  static generateAppMetadataCacheKey(environment, clientId) {
    const appMetaDataKeyArray = [APP_METADATA, environment, clientId];
    return appMetaDataKeyArray.join(Separators.CACHE_KEY_SEPARATOR).toLowerCase();
  }
  /**
   * Creates AppMetadataEntity
   * @param clientId
   * @param environment
   * @param familyId
   */


  static createAppMetadataEntity(clientId, environment, familyId) {
    const appMetadata = new AppMetadataEntity();
    appMetadata.clientId = clientId;
    appMetadata.environment = environment;

    if (familyId) {
      appMetadata.familyId = familyId;
    }

    return appMetadata;
  }
  /**
   * Validates an entity: checks for all expected params
   * @param entity
   */


  static isAppMetadataEntity(key, entity) {
    if (!entity) {
      return false;
    }

    return key.indexOf(APP_METADATA) === 0 && entity.hasOwnProperty("clientId") && entity.hasOwnProperty("environment");
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

/**
 * This class instance helps track the memory changes facilitating
 * decisions to read from and write to the persistent cache
 */
class TokenCacheContext {
  constructor(tokenCache, hasChanged) {
    this.cache = tokenCache;
    this.hasChanged = hasChanged;
  }
  /**
   * boolean which indicates the changes in cache
   */


  get cacheHasChanged() {
    return this.hasChanged;
  }
  /**
   * function to retrieve the token cache
   */


  get tokenCache() {
    return this.cache;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Class that handles response parsing.
 */

class ResponseHandler {
  constructor(clientId, cacheStorage, cryptoObj, logger, serializableCache, persistencePlugin) {
    this.clientId = clientId;
    this.cacheStorage = cacheStorage;
    this.cryptoObj = cryptoObj;
    this.logger = logger;
    this.serializableCache = serializableCache;
    this.persistencePlugin = persistencePlugin;
  }
  /**
   * Function which validates server authorization code response.
   * @param serverResponseHash
   * @param cachedState
   * @param cryptoObj
   */


  validateServerAuthorizationCodeResponse(serverResponseHash, cachedState, cryptoObj) {
    if (!serverResponseHash.state || !cachedState) {
      throw !serverResponseHash.state ? ClientAuthError.createStateNotFoundError("Server State") : ClientAuthError.createStateNotFoundError("Cached State");
    }

    if (decodeURIComponent(serverResponseHash.state) !== decodeURIComponent(cachedState)) {
      throw ClientAuthError.createStateMismatchError();
    } // Check for error


    if (serverResponseHash.error || serverResponseHash.error_description || serverResponseHash.suberror) {
      if (InteractionRequiredAuthError.isInteractionRequiredError(serverResponseHash.error, serverResponseHash.error_description, serverResponseHash.suberror)) {
        throw new InteractionRequiredAuthError(serverResponseHash.error || Constants.EMPTY_STRING, serverResponseHash.error_description, serverResponseHash.suberror);
      }

      throw new ServerError(serverResponseHash.error || Constants.EMPTY_STRING, serverResponseHash.error_description, serverResponseHash.suberror);
    }

    if (serverResponseHash.client_info) {
      buildClientInfo(serverResponseHash.client_info, cryptoObj);
    }
  }
  /**
   * Function which validates server authorization token response.
   * @param serverResponse
   */


  validateTokenResponse(serverResponse) {
    // Check for error
    if (serverResponse.error || serverResponse.error_description || serverResponse.suberror) {
      if (InteractionRequiredAuthError.isInteractionRequiredError(serverResponse.error, serverResponse.error_description, serverResponse.suberror)) {
        throw new InteractionRequiredAuthError(serverResponse.error, serverResponse.error_description, serverResponse.suberror);
      }

      const errString = `${serverResponse.error_codes} - [${serverResponse.timestamp}]: ${serverResponse.error_description} - Correlation ID: ${serverResponse.correlation_id} - Trace ID: ${serverResponse.trace_id}`;
      throw new ServerError(serverResponse.error, errString, serverResponse.suberror);
    }
  }
  /**
   * Returns a constructed token response based on given string. Also manages the cache updates and cleanups.
   * @param serverTokenResponse
   * @param authority
   */


  async handleServerTokenResponse(serverTokenResponse, authority, reqTimestamp, request, authCodePayload, oboAssertion, handlingRefreshTokenResponse) {
    // create an idToken object (not entity)
    let idTokenObj;

    if (serverTokenResponse.id_token) {
      idTokenObj = new AuthToken(serverTokenResponse.id_token || Constants.EMPTY_STRING, this.cryptoObj); // token nonce check (TODO: Add a warning if no nonce is given?)

      if (authCodePayload && !StringUtils.isEmpty(authCodePayload.nonce)) {
        if (idTokenObj.claims.nonce !== authCodePayload.nonce) {
          throw ClientAuthError.createNonceMismatchError();
        }
      }
    } // generate homeAccountId


    this.homeAccountIdentifier = AccountEntity.generateHomeAccountId(serverTokenResponse.client_info || Constants.EMPTY_STRING, authority.authorityType, this.logger, this.cryptoObj, idTokenObj); // save the response tokens

    let requestStateObj;

    if (!!authCodePayload && !!authCodePayload.state) {
      requestStateObj = ProtocolUtils.parseRequestState(this.cryptoObj, authCodePayload.state);
    }

    const cacheRecord = this.generateCacheRecord(serverTokenResponse, authority, reqTimestamp, idTokenObj, request.scopes, oboAssertion, authCodePayload);
    let cacheContext;

    try {
      if (this.persistencePlugin && this.serializableCache) {
        this.logger.verbose("Persistence enabled, calling beforeCacheAccess");
        cacheContext = new TokenCacheContext(this.serializableCache, true);
        await this.persistencePlugin.beforeCacheAccess(cacheContext);
      }
      /*
       * When saving a refreshed tokens to the cache, it is expected that the account that was used is present in the cache.
       * If not present, we should return null, as it's the case that another application called removeAccount in between
       * the calls to getAllAccounts and acquireTokenSilent. We should not overwrite that removal.
       */


      if (handlingRefreshTokenResponse && cacheRecord.account) {
        const key = cacheRecord.account.generateAccountKey();
        const account = this.cacheStorage.getAccount(key);

        if (!account) {
          this.logger.warning("Account used to refresh tokens not in persistence, refreshed tokens will not be stored in the cache");
          return ResponseHandler.generateAuthenticationResult(this.cryptoObj, authority, cacheRecord, false, request, idTokenObj, requestStateObj);
        }
      }

      this.cacheStorage.saveCacheRecord(cacheRecord);
    } finally {
      if (this.persistencePlugin && this.serializableCache && cacheContext) {
        this.logger.verbose("Persistence enabled, calling afterCacheAccess");
        await this.persistencePlugin.afterCacheAccess(cacheContext);
      }
    }

    return ResponseHandler.generateAuthenticationResult(this.cryptoObj, authority, cacheRecord, false, request, idTokenObj, requestStateObj);
  }
  /**
   * Generates CacheRecord
   * @param serverTokenResponse
   * @param idTokenObj
   * @param authority
   */


  generateCacheRecord(serverTokenResponse, authority, reqTimestamp, idTokenObj, requestScopes, oboAssertion, authCodePayload) {
    const env = authority.getPreferredCache();

    if (StringUtils.isEmpty(env)) {
      throw ClientAuthError.createInvalidCacheEnvironmentError();
    } // IdToken: non AAD scenarios can have empty realm


    let cachedIdToken;
    let cachedAccount;

    if (!StringUtils.isEmpty(serverTokenResponse.id_token) && !!idTokenObj) {
      cachedIdToken = IdTokenEntity.createIdTokenEntity(this.homeAccountIdentifier, env, serverTokenResponse.id_token || Constants.EMPTY_STRING, this.clientId, idTokenObj.claims.tid || Constants.EMPTY_STRING, oboAssertion);
      cachedAccount = this.generateAccountEntity(serverTokenResponse, idTokenObj, authority, oboAssertion, authCodePayload);
    } // AccessToken


    let cachedAccessToken = null;

    if (!StringUtils.isEmpty(serverTokenResponse.access_token)) {
      // If scopes not returned in server response, use request scopes
      const responseScopes = serverTokenResponse.scope ? ScopeSet.fromString(serverTokenResponse.scope) : new ScopeSet(requestScopes || []);
      /*
       * Use timestamp calculated before request
       * Server may return timestamps as strings, parse to numbers if so.
       */

      const expiresIn = (typeof serverTokenResponse.expires_in === "string" ? parseInt(serverTokenResponse.expires_in, 10) : serverTokenResponse.expires_in) || 0;
      const extExpiresIn = (typeof serverTokenResponse.ext_expires_in === "string" ? parseInt(serverTokenResponse.ext_expires_in, 10) : serverTokenResponse.ext_expires_in) || 0;
      const refreshIn = (typeof serverTokenResponse.refresh_in === "string" ? parseInt(serverTokenResponse.refresh_in, 10) : serverTokenResponse.refresh_in) || undefined;
      const tokenExpirationSeconds = reqTimestamp + expiresIn;
      const extendedTokenExpirationSeconds = tokenExpirationSeconds + extExpiresIn;
      const refreshOnSeconds = refreshIn && refreshIn > 0 ? reqTimestamp + refreshIn : undefined; // non AAD scenarios can have empty realm

      cachedAccessToken = AccessTokenEntity.createAccessTokenEntity(this.homeAccountIdentifier, env, serverTokenResponse.access_token || Constants.EMPTY_STRING, this.clientId, idTokenObj ? idTokenObj.claims.tid || Constants.EMPTY_STRING : authority.tenant, responseScopes.printScopes(), tokenExpirationSeconds, extendedTokenExpirationSeconds, this.cryptoObj, refreshOnSeconds, serverTokenResponse.token_type, oboAssertion);
    } // refreshToken


    let cachedRefreshToken = null;

    if (!StringUtils.isEmpty(serverTokenResponse.refresh_token)) {
      cachedRefreshToken = RefreshTokenEntity.createRefreshTokenEntity(this.homeAccountIdentifier, env, serverTokenResponse.refresh_token || Constants.EMPTY_STRING, this.clientId, serverTokenResponse.foci, oboAssertion);
    } // appMetadata


    let cachedAppMetadata = null;

    if (!StringUtils.isEmpty(serverTokenResponse.foci)) {
      cachedAppMetadata = AppMetadataEntity.createAppMetadataEntity(this.clientId, env, serverTokenResponse.foci);
    }

    return new CacheRecord(cachedAccount, cachedIdToken, cachedAccessToken, cachedRefreshToken, cachedAppMetadata);
  }
  /**
   * Generate Account
   * @param serverTokenResponse
   * @param idToken
   * @param authority
   */


  generateAccountEntity(serverTokenResponse, idToken, authority, oboAssertion, authCodePayload) {
    const authorityType = authority.authorityType;
    const cloudGraphHostName = authCodePayload ? authCodePayload.cloud_graph_host_name : "";
    const msGraphhost = authCodePayload ? authCodePayload.msgraph_host : ""; // ADFS does not require client_info in the response

    if (authorityType === AuthorityType.Adfs) {
      this.logger.verbose("Authority type is ADFS, creating ADFS account");
      return AccountEntity.createGenericAccount(authority, this.homeAccountIdentifier, idToken, oboAssertion, cloudGraphHostName, msGraphhost);
    } // This fallback applies to B2C as well as they fall under an AAD account type.


    if (StringUtils.isEmpty(serverTokenResponse.client_info) && authority.protocolMode === "AAD") {
      throw ClientAuthError.createClientInfoEmptyError();
    }

    return serverTokenResponse.client_info ? AccountEntity.createAccount(serverTokenResponse.client_info, this.homeAccountIdentifier, authority, idToken, oboAssertion, cloudGraphHostName, msGraphhost) : AccountEntity.createGenericAccount(authority, this.homeAccountIdentifier, idToken, oboAssertion, cloudGraphHostName, msGraphhost);
  }
  /**
   * Creates an @AuthenticationResult from @CacheRecord , @IdToken , and a boolean that states whether or not the result is from cache.
   *
   * Optionally takes a state string that is set as-is in the response.
   *
   * @param cacheRecord
   * @param idTokenObj
   * @param fromTokenCache
   * @param stateString
   */


  static async generateAuthenticationResult(cryptoObj, authority, cacheRecord, fromTokenCache, request, idTokenObj, requestState) {
    let accessToken = "";
    let responseScopes = [];
    let expiresOn = null;
    let extExpiresOn;
    let familyId = Constants.EMPTY_STRING;

    if (cacheRecord.accessToken) {
      if (cacheRecord.accessToken.tokenType === AuthenticationScheme.POP) {
        const popTokenGenerator = new PopTokenGenerator(cryptoObj);
        accessToken = await popTokenGenerator.signPopToken(cacheRecord.accessToken.secret, request);
      } else {
        accessToken = cacheRecord.accessToken.secret;
      }

      responseScopes = ScopeSet.fromString(cacheRecord.accessToken.target).asArray();
      expiresOn = new Date(Number(cacheRecord.accessToken.expiresOn) * 1000);
      extExpiresOn = new Date(Number(cacheRecord.accessToken.extendedExpiresOn) * 1000);
    }

    if (cacheRecord.appMetadata) {
      familyId = cacheRecord.appMetadata.familyId === THE_FAMILY_ID ? THE_FAMILY_ID : Constants.EMPTY_STRING;
    }

    const uid = idTokenObj?.claims.oid || idTokenObj?.claims.sub || Constants.EMPTY_STRING;
    const tid = idTokenObj?.claims.tid || Constants.EMPTY_STRING;
    return {
      authority: authority.canonicalAuthority,
      uniqueId: uid,
      tenantId: tid,
      scopes: responseScopes,
      account: cacheRecord.account ? cacheRecord.account.getAccountInfo() : null,
      idToken: idTokenObj ? idTokenObj.rawToken : Constants.EMPTY_STRING,
      idTokenClaims: idTokenObj ? idTokenObj.claims : {},
      accessToken: accessToken,
      fromCache: fromTokenCache,
      expiresOn: expiresOn,
      extExpiresOn: extExpiresOn,
      familyId: familyId,
      tokenType: cacheRecord.accessToken?.tokenType || Constants.EMPTY_STRING,
      state: requestState ? requestState.userRequestState : Constants.EMPTY_STRING,
      cloudGraphHostName: cacheRecord.account?.cloudGraphHostName || Constants.EMPTY_STRING,
      msGraphHost: cacheRecord.account?.msGraphHost || Constants.EMPTY_STRING
    };
  }

}

function ownKeys$8(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$8(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$8(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$8(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
/**
 * Oauth2.0 Authorization Code client
 */

class AuthorizationCodeClient extends BaseClient {
  constructor(configuration) {
    super(configuration);
  }
  /**
   * Creates the URL of the authorization request letting the user input credentials and consent to the
   * application. The URL target the /authorize endpoint of the authority configured in the
   * application object.
   *
   * Once the user inputs their credentials and consents, the authority will send a response to the redirect URI
   * sent in the request and should contain an authorization code, which can then be used to acquire tokens via
   * acquireToken(AuthorizationCodeRequest)
   * @param request
   */


  async getAuthCodeUrl(request) {
    const queryString = this.createAuthCodeUrlQueryString(request);
    return UrlString.appendQueryString(this.authority.authorizationEndpoint, queryString);
  }
  /**
   * API to acquire a token in exchange of 'authorization_code` acquired by the user in the first leg of the
   * authorization_code_grant
   * @param request
   */


  async acquireToken(request, authCodePayload) {
    this.logger.info("in acquireToken call");

    if (!request || StringUtils.isEmpty(request.code)) {
      throw ClientAuthError.createTokenRequestCannotBeMadeError();
    }

    const reqTimestamp = TimeUtils.nowSeconds();
    const response = await this.executeTokenRequest(this.authority, request);
    const responseHandler = new ResponseHandler(this.config.authOptions.clientId, this.cacheManager, this.cryptoUtils, this.logger, this.config.serializableCache, this.config.persistencePlugin); // Validate response. This function throws a server error if an error is returned by the server.

    responseHandler.validateTokenResponse(response.body);
    return await responseHandler.handleServerTokenResponse(response.body, this.authority, reqTimestamp, request, authCodePayload);
  }
  /**
   * Handles the hash fragment response from public client code request. Returns a code response used by
   * the client to exchange for a token in acquireToken.
   * @param hashFragment
   */


  handleFragmentResponse(hashFragment, cachedState) {
    // Handle responses.
    const responseHandler = new ResponseHandler(this.config.authOptions.clientId, this.cacheManager, this.cryptoUtils, this.logger, null, null); // Deserialize hash fragment response parameters.

    const hashUrlString = new UrlString(hashFragment); // Deserialize hash fragment response parameters.

    const serverParams = UrlString.getDeserializedHash(hashUrlString.getHash()); // Get code response

    responseHandler.validateServerAuthorizationCodeResponse(serverParams, cachedState, this.cryptoUtils); // throw when there is no auth code in the response

    if (!serverParams.code) {
      throw ClientAuthError.createNoAuthCodeInServerResponseError();
    }

    return _objectSpread$8(_objectSpread$8({}, serverParams), {}, {
      // Code param is optional in ServerAuthorizationCodeResponse but required in AuthorizationCodePaylod
      code: serverParams.code
    });
  }
  /**
   * Use to log out the current user, and redirect the user to the postLogoutRedirectUri.
   * Default behaviour is to redirect the user to `window.location.href`.
   * @param authorityUri
   */


  getLogoutUri(logoutRequest) {
    // Throw error if logoutRequest is null/undefined
    if (!logoutRequest) {
      throw ClientConfigurationError.createEmptyLogoutRequestError();
    }

    if (logoutRequest.account) {
      // Clear given account.
      this.cacheManager.removeAccount(AccountEntity.generateAccountCacheKey(logoutRequest.account));
    } else {
      // Clear all accounts and tokens
      this.cacheManager.clear();
    }

    const queryString = this.createLogoutUrlQueryString(logoutRequest); // Construct logout URI.

    return StringUtils.isEmpty(queryString) ? this.authority.endSessionEndpoint : `${this.authority.endSessionEndpoint}?${queryString}`;
  }
  /**
   * Executes POST request to token endpoint
   * @param authority
   * @param request
   */


  async executeTokenRequest(authority, request) {
    const thumbprint = {
      clientId: this.config.authOptions.clientId,
      authority: authority.canonicalAuthority,
      scopes: request.scopes
    };
    const requestBody = await this.createTokenRequestBody(request);
    const queryParameters = this.createTokenQueryParameters(request);
    const headers = this.createDefaultTokenRequestHeaders();
    const endpoint = StringUtils.isEmpty(queryParameters) ? authority.tokenEndpoint : `${authority.tokenEndpoint}?${queryParameters}`;
    return this.executePostToTokenEndpoint(endpoint, requestBody, headers, thumbprint);
  }
  /**
   * Creates query string for the /token request
   * @param request
   */


  createTokenQueryParameters(request) {
    const parameterBuilder = new RequestParameterBuilder();

    if (request.tokenQueryParameters) {
      parameterBuilder.addExtraQueryParameters(request.tokenQueryParameters);
    }

    return parameterBuilder.createQueryString();
  }
  /**
   * Generates a map for all the params to be sent to the service
   * @param request
   */


  async createTokenRequestBody(request) {
    const parameterBuilder = new RequestParameterBuilder();
    parameterBuilder.addClientId(this.config.authOptions.clientId); // validate the redirectUri (to be a non null value)

    parameterBuilder.addRedirectUri(request.redirectUri); // Add scope array, parameter builder will add default scopes and dedupe

    parameterBuilder.addScopes(request.scopes); // add code: user set, not validated

    parameterBuilder.addAuthorizationCode(request.code); // Add library metadata

    parameterBuilder.addLibraryInfo(this.config.libraryInfo);
    parameterBuilder.addThrottling();

    if (this.serverTelemetryManager) {
      parameterBuilder.addServerTelemetry(this.serverTelemetryManager);
    } // add code_verifier if passed


    if (request.codeVerifier) {
      parameterBuilder.addCodeVerifier(request.codeVerifier);
    }

    if (this.config.clientCredentials.clientSecret) {
      parameterBuilder.addClientSecret(this.config.clientCredentials.clientSecret);
    }

    if (this.config.clientCredentials.clientAssertion) {
      const clientAssertion = this.config.clientCredentials.clientAssertion;
      parameterBuilder.addClientAssertion(clientAssertion.assertion);
      parameterBuilder.addClientAssertionType(clientAssertion.assertionType);
    }

    parameterBuilder.addGrantType(GrantType.AUTHORIZATION_CODE_GRANT);
    parameterBuilder.addClientInfo();

    if (request.authenticationScheme === AuthenticationScheme.POP) {
      const popTokenGenerator = new PopTokenGenerator(this.cryptoUtils);
      const cnfString = await popTokenGenerator.generateCnf(request);
      parameterBuilder.addPopToken(cnfString);
    }

    const correlationId = request.correlationId || this.config.cryptoInterface.createNewGuid();
    parameterBuilder.addCorrelationId(correlationId);

    if (!StringUtils.isEmptyObj(request.claims) || this.config.authOptions.clientCapabilities && this.config.authOptions.clientCapabilities.length > 0) {
      parameterBuilder.addClaims(request.claims, this.config.authOptions.clientCapabilities);
    }

    return parameterBuilder.createQueryString();
  }
  /**
   * This API validates the `AuthorizationCodeUrlRequest` and creates a URL
   * @param request
   */


  createAuthCodeUrlQueryString(request) {
    const parameterBuilder = new RequestParameterBuilder();
    parameterBuilder.addClientId(this.config.authOptions.clientId);
    const requestScopes = [...(request.scopes || []), ...(request.extraScopesToConsent || [])];
    parameterBuilder.addScopes(requestScopes); // validate the redirectUri (to be a non null value)

    parameterBuilder.addRedirectUri(request.redirectUri); // generate the correlationId if not set by the user and add

    const correlationId = request.correlationId || this.config.cryptoInterface.createNewGuid();
    parameterBuilder.addCorrelationId(correlationId); // add response_mode. If not passed in it defaults to query.

    parameterBuilder.addResponseMode(request.responseMode); // add response_type = code

    parameterBuilder.addResponseTypeCode(); // add library info parameters

    parameterBuilder.addLibraryInfo(this.config.libraryInfo); // add client_info=1

    parameterBuilder.addClientInfo();

    if (request.codeChallenge && request.codeChallengeMethod) {
      parameterBuilder.addCodeChallengeParams(request.codeChallenge, request.codeChallengeMethod);
    }

    if (request.prompt) {
      parameterBuilder.addPrompt(request.prompt);
    }

    if (request.domainHint) {
      parameterBuilder.addDomainHint(request.domainHint);
    } // Add sid or loginHint with preference for sid -> loginHint -> username of AccountInfo object


    if (request.prompt !== PromptValue.SELECT_ACCOUNT) {
      // AAD will throw if prompt=select_account is passed with an account hint
      if (request.sid && request.prompt === PromptValue.NONE) {
        // SessionID is only used in silent calls
        this.logger.verbose("createAuthCodeUrlQueryString: Prompt is none, adding sid from request");
        parameterBuilder.addSid(request.sid);
      } else if (request.account) {
        const accountSid = this.extractAccountSid(request.account); // If account and loginHint are provided, we will check account first for sid before adding loginHint

        if (accountSid && request.prompt === PromptValue.NONE) {
          // SessionId is only used in silent calls
          this.logger.verbose("createAuthCodeUrlQueryString: Prompt is none, adding sid from account");
          parameterBuilder.addSid(accountSid);
        } else if (request.loginHint) {
          this.logger.verbose("createAuthCodeUrlQueryString: Adding login_hint from request");
          parameterBuilder.addLoginHint(request.loginHint);
        } else if (request.account.username) {
          // Fallback to account username if provided
          this.logger.verbose("createAuthCodeUrlQueryString: Adding login_hint from account");
          parameterBuilder.addLoginHint(request.account.username);
        }
      } else if (request.loginHint) {
        this.logger.verbose("createAuthCodeUrlQueryString: No account, adding login_hint from request");
        parameterBuilder.addLoginHint(request.loginHint);
      }
    } else {
      this.logger.verbose("createAuthCodeUrlQueryString: Prompt is select_account, ignoring account hints");
    }

    if (request.nonce) {
      parameterBuilder.addNonce(request.nonce);
    }

    if (request.state) {
      parameterBuilder.addState(request.state);
    }

    if (!StringUtils.isEmpty(request.claims) || this.config.authOptions.clientCapabilities && this.config.authOptions.clientCapabilities.length > 0) {
      parameterBuilder.addClaims(request.claims, this.config.authOptions.clientCapabilities);
    }

    if (request.extraQueryParameters) {
      parameterBuilder.addExtraQueryParameters(request.extraQueryParameters);
    }

    return parameterBuilder.createQueryString();
  }
  /**
   * This API validates the `EndSessionRequest` and creates a URL
   * @param request
   */


  createLogoutUrlQueryString(request) {
    const parameterBuilder = new RequestParameterBuilder();

    if (request.postLogoutRedirectUri) {
      parameterBuilder.addPostLogoutRedirectUri(request.postLogoutRedirectUri);
    }

    if (request.correlationId) {
      parameterBuilder.addCorrelationId(request.correlationId);
    }

    if (request.idTokenHint) {
      parameterBuilder.addIdTokenHint(request.idTokenHint);
    }

    return parameterBuilder.createQueryString();
  }
  /**
   * Helper to get sid from account. Returns null if idTokenClaims are not present or sid is not present.
   * @param account
   */


  extractAccountSid(account) {
    if (account.idTokenClaims) {
      const tokenClaims = account.idTokenClaims;
      return tokenClaims.sid || null;
    }

    return null;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * OAuth2.0 Device code client
 */

class DeviceCodeClient extends BaseClient {
  constructor(configuration) {
    super(configuration);
  }
  /**
   * Gets device code from device code endpoint, calls back to with device code response, and
   * polls token endpoint to exchange device code for tokens
   * @param request
   */


  async acquireToken(request) {
    const deviceCodeResponse = await this.getDeviceCode(request);
    request.deviceCodeCallback(deviceCodeResponse);
    const reqTimestamp = TimeUtils.nowSeconds();
    const response = await this.acquireTokenWithDeviceCode(request, deviceCodeResponse);
    const responseHandler = new ResponseHandler(this.config.authOptions.clientId, this.cacheManager, this.cryptoUtils, this.logger, this.config.serializableCache, this.config.persistencePlugin); // Validate response. This function throws a server error if an error is returned by the server.

    responseHandler.validateTokenResponse(response);
    return await responseHandler.handleServerTokenResponse(response, this.authority, reqTimestamp, request);
  }
  /**
   * Creates device code request and executes http GET
   * @param request
   */


  async getDeviceCode(request) {
    const queryString = this.createQueryString(request);
    const headers = this.createDefaultTokenRequestHeaders();
    const thumbprint = {
      clientId: this.config.authOptions.clientId,
      authority: request.authority,
      scopes: request.scopes
    };
    return this.executePostRequestToDeviceCodeEndpoint(this.authority.deviceCodeEndpoint, queryString, headers, thumbprint);
  }
  /**
   * Executes POST request to device code endpoint
   * @param deviceCodeEndpoint
   * @param queryString
   * @param headers
   */


  async executePostRequestToDeviceCodeEndpoint(deviceCodeEndpoint, queryString, headers, thumbprint) {
    const {
      body: {
        user_code: userCode,
        device_code: deviceCode,
        verification_uri: verificationUri,
        expires_in: expiresIn,
        interval,
        message
      }
    } = await this.networkManager.sendPostRequest(thumbprint, deviceCodeEndpoint, {
      body: queryString,
      headers: headers
    });
    return {
      userCode,
      deviceCode,
      verificationUri,
      expiresIn,
      interval,
      message
    };
  }
  /**
   * Create device code endpoint query parameters and returns string
   */


  createQueryString(request) {
    const parameterBuilder = new RequestParameterBuilder();
    parameterBuilder.addScopes(request.scopes);
    parameterBuilder.addClientId(this.config.authOptions.clientId);

    if (!StringUtils.isEmpty(request.claims) || this.config.authOptions.clientCapabilities && this.config.authOptions.clientCapabilities.length > 0) {
      parameterBuilder.addClaims(request.claims, this.config.authOptions.clientCapabilities);
    }

    return parameterBuilder.createQueryString();
  }
  /**
   * Creates token request with device code response and polls token endpoint at interval set by the device code
   * response
   * @param request
   * @param deviceCodeResponse
   */


  async acquireTokenWithDeviceCode(request, deviceCodeResponse) {
    const requestBody = this.createTokenRequestBody(request, deviceCodeResponse);
    const headers = this.createDefaultTokenRequestHeaders();
    const userSpecifiedTimeout = request.timeout ? TimeUtils.nowSeconds() + request.timeout : undefined;
    const deviceCodeExpirationTime = TimeUtils.nowSeconds() + deviceCodeResponse.expiresIn;
    const pollingIntervalMilli = deviceCodeResponse.interval * 1000;
    /*
     * Poll token endpoint while (device code is not expired AND operation has not been cancelled by
     * setting CancellationToken.cancel = true). POST request is sent at interval set by pollingIntervalMilli
     */

    return new Promise((resolve, reject) => {
      const intervalId = setInterval(async () => {
        try {
          if (request.cancel) {
            this.logger.error("Token request cancelled by setting DeviceCodeRequest.cancel = true");
            clearInterval(intervalId);
            reject(ClientAuthError.createDeviceCodeCancelledError());
          } else if (userSpecifiedTimeout && userSpecifiedTimeout < deviceCodeExpirationTime && TimeUtils.nowSeconds() > userSpecifiedTimeout) {
            this.logger.error(`User defined timeout for device code polling reached. The timeout was set for ${userSpecifiedTimeout}`);
            clearInterval(intervalId);
            reject(ClientAuthError.createUserTimeoutReachedError());
          } else if (TimeUtils.nowSeconds() > deviceCodeExpirationTime) {
            if (userSpecifiedTimeout) {
              this.logger.verbose(`User specified timeout ignored as the device code has expired before the timeout elapsed. The user specified timeout was set for ${userSpecifiedTimeout}`);
            }

            this.logger.error(`Device code expired. Expiration time of device code was ${deviceCodeExpirationTime}`);
            clearInterval(intervalId);
            reject(ClientAuthError.createDeviceCodeExpiredError());
          } else {
            const thumbprint = {
              clientId: this.config.authOptions.clientId,
              authority: request.authority,
              scopes: request.scopes
            };
            const response = await this.executePostToTokenEndpoint(this.authority.tokenEndpoint, requestBody, headers, thumbprint);

            if (response.body && response.body.error === Constants.AUTHORIZATION_PENDING) {
              // user authorization is pending. Sleep for polling interval and try again
              this.logger.info(response.body.error_description || "no_error_description");
            } else {
              clearInterval(intervalId);
              resolve(response.body);
            }
          }
        } catch (error) {
          clearInterval(intervalId);
          reject(error);
        }
      }, pollingIntervalMilli);
    });
  }
  /**
   * Creates query parameters and converts to string.
   * @param request
   * @param deviceCodeResponse
   */


  createTokenRequestBody(request, deviceCodeResponse) {
    const requestParameters = new RequestParameterBuilder();
    requestParameters.addScopes(request.scopes);
    requestParameters.addClientId(this.config.authOptions.clientId);
    requestParameters.addGrantType(GrantType.DEVICE_CODE_GRANT);
    requestParameters.addDeviceCode(deviceCodeResponse.deviceCode);
    const correlationId = request.correlationId || this.config.cryptoInterface.createNewGuid();
    requestParameters.addCorrelationId(correlationId);
    requestParameters.addClientInfo();
    requestParameters.addLibraryInfo(this.config.libraryInfo);
    requestParameters.addThrottling();

    if (this.serverTelemetryManager) {
      requestParameters.addServerTelemetry(this.serverTelemetryManager);
    }

    if (!StringUtils.isEmptyObj(request.claims) || this.config.authOptions.clientCapabilities && this.config.authOptions.clientCapabilities.length > 0) {
      requestParameters.addClaims(request.claims, this.config.authOptions.clientCapabilities);
    }

    return requestParameters.createQueryString();
  }

}

function ownKeys$7(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$7(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$7(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$7(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
/**
 * OAuth2.0 refresh token client
 */

class RefreshTokenClient extends BaseClient {
  constructor(configuration) {
    super(configuration);
  }

  async acquireToken(request) {
    const reqTimestamp = TimeUtils.nowSeconds();
    const response = await this.executeTokenRequest(request, this.authority);
    const responseHandler = new ResponseHandler(this.config.authOptions.clientId, this.cacheManager, this.cryptoUtils, this.logger, this.config.serializableCache, this.config.persistencePlugin);
    responseHandler.validateTokenResponse(response.body);
    return responseHandler.handleServerTokenResponse(response.body, this.authority, reqTimestamp, request, undefined, undefined, true);
  }
  /**
   * Gets cached refresh token and attaches to request, then calls acquireToken API
   * @param request
   */


  async acquireTokenByRefreshToken(request) {
    // Cannot renew token if no request object is given.
    if (!request) {
      throw ClientConfigurationError.createEmptyTokenRequestError();
    } // We currently do not support silent flow for account === null use cases; This will be revisited for confidential flow usecases


    if (!request.account) {
      throw ClientAuthError.createNoAccountInSilentRequestError();
    } // try checking if FOCI is enabled for the given application


    const isFOCI = this.cacheManager.isAppMetadataFOCI(request.account.environment, this.config.authOptions.clientId); // if the app is part of the family, retrive a Family refresh token if present and make a refreshTokenRequest

    if (isFOCI) {
      try {
        return this.acquireTokenWithCachedRefreshToken(request, true);
      } catch (e) {
        const noFamilyRTInCache = e instanceof ClientAuthError && e.errorCode === ClientAuthErrorMessage.noTokensFoundError.code;
        const clientMismatchErrorWithFamilyRT = e instanceof ServerError && e.errorCode === Errors.INVALID_GRANT_ERROR && e.subError === Errors.CLIENT_MISMATCH_ERROR; // if family Refresh Token (FRT) cache acquisition fails or if client_mismatch error is seen with FRT, reattempt with application Refresh Token (ART)

        if (noFamilyRTInCache || clientMismatchErrorWithFamilyRT) {
          return this.acquireTokenWithCachedRefreshToken(request, false); // throw in all other cases
        } else {
          throw e;
        }
      }
    } // fall back to application refresh token acquisition


    return this.acquireTokenWithCachedRefreshToken(request, false);
  }
  /**
   * makes a network call to acquire tokens by exchanging RefreshToken available in userCache; throws if refresh token is not cached
   * @param request
   */


  async acquireTokenWithCachedRefreshToken(request, foci) {
    // fetches family RT or application RT based on FOCI value
    const refreshToken = this.cacheManager.readRefreshTokenFromCache(this.config.authOptions.clientId, request.account, foci); // no refresh Token

    if (!refreshToken) {
      throw ClientAuthError.createNoTokensFoundError();
    }

    const refreshTokenRequest = _objectSpread$7(_objectSpread$7({}, request), {}, {
      refreshToken: refreshToken.secret,
      authenticationScheme: request.authenticationScheme || AuthenticationScheme.BEARER
    });

    return this.acquireToken(refreshTokenRequest);
  }
  /**
   * Constructs the network message and makes a NW call to the underlying secure token service
   * @param request
   * @param authority
   */


  async executeTokenRequest(request, authority) {
    const requestBody = await this.createTokenRequestBody(request);
    const queryParameters = this.createTokenQueryParameters(request);
    const headers = this.createDefaultTokenRequestHeaders();
    const thumbprint = {
      clientId: this.config.authOptions.clientId,
      authority: authority.canonicalAuthority,
      scopes: request.scopes
    };
    const endpoint = UrlString.appendQueryString(authority.tokenEndpoint, queryParameters);
    return this.executePostToTokenEndpoint(endpoint, requestBody, headers, thumbprint);
  }
  /**
   * Creates query string for the /token request
   * @param request
   */


  createTokenQueryParameters(request) {
    const parameterBuilder = new RequestParameterBuilder();

    if (request.tokenQueryParameters) {
      parameterBuilder.addExtraQueryParameters(request.tokenQueryParameters);
    }

    return parameterBuilder.createQueryString();
  }
  /**
   * Helper function to create the token request body
   * @param request
   */


  async createTokenRequestBody(request) {
    const parameterBuilder = new RequestParameterBuilder();
    parameterBuilder.addClientId(this.config.authOptions.clientId);
    parameterBuilder.addScopes(request.scopes);
    parameterBuilder.addGrantType(GrantType.REFRESH_TOKEN_GRANT);
    parameterBuilder.addClientInfo();
    parameterBuilder.addLibraryInfo(this.config.libraryInfo);
    parameterBuilder.addThrottling();

    if (this.serverTelemetryManager) {
      parameterBuilder.addServerTelemetry(this.serverTelemetryManager);
    }

    const correlationId = request.correlationId || this.config.cryptoInterface.createNewGuid();
    parameterBuilder.addCorrelationId(correlationId);
    parameterBuilder.addRefreshToken(request.refreshToken);

    if (this.config.clientCredentials.clientSecret) {
      parameterBuilder.addClientSecret(this.config.clientCredentials.clientSecret);
    }

    if (this.config.clientCredentials.clientAssertion) {
      const clientAssertion = this.config.clientCredentials.clientAssertion;
      parameterBuilder.addClientAssertion(clientAssertion.assertion);
      parameterBuilder.addClientAssertionType(clientAssertion.assertionType);
    }

    if (request.authenticationScheme === AuthenticationScheme.POP) {
      const popTokenGenerator = new PopTokenGenerator(this.cryptoUtils);
      parameterBuilder.addPopToken(await popTokenGenerator.generateCnf(request));
    }

    if (!StringUtils.isEmptyObj(request.claims) || this.config.authOptions.clientCapabilities && this.config.authOptions.clientCapabilities.length > 0) {
      parameterBuilder.addClaims(request.claims, this.config.authOptions.clientCapabilities);
    }

    return parameterBuilder.createQueryString();
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * OAuth2.0 client credential grant
 */

class ClientCredentialClient extends BaseClient {
  constructor(configuration) {
    super(configuration);
  }
  /**
   * Public API to acquire a token with ClientCredential Flow for Confidential clients
   * @param request
   */


  async acquireToken(request) {
    this.scopeSet = new ScopeSet(request.scopes || []);

    if (request.skipCache) {
      return await this.executeTokenRequest(request, this.authority);
    }

    const cachedAuthenticationResult = await this.getCachedAuthenticationResult(request);

    if (cachedAuthenticationResult) {
      return cachedAuthenticationResult;
    } else {
      return await this.executeTokenRequest(request, this.authority);
    }
  }
  /**
   * looks up cache if the tokens are cached already
   */


  async getCachedAuthenticationResult(request) {
    const cachedAccessToken = this.readAccessTokenFromCache();

    if (!cachedAccessToken || TimeUtils.isTokenExpired(cachedAccessToken.expiresOn, this.config.systemOptions.tokenRenewalOffsetSeconds)) {
      return null;
    }

    return await ResponseHandler.generateAuthenticationResult(this.cryptoUtils, this.authority, {
      account: null,
      idToken: null,
      accessToken: cachedAccessToken,
      refreshToken: null,
      appMetadata: null
    }, true, request);
  }
  /**
   * Reads access token from the cache
   * TODO: Move this call to cacheManager instead
   */


  readAccessTokenFromCache() {
    const accessTokenFilter = {
      homeAccountId: "",
      environment: this.authority.canonicalAuthorityUrlComponents.HostNameAndPort,
      credentialType: CredentialType.ACCESS_TOKEN,
      clientId: this.config.authOptions.clientId,
      realm: this.authority.tenant,
      target: this.scopeSet.printScopesLowerCase()
    };
    const credentialCache = this.cacheManager.getCredentialsFilteredBy(accessTokenFilter);
    const accessTokens = Object.keys(credentialCache.accessTokens).map(key => credentialCache.accessTokens[key]);

    if (accessTokens.length < 1) {
      return null;
    } else if (accessTokens.length > 1) {
      throw ClientAuthError.createMultipleMatchingTokensInCacheError();
    }

    return accessTokens[0];
  }
  /**
   * Makes a network call to request the token from the service
   * @param request
   * @param authority
   */


  async executeTokenRequest(request, authority) {
    const requestBody = this.createTokenRequestBody(request);
    const headers = this.createDefaultTokenRequestHeaders();
    const thumbprint = {
      clientId: this.config.authOptions.clientId,
      authority: request.authority,
      scopes: request.scopes
    };
    const reqTimestamp = TimeUtils.nowSeconds();
    const response = await this.executePostToTokenEndpoint(authority.tokenEndpoint, requestBody, headers, thumbprint);
    const responseHandler = new ResponseHandler(this.config.authOptions.clientId, this.cacheManager, this.cryptoUtils, this.logger, this.config.serializableCache, this.config.persistencePlugin);
    responseHandler.validateTokenResponse(response.body);
    const tokenResponse = await responseHandler.handleServerTokenResponse(response.body, this.authority, reqTimestamp, request);
    return tokenResponse;
  }
  /**
   * generate the request to the server in the acceptable format
   * @param request
   */


  createTokenRequestBody(request) {
    const parameterBuilder = new RequestParameterBuilder();
    parameterBuilder.addClientId(this.config.authOptions.clientId);
    parameterBuilder.addScopes(request.scopes, false);
    parameterBuilder.addGrantType(GrantType.CLIENT_CREDENTIALS_GRANT);
    parameterBuilder.addLibraryInfo(this.config.libraryInfo);
    parameterBuilder.addThrottling();

    if (this.serverTelemetryManager) {
      parameterBuilder.addServerTelemetry(this.serverTelemetryManager);
    }

    const correlationId = request.correlationId || this.config.cryptoInterface.createNewGuid();
    parameterBuilder.addCorrelationId(correlationId);

    if (this.config.clientCredentials.clientSecret) {
      parameterBuilder.addClientSecret(this.config.clientCredentials.clientSecret);
    }

    if (this.config.clientCredentials.clientAssertion) {
      const clientAssertion = this.config.clientCredentials.clientAssertion;
      parameterBuilder.addClientAssertion(clientAssertion.assertion);
      parameterBuilder.addClientAssertionType(clientAssertion.assertionType);
    }

    if (!StringUtils.isEmptyObj(request.claims) || this.config.authOptions.clientCapabilities && this.config.authOptions.clientCapabilities.length > 0) {
      parameterBuilder.addClaims(request.claims, this.config.authOptions.clientCapabilities);
    }

    return parameterBuilder.createQueryString();
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * On-Behalf-Of client
 */

class OnBehalfOfClient extends BaseClient {
  constructor(configuration) {
    super(configuration);
  }
  /**
   * Public API to acquire tokens with on behalf of flow
   * @param request
   */


  async acquireToken(request) {
    this.scopeSet = new ScopeSet(request.scopes || []);

    if (request.skipCache) {
      return await this.executeTokenRequest(request, this.authority);
    }

    const cachedAuthenticationResult = await this.getCachedAuthenticationResult(request);

    if (cachedAuthenticationResult) {
      return cachedAuthenticationResult;
    } else {
      return await this.executeTokenRequest(request, this.authority);
    }
  }
  /**
   * look up cache for tokens
   * @param request
   */


  async getCachedAuthenticationResult(request) {
    const cachedAccessToken = this.readAccessTokenFromCache(request);

    if (!cachedAccessToken || TimeUtils.isTokenExpired(cachedAccessToken.expiresOn, this.config.systemOptions.tokenRenewalOffsetSeconds)) {
      return null;
    }

    const cachedIdToken = this.readIdTokenFromCache(request);
    let idTokenObject;
    let cachedAccount = null;

    if (cachedIdToken) {
      idTokenObject = new AuthToken(cachedIdToken.secret, this.config.cryptoInterface);
      const localAccountId = idTokenObject.claims.oid ? idTokenObject.claims.oid : idTokenObject.claims.sub;
      const accountInfo = {
        homeAccountId: cachedIdToken.homeAccountId,
        environment: cachedIdToken.environment,
        tenantId: cachedIdToken.realm,
        username: Constants.EMPTY_STRING,
        localAccountId: localAccountId || ""
      };
      cachedAccount = this.readAccountFromCache(accountInfo);
    }

    return await ResponseHandler.generateAuthenticationResult(this.cryptoUtils, this.authority, {
      account: cachedAccount,
      accessToken: cachedAccessToken,
      idToken: cachedIdToken,
      refreshToken: null,
      appMetadata: null
    }, true, request, idTokenObject);
  }
  /**
   * read access token from cache TODO: CacheManager API should be used here
   * @param request
   */


  readAccessTokenFromCache(request) {
    const accessTokenFilter = {
      environment: this.authority.canonicalAuthorityUrlComponents.HostNameAndPort,
      credentialType: CredentialType.ACCESS_TOKEN,
      clientId: this.config.authOptions.clientId,
      realm: this.authority.tenant,
      target: this.scopeSet.printScopesLowerCase(),
      oboAssertion: request.oboAssertion
    };
    const credentialCache = this.cacheManager.getCredentialsFilteredBy(accessTokenFilter);
    const accessTokens = Object.keys(credentialCache.accessTokens).map(key => credentialCache.accessTokens[key]);
    const numAccessTokens = accessTokens.length;

    if (numAccessTokens < 1) {
      return null;
    } else if (numAccessTokens > 1) {
      throw ClientAuthError.createMultipleMatchingTokensInCacheError();
    }

    return accessTokens[0];
  }
  /**
   * read idtoken from cache TODO: CacheManager API should be used here instead
   * @param request
   */


  readIdTokenFromCache(request) {
    const idTokenFilter = {
      environment: this.authority.canonicalAuthorityUrlComponents.HostNameAndPort,
      credentialType: CredentialType.ID_TOKEN,
      clientId: this.config.authOptions.clientId,
      realm: this.authority.tenant,
      oboAssertion: request.oboAssertion
    };
    const credentialCache = this.cacheManager.getCredentialsFilteredBy(idTokenFilter);
    const idTokens = Object.keys(credentialCache.idTokens).map(key => credentialCache.idTokens[key]); // When acquiring a token on behalf of an application, there might not be an id token in the cache

    if (idTokens.length < 1) {
      return null;
    }

    return idTokens[0];
  }
  /**
   * read account from cache, TODO: CacheManager API should be used here instead
   * @param account
   */


  readAccountFromCache(account) {
    return this.cacheManager.readAccountFromCache(account);
  }
  /**
   * Make a network call to the server requesting credentials
   * @param request
   * @param authority
   */


  async executeTokenRequest(request, authority) {
    const requestBody = this.createTokenRequestBody(request);
    const headers = this.createDefaultTokenRequestHeaders();
    const thumbprint = {
      clientId: this.config.authOptions.clientId,
      authority: request.authority,
      scopes: request.scopes
    };
    const reqTimestamp = TimeUtils.nowSeconds();
    const response = await this.executePostToTokenEndpoint(authority.tokenEndpoint, requestBody, headers, thumbprint);
    const responseHandler = new ResponseHandler(this.config.authOptions.clientId, this.cacheManager, this.cryptoUtils, this.logger, this.config.serializableCache, this.config.persistencePlugin);
    responseHandler.validateTokenResponse(response.body);
    const tokenResponse = await responseHandler.handleServerTokenResponse(response.body, this.authority, reqTimestamp, request);
    return tokenResponse;
  }
  /**
   * generate a server request in accepable format
   * @param request
   */


  createTokenRequestBody(request) {
    const parameterBuilder = new RequestParameterBuilder();
    parameterBuilder.addClientId(this.config.authOptions.clientId);
    parameterBuilder.addScopes(request.scopes);
    parameterBuilder.addGrantType(GrantType.JWT_BEARER);
    parameterBuilder.addClientInfo();
    parameterBuilder.addLibraryInfo(this.config.libraryInfo);
    parameterBuilder.addThrottling();

    if (this.serverTelemetryManager) {
      parameterBuilder.addServerTelemetry(this.serverTelemetryManager);
    }

    const correlationId = request.correlationId || this.config.cryptoInterface.createNewGuid();
    parameterBuilder.addCorrelationId(correlationId);
    parameterBuilder.addRequestTokenUse(AADServerParamKeys.ON_BEHALF_OF);
    parameterBuilder.addOboAssertion(request.oboAssertion);

    if (this.config.clientCredentials.clientSecret) {
      parameterBuilder.addClientSecret(this.config.clientCredentials.clientSecret);
    }

    if (this.config.clientCredentials.clientAssertion) {
      const clientAssertion = this.config.clientCredentials.clientAssertion;
      parameterBuilder.addClientAssertion(clientAssertion.assertion);
      parameterBuilder.addClientAssertionType(clientAssertion.assertionType);
    }

    return parameterBuilder.createQueryString();
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class SilentFlowClient extends BaseClient {
  constructor(configuration) {
    super(configuration);
  }
  /**
   * Retrieves a token from cache if it is still valid, or uses the cached refresh token to renew
   * the given token and returns the renewed token
   * @param request
   */


  async acquireToken(request) {
    try {
      return await this.acquireCachedToken(request);
    } catch (e) {
      if (e instanceof ClientAuthError && e.errorCode === ClientAuthErrorMessage.tokenRefreshRequired.code) {
        const refreshTokenClient = new RefreshTokenClient(this.config);
        return refreshTokenClient.acquireTokenByRefreshToken(request);
      } else {
        throw e;
      }
    }
  }
  /**
   * Retrieves token from cache or throws an error if it must be refreshed.
   * @param request
   */


  async acquireCachedToken(request) {
    // Cannot renew token if no request object is given.
    if (!request) {
      throw ClientConfigurationError.createEmptyTokenRequestError();
    } // We currently do not support silent flow for account === null use cases; This will be revisited for confidential flow usecases


    if (!request.account) {
      throw ClientAuthError.createNoAccountInSilentRequestError();
    }

    const requestScopes = new ScopeSet(request.scopes || []);
    const environment = request.authority || this.authority.getPreferredCache();
    const authScheme = request.authenticationScheme || AuthenticationScheme.BEARER;
    const cacheRecord = this.cacheManager.readCacheRecord(request.account, this.config.authOptions.clientId, requestScopes, environment, authScheme);

    if (request.forceRefresh || !StringUtils.isEmptyObj(request.claims) || !cacheRecord.accessToken || TimeUtils.isTokenExpired(cacheRecord.accessToken.expiresOn, this.config.systemOptions.tokenRenewalOffsetSeconds) || cacheRecord.accessToken.refreshOn && TimeUtils.isTokenExpired(cacheRecord.accessToken.refreshOn, 0)) {
      // Must refresh due to request parameters, or expired or non-existent access_token
      throw ClientAuthError.createRefreshRequiredError();
    }

    if (this.config.serverTelemetryManager) {
      this.config.serverTelemetryManager.incrementCacheHits();
    }

    return await this.generateResultFromCacheRecord(cacheRecord, request);
  }
  /**
   * Helper function to build response object from the CacheRecord
   * @param cacheRecord
   */


  async generateResultFromCacheRecord(cacheRecord, request) {
    let idTokenObj;

    if (cacheRecord.idToken) {
      idTokenObj = new AuthToken(cacheRecord.idToken.secret, this.config.cryptoInterface);
    }

    return await ResponseHandler.generateAuthenticationResult(this.cryptoUtils, this.authority, cacheRecord, true, request, idTokenObj);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Oauth2.0 Password grant client
 * Note: We are only supporting public clients for password grant and for purely testing purposes
 */

class UsernamePasswordClient extends BaseClient {
  constructor(configuration) {
    super(configuration);
  }
  /**
   * API to acquire a token by passing the username and password to the service in exchage of credentials
   * password_grant
   * @param request
   */


  async acquireToken(request) {
    this.logger.info("in acquireToken call");
    const reqTimestamp = TimeUtils.nowSeconds();
    const response = await this.executeTokenRequest(this.authority, request);
    const responseHandler = new ResponseHandler(this.config.authOptions.clientId, this.cacheManager, this.cryptoUtils, this.logger, this.config.serializableCache, this.config.persistencePlugin); // Validate response. This function throws a server error if an error is returned by the server.

    responseHandler.validateTokenResponse(response.body);
    const tokenResponse = responseHandler.handleServerTokenResponse(response.body, this.authority, reqTimestamp, request);
    return tokenResponse;
  }
  /**
   * Executes POST request to token endpoint
   * @param authority
   * @param request
   */


  async executeTokenRequest(authority, request) {
    const thumbprint = {
      clientId: this.config.authOptions.clientId,
      authority: authority.canonicalAuthority,
      scopes: request.scopes
    };
    const requestBody = this.createTokenRequestBody(request);
    const headers = this.createDefaultTokenRequestHeaders();
    return this.executePostToTokenEndpoint(authority.tokenEndpoint, requestBody, headers, thumbprint);
  }
  /**
   * Generates a map for all the params to be sent to the service
   * @param request
   */


  createTokenRequestBody(request) {
    const parameterBuilder = new RequestParameterBuilder();
    parameterBuilder.addClientId(this.config.authOptions.clientId);
    parameterBuilder.addUsername(request.username);
    parameterBuilder.addPassword(request.password);
    parameterBuilder.addScopes(request.scopes);
    parameterBuilder.addGrantType(GrantType.RESOURCE_OWNER_PASSWORD_GRANT);
    parameterBuilder.addClientInfo();
    parameterBuilder.addLibraryInfo(this.config.libraryInfo);
    parameterBuilder.addThrottling();

    if (this.serverTelemetryManager) {
      parameterBuilder.addServerTelemetry(this.serverTelemetryManager);
    }

    const correlationId = request.correlationId || this.config.cryptoInterface.createNewGuid();
    parameterBuilder.addCorrelationId(correlationId);

    if (!StringUtils.isEmptyObj(request.claims) || this.config.authOptions.clientCapabilities && this.config.authOptions.clientCapabilities.length > 0) {
      parameterBuilder.addClaims(request.claims, this.config.authOptions.clientCapabilities);
    }

    return parameterBuilder.createQueryString();
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
function isOpenIdConfigResponse(response) {
  return response.hasOwnProperty("authorization_endpoint") && response.hasOwnProperty("token_endpoint") && response.hasOwnProperty("end_session_endpoint") && response.hasOwnProperty("issuer");
}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

/**
 * Protocol modes supported by MSAL.
 */
var ProtocolMode;

(function (ProtocolMode) {
  ProtocolMode["AAD"] = "AAD";
  ProtocolMode["OIDC"] = "OIDC";
})(ProtocolMode || (ProtocolMode = {}));

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class AuthorityMetadataEntity {
  constructor() {
    this.expiresAt = TimeUtils.nowSeconds() + AUTHORITY_METADATA_CONSTANTS.REFRESH_TIME_SECONDS;
  }
  /**
   * Update the entity with new aliases, preferred_cache and preferred_network values
   * @param metadata
   * @param fromNetwork
   */


  updateCloudDiscoveryMetadata(metadata, fromNetwork) {
    this.aliases = metadata.aliases;
    this.preferred_cache = metadata.preferred_cache;
    this.preferred_network = metadata.preferred_network;
    this.aliasesFromNetwork = fromNetwork;
  }
  /**
   * Update the entity with new endpoints
   * @param metadata
   * @param fromNetwork
   */


  updateEndpointMetadata(metadata, fromNetwork) {
    this.authorization_endpoint = metadata.authorization_endpoint;
    this.token_endpoint = metadata.token_endpoint;
    this.end_session_endpoint = metadata.end_session_endpoint;
    this.issuer = metadata.issuer;
    this.endpointsFromNetwork = fromNetwork;
  }
  /**
   * Save the authority that was used to create this cache entry
   * @param authority
   */


  updateCanonicalAuthority(authority) {
    this.canonical_authority = authority;
  }
  /**
   * Reset the exiresAt value
   */


  resetExpiresAt() {
    this.expiresAt = TimeUtils.nowSeconds() + AUTHORITY_METADATA_CONSTANTS.REFRESH_TIME_SECONDS;
  }
  /**
   * Returns whether or not the data needs to be refreshed
   */


  isExpired() {
    return this.expiresAt <= TimeUtils.nowSeconds();
  }
  /**
   * Validates an entity: checks for all expected params
   * @param entity
   */


  static isAuthorityMetadataEntity(key, entity) {
    if (!entity) {
      return false;
    }

    return key.indexOf(AUTHORITY_METADATA_CONSTANTS.CACHE_KEY) === 0 && entity.hasOwnProperty("aliases") && entity.hasOwnProperty("preferred_cache") && entity.hasOwnProperty("preferred_network") && entity.hasOwnProperty("canonical_authority") && entity.hasOwnProperty("authorization_endpoint") && entity.hasOwnProperty("token_endpoint") && entity.hasOwnProperty("end_session_endpoint") && entity.hasOwnProperty("issuer") && entity.hasOwnProperty("aliasesFromNetwork") && entity.hasOwnProperty("endpointsFromNetwork") && entity.hasOwnProperty("expiresAt");
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
function isCloudInstanceDiscoveryResponse(response) {
  return response.hasOwnProperty("tenant_discovery_endpoint") && response.hasOwnProperty("metadata");
}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class RegionDiscovery {
  constructor(networkInterface) {
    this.networkInterface = networkInterface;
  }
  /**
   * Detect the region from the application's environment.
   *
   * @returns Promise<string | null>
   */


  async detectRegion(environmentRegion) {
    // Initialize auto detected region with the region from the envrionment 
    let autodetectedRegionName = environmentRegion; // Call the local IMDS endpoint for applications running in azure vms

    if (!autodetectedRegionName) {
      try {
        const response = await this.getRegionFromIMDS(Constants.IMDS_VERSION);

        if (response.status === ResponseCodes.httpSuccess) {
          autodetectedRegionName = response.body;
        }

        if (response.status === ResponseCodes.httpBadRequest) {
          const latestIMDSVersion = await this.getCurrentVersion();

          if (!latestIMDSVersion) {
            return null;
          }

          const response = await this.getRegionFromIMDS(latestIMDSVersion);

          if (response.status === ResponseCodes.httpSuccess) {
            autodetectedRegionName = response.body;
          }
        }
      } catch (e) {
        return null;
      }
    }

    return autodetectedRegionName || null;
  }
  /**
   * Make the call to the IMDS endpoint
   *
   * @param imdsEndpointUrl
   * @returns Promise<NetworkResponse<string>>
   */


  async getRegionFromIMDS(version) {
    return this.networkInterface.sendGetRequestAsync(`${Constants.IMDS_ENDPOINT}?api-version=${version}&format=text`, RegionDiscovery.IMDS_OPTIONS, Constants.IMDS_TIMEOUT);
  }
  /**
   * Get the most recent version of the IMDS endpoint available
   *
   * @returns Promise<string | null>
   */


  async getCurrentVersion() {
    try {
      const response = await this.networkInterface.sendGetRequestAsync(`${Constants.IMDS_ENDPOINT}?format=json`, RegionDiscovery.IMDS_OPTIONS); // When IMDS endpoint is called without the api version query param, bad request response comes back with latest version.

      if (response.status === ResponseCodes.httpBadRequest && response.body && response.body["newest-versions"] && response.body["newest-versions"].length > 0) {
        return response.body["newest-versions"][0];
      }

      return null;
    } catch (e) {
      return null;
    }
  }

} // Options for the IMDS endpoint request

RegionDiscovery.IMDS_OPTIONS = {
  headers: {
    "Metadata": "true"
  }
};

function ownKeys$6(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$6(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$6(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$6(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
/**
 * The authority class validates the authority URIs used by the user, and retrieves the OpenID Configuration Data from the
 * endpoint. It will store the pertinent config data in this object for use during token calls.
 */

class Authority {
  constructor(authority, networkInterface, cacheManager, authorityOptions) {
    this.canonicalAuthority = authority;

    this._canonicalAuthority.validateAsUri();

    this.networkInterface = networkInterface;
    this.cacheManager = cacheManager;
    this.authorityOptions = authorityOptions;
    this.regionDiscovery = new RegionDiscovery(networkInterface);
  } // See above for AuthorityType


  get authorityType() {
    const pathSegments = this.canonicalAuthorityUrlComponents.PathSegments;

    if (pathSegments.length && pathSegments[0].toLowerCase() === Constants.ADFS) {
      return AuthorityType.Adfs;
    }

    return AuthorityType.Default;
  }
  /**
   * ProtocolMode enum representing the way endpoints are constructed.
   */


  get protocolMode() {
    return this.authorityOptions.protocolMode;
  }
  /**
   * Returns authorityOptions which can be used to reinstantiate a new authority instance
   */


  get options() {
    return this.authorityOptions;
  }
  /**
   * A URL that is the authority set by the developer
   */


  get canonicalAuthority() {
    return this._canonicalAuthority.urlString;
  }
  /**
   * Sets canonical authority.
   */


  set canonicalAuthority(url) {
    this._canonicalAuthority = new UrlString(url);

    this._canonicalAuthority.validateAsUri();

    this._canonicalAuthorityUrlComponents = null;
  }
  /**
   * Get authority components.
   */


  get canonicalAuthorityUrlComponents() {
    if (!this._canonicalAuthorityUrlComponents) {
      this._canonicalAuthorityUrlComponents = this._canonicalAuthority.getUrlComponents();
    }

    return this._canonicalAuthorityUrlComponents;
  }
  /**
   * Get hostname and port i.e. login.microsoftonline.com
   */


  get hostnameAndPort() {
    return this.canonicalAuthorityUrlComponents.HostNameAndPort.toLowerCase();
  }
  /**
   * Get tenant for authority.
   */


  get tenant() {
    return this.canonicalAuthorityUrlComponents.PathSegments[0];
  }
  /**
   * OAuth /authorize endpoint for requests
   */


  get authorizationEndpoint() {
    if (this.discoveryComplete()) {
      const endpoint = this.replacePath(this.metadata.authorization_endpoint);
      return this.replaceTenant(endpoint);
    } else {
      throw ClientAuthError.createEndpointDiscoveryIncompleteError("Discovery incomplete.");
    }
  }
  /**
   * OAuth /token endpoint for requests
   */


  get tokenEndpoint() {
    if (this.discoveryComplete()) {
      const endpoint = this.replacePath(this.metadata.token_endpoint);
      return this.replaceTenant(endpoint);
    } else {
      throw ClientAuthError.createEndpointDiscoveryIncompleteError("Discovery incomplete.");
    }
  }

  get deviceCodeEndpoint() {
    if (this.discoveryComplete()) {
      const endpoint = this.replacePath(this.metadata.token_endpoint.replace("/token", "/devicecode"));
      return this.replaceTenant(endpoint);
    } else {
      throw ClientAuthError.createEndpointDiscoveryIncompleteError("Discovery incomplete.");
    }
  }
  /**
   * OAuth logout endpoint for requests
   */


  get endSessionEndpoint() {
    if (this.discoveryComplete()) {
      const endpoint = this.replacePath(this.metadata.end_session_endpoint);
      return this.replaceTenant(endpoint);
    } else {
      throw ClientAuthError.createEndpointDiscoveryIncompleteError("Discovery incomplete.");
    }
  }
  /**
   * OAuth issuer for requests
   */


  get selfSignedJwtAudience() {
    if (this.discoveryComplete()) {
      const endpoint = this.replacePath(this.metadata.issuer);
      return this.replaceTenant(endpoint);
    } else {
      throw ClientAuthError.createEndpointDiscoveryIncompleteError("Discovery incomplete.");
    }
  }
  /**
   * Replaces tenant in url path with current tenant. Defaults to common.
   * @param urlString
   */


  replaceTenant(urlString) {
    return urlString.replace(/{tenant}|{tenantid}/g, this.tenant);
  }
  /**
   * Replaces path such as tenant or policy with the current tenant or policy.
   * @param urlString
   */


  replacePath(urlString) {
    let endpoint = urlString;
    const cachedAuthorityUrl = new UrlString(this.metadata.canonical_authority);
    const cachedAuthorityParts = cachedAuthorityUrl.getUrlComponents().PathSegments;
    const currentAuthorityParts = this.canonicalAuthorityUrlComponents.PathSegments;
    currentAuthorityParts.forEach((currentPart, index) => {
      const cachedPart = cachedAuthorityParts[index];

      if (currentPart !== cachedPart) {
        endpoint = endpoint.replace(`/${cachedPart}/`, `/${currentPart}/`);
      }
    });
    return endpoint;
  }
  /**
   * The default open id configuration endpoint for any canonical authority.
   */


  get defaultOpenIdConfigurationEndpoint() {
    if (this.authorityType === AuthorityType.Adfs || this.protocolMode === ProtocolMode.OIDC) {
      return `${this.canonicalAuthority}.well-known/openid-configuration`;
    }

    return `${this.canonicalAuthority}v2.0/.well-known/openid-configuration`;
  }
  /**
   * Boolean that returns whethr or not tenant discovery has been completed.
   */


  discoveryComplete() {
    return !!this.metadata;
  }
  /**
   * Perform endpoint discovery to discover aliases, preferred_cache, preferred_network
   * and the /authorize, /token and logout endpoints.
   */


  async resolveEndpointsAsync() {
    let metadataEntity = this.cacheManager.getAuthorityMetadataByAlias(this.hostnameAndPort);

    if (!metadataEntity) {
      metadataEntity = new AuthorityMetadataEntity();
      metadataEntity.updateCanonicalAuthority(this.canonicalAuthority);
    }

    const cloudDiscoverySource = await this.updateCloudDiscoveryMetadata(metadataEntity);
    this.canonicalAuthority = this.canonicalAuthority.replace(this.hostnameAndPort, metadataEntity.preferred_network);
    const endpointSource = await this.updateEndpointMetadata(metadataEntity);

    if (cloudDiscoverySource !== AuthorityMetadataSource.CACHE && endpointSource !== AuthorityMetadataSource.CACHE) {
      // Reset the expiration time unless both values came from a successful cache lookup
      metadataEntity.resetExpiresAt();
      metadataEntity.updateCanonicalAuthority(this.canonicalAuthority);
    }

    const cacheKey = this.cacheManager.generateAuthorityMetadataCacheKey(metadataEntity.preferred_cache);
    this.cacheManager.setAuthorityMetadata(cacheKey, metadataEntity);
    this.metadata = metadataEntity;
  }
  /**
   * Update AuthorityMetadataEntity with new endpoints and return where the information came from
   * @param metadataEntity
   */


  async updateEndpointMetadata(metadataEntity) {
    let metadata = this.getEndpointMetadataFromConfig();

    if (metadata) {
      metadataEntity.updateEndpointMetadata(metadata, false);
      return AuthorityMetadataSource.CONFIG;
    }

    if (this.isAuthoritySameType(metadataEntity) && metadataEntity.endpointsFromNetwork && !metadataEntity.isExpired()) {
      // No need to update
      return AuthorityMetadataSource.CACHE;
    }

    metadata = await this.getEndpointMetadataFromNetwork();

    if (metadata) {
      // If the user prefers to use an azure region replace the global endpoints with regional information.
      if (this.authorityOptions.azureRegionConfiguration?.azureRegion) {
        const autodetectedRegionName = await this.regionDiscovery.detectRegion(this.authorityOptions.azureRegionConfiguration.environmentRegion);
        const azureRegion = this.authorityOptions.azureRegionConfiguration.azureRegion === Constants.AZURE_REGION_AUTO_DISCOVER_FLAG ? autodetectedRegionName : this.authorityOptions.azureRegionConfiguration.azureRegion;

        if (azureRegion) {
          metadata = Authority.replaceWithRegionalInformation(metadata, azureRegion);
        }
      }

      metadataEntity.updateEndpointMetadata(metadata, true);
      return AuthorityMetadataSource.NETWORK;
    } else {
      throw ClientAuthError.createUnableToGetOpenidConfigError(this.defaultOpenIdConfigurationEndpoint);
    }
  }
  /**
   * Compares the number of url components after the domain to determine if the cached authority metadata can be used for the requested authority
   * Protects against same domain different authority such as login.microsoftonline.com/tenant and login.microsoftonline.com/tfp/tenant/policy
   * @param metadataEntity
   */


  isAuthoritySameType(metadataEntity) {
    const cachedAuthorityUrl = new UrlString(metadataEntity.canonical_authority);
    const cachedParts = cachedAuthorityUrl.getUrlComponents().PathSegments;
    return cachedParts.length === this.canonicalAuthorityUrlComponents.PathSegments.length;
  }
  /**
   * Parse authorityMetadata config option
   */


  getEndpointMetadataFromConfig() {
    if (this.authorityOptions.authorityMetadata) {
      try {
        return JSON.parse(this.authorityOptions.authorityMetadata);
      } catch (e) {
        throw ClientConfigurationError.createInvalidAuthorityMetadataError();
      }
    }

    return null;
  }
  /**
   * Gets OAuth endpoints from the given OpenID configuration endpoint.
   */


  async getEndpointMetadataFromNetwork() {
    try {
      const response = await this.networkInterface.sendGetRequestAsync(this.defaultOpenIdConfigurationEndpoint);
      return isOpenIdConfigResponse(response.body) ? response.body : null;
    } catch (e) {
      return null;
    }
  }
  /**
   * Updates the AuthorityMetadataEntity with new aliases, preferred_network and preferred_cache and returns where the information was retrived from
   * @param cachedMetadata
   * @param newMetadata
   */


  async updateCloudDiscoveryMetadata(metadataEntity) {
    let metadata = this.getCloudDiscoveryMetadataFromConfig();

    if (metadata) {
      metadataEntity.updateCloudDiscoveryMetadata(metadata, false);
      return AuthorityMetadataSource.CONFIG;
    } // If The cached metadata came from config but that config was not passed to this instance, we must go to the network


    if (this.isAuthoritySameType(metadataEntity) && metadataEntity.aliasesFromNetwork && !metadataEntity.isExpired()) {
      // No need to update
      return AuthorityMetadataSource.CACHE;
    }

    metadata = await this.getCloudDiscoveryMetadataFromNetwork();

    if (metadata) {
      metadataEntity.updateCloudDiscoveryMetadata(metadata, true);
      return AuthorityMetadataSource.NETWORK;
    } else {
      // Metadata could not be obtained from config, cache or network
      throw ClientConfigurationError.createUntrustedAuthorityError();
    }
  }
  /**
   * Parse cloudDiscoveryMetadata config or check knownAuthorities
   */


  getCloudDiscoveryMetadataFromConfig() {
    // Check if network response was provided in config
    if (this.authorityOptions.cloudDiscoveryMetadata) {
      try {
        const parsedResponse = JSON.parse(this.authorityOptions.cloudDiscoveryMetadata);
        const metadata = Authority.getCloudDiscoveryMetadataFromNetworkResponse(parsedResponse.metadata, this.hostnameAndPort);

        if (metadata) {
          return metadata;
        }
      } catch (e) {
        throw ClientConfigurationError.createInvalidCloudDiscoveryMetadataError();
      }
    } // If cloudDiscoveryMetadata is empty or does not contain the host, check knownAuthorities


    if (this.isInKnownAuthorities()) {
      return Authority.createCloudDiscoveryMetadataFromHost(this.hostnameAndPort);
    }

    return null;
  }
  /**
   * Called to get metadata from network if CloudDiscoveryMetadata was not populated by config
   * @param networkInterface
   */


  async getCloudDiscoveryMetadataFromNetwork() {
    const instanceDiscoveryEndpoint = `${Constants.AAD_INSTANCE_DISCOVERY_ENDPT}${this.canonicalAuthority}oauth2/v2.0/authorize`;
    let match = null;

    try {
      const response = await this.networkInterface.sendGetRequestAsync(instanceDiscoveryEndpoint);
      const metadata = isCloudInstanceDiscoveryResponse(response.body) ? response.body.metadata : [];

      if (metadata.length === 0) {
        // If no metadata is returned, authority is untrusted
        return null;
      }

      match = Authority.getCloudDiscoveryMetadataFromNetworkResponse(metadata, this.hostnameAndPort);
    } catch (e) {
      return null;
    }

    if (!match) {
      // Custom Domain scenario, host is trusted because Instance Discovery call succeeded 
      match = Authority.createCloudDiscoveryMetadataFromHost(this.hostnameAndPort);
    }

    return match;
  }
  /**
   * Helper function to determine if this host is included in the knownAuthorities config option
   */


  isInKnownAuthorities() {
    const matches = this.authorityOptions.knownAuthorities.filter(authority => {
      return UrlString.getDomainFromUrl(authority).toLowerCase() === this.hostnameAndPort;
    });
    return matches.length > 0;
  }
  /**
   * Creates cloud discovery metadata object from a given host
   * @param host
   */


  static createCloudDiscoveryMetadataFromHost(host) {
    return {
      preferred_network: host,
      preferred_cache: host,
      aliases: [host]
    };
  }
  /**
   * Searches instance discovery network response for the entry that contains the host in the aliases list
   * @param response
   * @param authority
   */


  static getCloudDiscoveryMetadataFromNetworkResponse(response, authority) {
    for (let i = 0; i < response.length; i++) {
      const metadata = response[i];

      if (metadata.aliases.indexOf(authority) > -1) {
        return metadata;
      }
    }

    return null;
  }
  /**
   * helper function to generate environment from authority object
   */


  getPreferredCache() {
    if (this.discoveryComplete()) {
      return this.metadata.preferred_cache;
    } else {
      throw ClientAuthError.createEndpointDiscoveryIncompleteError("Discovery incomplete.");
    }
  }
  /**
   * Returns whether or not the provided host is an alias of this authority instance
   * @param host
   */


  isAlias(host) {
    return this.metadata.aliases.indexOf(host) > -1;
  }
  /**
   * Checks whether the provided host is that of a public cloud authority
   *
   * @param authority string
   * @returns bool
   */


  static isPublicCloudAuthority(host) {
    return Constants.KNOWN_PUBLIC_CLOUDS.includes(host);
  }
  /**
   * Rebuild the authority string with the region
   *
   * @param host string
   * @param region string
   */


  static buildRegionalAuthorityString(host, region, queryString) {
    // Create and validate a Url string object with the initial authority string
    const authorityUrlInstance = new UrlString(host);
    authorityUrlInstance.validateAsUri();
    const authorityUrlParts = authorityUrlInstance.getUrlComponents();
    let hostNameAndPort = `${region}.${authorityUrlParts.HostNameAndPort}`;

    if (this.isPublicCloudAuthority(authorityUrlParts.HostNameAndPort)) {
      hostNameAndPort = `${region}.${Constants.REGIONAL_AUTH_PUBLIC_CLOUD_SUFFIX}`;
    } // Include the query string portion of the url


    const url = UrlString.constructAuthorityUriFromObject(_objectSpread$6(_objectSpread$6({}, authorityUrlInstance.getUrlComponents()), {}, {
      HostNameAndPort: hostNameAndPort
    })).urlString; // Add the query string if a query string was provided

    if (queryString) return `${url}?${queryString}`;
    return url;
  }
  /**
   * Replace the endpoints in the metadata object with their regional equivalents.
   *
   * @param metadata OpenIdConfigResponse
   * @param azureRegion string
   */


  static replaceWithRegionalInformation(metadata, azureRegion) {
    metadata.authorization_endpoint = Authority.buildRegionalAuthorityString(metadata.authorization_endpoint, azureRegion); // TODO: Enquire on whether we should leave the query string or remove it before releasing the feature

    metadata.token_endpoint = Authority.buildRegionalAuthorityString(metadata.token_endpoint, azureRegion, "allowestsrnonmsi=true");
    metadata.end_session_endpoint = Authority.buildRegionalAuthorityString(metadata.end_session_endpoint, azureRegion);
    return metadata;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class AuthorityFactory {
  /**
   * Create an authority object of the correct type based on the url
   * Performs basic authority validation - checks to see if the authority is of a valid type (i.e. aad, b2c, adfs)
   *
   * Also performs endpoint discovery.
   *
   * @param authorityUri
   * @param networkClient
   * @param protocolMode
   */
  static async createDiscoveredInstance(authorityUri, networkClient, cacheManager, authorityOptions) {
    // Initialize authority and perform discovery endpoint check.
    const acquireTokenAuthority = AuthorityFactory.createInstance(authorityUri, networkClient, cacheManager, authorityOptions);

    try {
      await acquireTokenAuthority.resolveEndpointsAsync();
      return acquireTokenAuthority;
    } catch (e) {
      throw ClientAuthError.createEndpointDiscoveryIncompleteError(e);
    }
  }
  /**
   * Create an authority object of the correct type based on the url
   * Performs basic authority validation - checks to see if the authority is of a valid type (i.e. aad, b2c, adfs)
   *
   * Does not perform endpoint discovery.
   *
   * @param authorityUrl
   * @param networkInterface
   * @param protocolMode
   */


  static createInstance(authorityUrl, networkInterface, cacheManager, authorityOptions) {
    // Throw error if authority url is empty
    if (StringUtils.isEmpty(authorityUrl)) {
      throw ClientConfigurationError.createUrlEmptyError();
    }

    return new Authority(authorityUrl, networkInterface, cacheManager, authorityOptions);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class ServerTelemetryEntity {
  constructor() {
    this.failedRequests = [];
    this.errors = [];
    this.cacheHits = 0;
  }
  /**
   * validates if a given cache entry is "Telemetry", parses <key,value>
   * @param key
   * @param entity
   */


  static isServerTelemetryEntity(key, entity) {
    const validateKey = key.indexOf(SERVER_TELEM_CONSTANTS.CACHE_KEY) === 0;
    let validateEntity = true;

    if (entity) {
      validateEntity = entity.hasOwnProperty("failedRequests") && entity.hasOwnProperty("errors") && entity.hasOwnProperty("cacheHits");
    }

    return validateKey && validateEntity;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class ThrottlingEntity {
  /**
   * validates if a given cache entry is "Throttling", parses <key,value>
   * @param key
   * @param entity
   */
  static isThrottlingEntity(key, entity) {
    let validateKey = false;

    if (key) {
      validateKey = key.indexOf(ThrottlingConstants.THROTTLING_PREFIX) === 0;
    }

    let validateEntity = true;

    if (entity) {
      validateEntity = entity.hasOwnProperty("throttleTime");
    }

    return validateKey && validateEntity;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class ServerTelemetryManager {
  constructor(telemetryRequest, cacheManager) {
    this.cacheManager = cacheManager;
    this.apiId = telemetryRequest.apiId;
    this.correlationId = telemetryRequest.correlationId;
    this.forceRefresh = telemetryRequest.forceRefresh || false;
    this.wrapperSKU = telemetryRequest.wrapperSKU || Constants.EMPTY_STRING;
    this.wrapperVer = telemetryRequest.wrapperVer || Constants.EMPTY_STRING;
    this.telemetryCacheKey = SERVER_TELEM_CONSTANTS.CACHE_KEY + Separators.CACHE_KEY_SEPARATOR + telemetryRequest.clientId;
  }
  /**
   * API to add MSER Telemetry to request
   */


  generateCurrentRequestHeaderValue() {
    const forceRefreshInt = this.forceRefresh ? 1 : 0;
    const request = `${this.apiId}${SERVER_TELEM_CONSTANTS.VALUE_SEPARATOR}${forceRefreshInt}`;
    const platformFields = [this.wrapperSKU, this.wrapperVer].join(SERVER_TELEM_CONSTANTS.VALUE_SEPARATOR);
    return [SERVER_TELEM_CONSTANTS.SCHEMA_VERSION, request, platformFields].join(SERVER_TELEM_CONSTANTS.CATEGORY_SEPARATOR);
  }
  /**
   * API to add MSER Telemetry for the last failed request
   */


  generateLastRequestHeaderValue() {
    const lastRequests = this.getLastRequests();
    const maxErrors = ServerTelemetryManager.maxErrorsToSend(lastRequests);
    const failedRequests = lastRequests.failedRequests.slice(0, 2 * maxErrors).join(SERVER_TELEM_CONSTANTS.VALUE_SEPARATOR);
    const errors = lastRequests.errors.slice(0, maxErrors).join(SERVER_TELEM_CONSTANTS.VALUE_SEPARATOR);
    const errorCount = lastRequests.errors.length; // Indicate whether this header contains all data or partial data

    const overflow = maxErrors < errorCount ? SERVER_TELEM_CONSTANTS.OVERFLOW_TRUE : SERVER_TELEM_CONSTANTS.OVERFLOW_FALSE;
    const platformFields = [errorCount, overflow].join(SERVER_TELEM_CONSTANTS.VALUE_SEPARATOR);
    return [SERVER_TELEM_CONSTANTS.SCHEMA_VERSION, lastRequests.cacheHits, failedRequests, errors, platformFields].join(SERVER_TELEM_CONSTANTS.CATEGORY_SEPARATOR);
  }
  /**
   * API to cache token failures for MSER data capture
   * @param error
   */


  cacheFailedRequest(error) {
    const lastRequests = this.getLastRequests();

    if (lastRequests.errors.length >= SERVER_TELEM_CONSTANTS.MAX_CACHED_ERRORS) {
      // Remove a cached error to make room, first in first out
      lastRequests.failedRequests.shift(); // apiId

      lastRequests.failedRequests.shift(); // correlationId

      lastRequests.errors.shift();
    }

    lastRequests.failedRequests.push(this.apiId, this.correlationId);

    if (!StringUtils.isEmpty(error.subError)) {
      lastRequests.errors.push(error.subError);
    } else if (!StringUtils.isEmpty(error.errorCode)) {
      lastRequests.errors.push(error.errorCode);
    } else if (!!error && error.toString()) {
      lastRequests.errors.push(error.toString());
    } else {
      lastRequests.errors.push(SERVER_TELEM_CONSTANTS.UNKNOWN_ERROR);
    }

    this.cacheManager.setServerTelemetry(this.telemetryCacheKey, lastRequests);
    return;
  }
  /**
   * Update server telemetry cache entry by incrementing cache hit counter
   */


  incrementCacheHits() {
    const lastRequests = this.getLastRequests();
    lastRequests.cacheHits += 1;
    this.cacheManager.setServerTelemetry(this.telemetryCacheKey, lastRequests);
    return lastRequests.cacheHits;
  }
  /**
   * Get the server telemetry entity from cache or initialize a new one
   */


  getLastRequests() {
    const initialValue = new ServerTelemetryEntity();
    const lastRequests = this.cacheManager.getServerTelemetry(this.telemetryCacheKey);
    return lastRequests || initialValue;
  }
  /**
   * Remove server telemetry cache entry
   */


  clearTelemetryCache() {
    const lastRequests = this.getLastRequests();
    const numErrorsFlushed = ServerTelemetryManager.maxErrorsToSend(lastRequests);
    const errorCount = lastRequests.errors.length;

    if (numErrorsFlushed === errorCount) {
      // All errors were sent on last request, clear Telemetry cache
      this.cacheManager.removeItem(this.telemetryCacheKey);
    } else {
      // Partial data was flushed to server, construct a new telemetry cache item with errors that were not flushed
      const serverTelemEntity = new ServerTelemetryEntity();
      serverTelemEntity.failedRequests = lastRequests.failedRequests.slice(numErrorsFlushed * 2); // failedRequests contains 2 items for each error

      serverTelemEntity.errors = lastRequests.errors.slice(numErrorsFlushed);
      this.cacheManager.setServerTelemetry(this.telemetryCacheKey, serverTelemEntity);
    }
  }
  /**
   * Returns the maximum number of errors that can be flushed to the server in the next network request
   * @param serverTelemetryEntity
   */


  static maxErrorsToSend(serverTelemetryEntity) {
    let i;
    let maxErrors = 0;
    let dataSize = 0;
    const errorCount = serverTelemetryEntity.errors.length;

    for (i = 0; i < errorCount; i++) {
      // failedRequests parameter contains pairs of apiId and correlationId, multiply index by 2 to preserve pairs
      const apiId = serverTelemetryEntity.failedRequests[2 * i] || Constants.EMPTY_STRING;
      const correlationId = serverTelemetryEntity.failedRequests[2 * i + 1] || Constants.EMPTY_STRING;
      const errorCode = serverTelemetryEntity.errors[i] || Constants.EMPTY_STRING; // Count number of characters that would be added to header, each character is 1 byte. Add 3 at the end to account for separators

      dataSize += apiId.toString().length + correlationId.toString().length + errorCode.length + 3;

      if (dataSize < SERVER_TELEM_CONSTANTS.MAX_LAST_HEADER_BYTES) {
        // Adding this entry to the header would still keep header size below the limit
        maxErrors += 1;
      } else {
        break;
      }
    }

    return maxErrors;
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * This class implements the API for network requests.
 */

class HttpClient {
  /**
   * Http Get request
   * @param url
   * @param options
   */
  async sendGetRequestAsync(url, options) {
    const request = {
      method: HttpMethod.GET,
      url: url,
      headers: options && options.headers,
      validateStatus: () => true
    };
    const response = await axios(request);
    return {
      headers: response.headers,
      body: response.data,
      status: response.status
    };
  }
  /**
   * Http Post request
   * @param url
   * @param options
   */


  async sendPostRequestAsync(url, options, cancellationToken) {
    const request = {
      method: HttpMethod.POST,
      url: url,
      data: options && options.body || "",
      timeout: cancellationToken,
      headers: options && options.headers,
      validateStatus: () => true
    };
    const response = await axios(request);
    return {
      headers: response.headers,
      body: response.data,
      status: response.status
    };
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class NetworkUtils {
  /**
   * Returns best compatible network client object.
   */
  static getNetworkClient() {
    return new HttpClient();
  }

}

function ownKeys$5(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$5(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$5(Object(source), true).forEach(function (key) { _defineProperty$1(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$5(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
const DEFAULT_AUTH_OPTIONS = {
  clientId: "",
  authority: Constants.DEFAULT_AUTHORITY,
  clientSecret: "",
  clientAssertion: "",
  clientCertificate: {
    thumbprint: "",
    privateKey: "",
    x5c: ""
  },
  knownAuthorities: [],
  cloudDiscoveryMetadata: "",
  authorityMetadata: "",
  clientCapabilities: [],
  protocolMode: ProtocolMode.AAD
};
const DEFAULT_CACHE_OPTIONS = {};
const DEFAULT_LOGGER_OPTIONS = {
  loggerCallback: () => {// allow users to not set logger call back
  },
  piiLoggingEnabled: false,
  logLevel: LogLevel.Info
};
const DEFAULT_SYSTEM_OPTIONS = {
  loggerOptions: DEFAULT_LOGGER_OPTIONS,
  networkClient: NetworkUtils.getNetworkClient()
};
/**
 * Sets the default options when not explicitly configured from app developer
 *
 * @param auth - Authentication options
 * @param cache - Cache options
 * @param system - System options
 *
 * @returns Configuration
 * @public
 */

function buildAppConfiguration({
  auth,
  cache,
  system
}) {
  return {
    auth: _objectSpread$5(_objectSpread$5({}, DEFAULT_AUTH_OPTIONS), auth),
    cache: _objectSpread$5(_objectSpread$5({}, DEFAULT_CACHE_OPTIONS), cache),
    system: _objectSpread$5(_objectSpread$5({}, DEFAULT_SYSTEM_OPTIONS), system)
  };
}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class GuidGenerator {
  /**
   *
   * RFC4122: The version 4 UUID is meant for generating UUIDs from truly-random or pseudo-random numbers.
   * uuidv4 generates guids from cryprtographically-string random
   */
  static generateGuid() {
    return v4();
  }
  /**
   * verifies if a string is  GUID
   * @param guid
   */


  static isGuid(guid) {
    const regexGuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return regexGuid.test(guid);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class EncodingUtils {
  /**
   * 'utf8': Multibyte encoded Unicode characters. Many web pages and other document formats use UTF-8.
   * 'base64': Base64 encoding.
   *
   * @param str text
   */
  static base64Encode(str, encoding) {
    return Buffer.from(str, encoding).toString("base64");
  }
  /**
   * encode a URL
   * @param str
   */


  static base64EncodeUrl(str, encoding) {
    return EncodingUtils.base64Encode(str, encoding).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }
  /**
   * 'utf8': Multibyte encoded Unicode characters. Many web pages and other document formats use UTF-8.
   * 'base64': Base64 encoding.
   *
   * @param base64Str Base64 encoded text
   */


  static base64Decode(base64Str) {
    return Buffer.from(base64Str, "base64").toString("utf8");
  }
  /**
   * @param base64Str Base64 encoded Url
   */


  static base64DecodeUrl(base64Str) {
    let str = base64Str.replace(/-/g, "+").replace(/_/g, "/");

    while (str.length % 4) {
      str += "=";
    }

    return EncodingUtils.base64Decode(str);
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * https://tools.ietf.org/html/rfc7636#page-8
 */

class PkceGenerator {
  /**
   * generates the codeVerfier and the challenge from the codeVerfier
   * reference: https://tools.ietf.org/html/rfc7636#section-4.1 and https://tools.ietf.org/html/rfc7636#section-4.2
   */
  async generatePkceCodes() {
    const verifier = this.generateCodeVerifier();
    const challenge = this.generateCodeChallengeFromVerifier(verifier);
    return {
      verifier,
      challenge
    };
  }
  /**
   * generates the codeVerfier; reference: https://tools.ietf.org/html/rfc7636#section-4.1
   */


  generateCodeVerifier() {
    const buffer = crypto.randomBytes(RANDOM_OCTET_SIZE);
    const verifier = this.bufferToCVString(buffer);
    return EncodingUtils.base64EncodeUrl(verifier);
  }
  /**
   * generate the challenge from the codeVerfier; reference: https://tools.ietf.org/html/rfc7636#section-4.2
   * @param codeVerifier
   */


  generateCodeChallengeFromVerifier(codeVerifier) {
    return EncodingUtils.base64EncodeUrl(this.sha256(codeVerifier).toString("base64"), "base64");
  }
  /**
   * generate 'SHA256' hash
   * @param buffer
   */


  sha256(buffer) {
    return crypto.createHash(Hash.SHA256).update(buffer).digest();
  }
  /**
   * Accepted characters; reference: https://tools.ietf.org/html/rfc7636#section-4.1
   * @param buffer
   */


  bufferToCVString(buffer) {
    const charArr = [];

    for (let i = 0; i < buffer.byteLength; i += 1) {
      const index = buffer[i] % CharSet.CV_CHARSET.length;
      charArr.push(CharSet.CV_CHARSET[index]);
    }

    return charArr.join("");
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * This class implements MSAL node's crypto interface, which allows it to perform base64 encoding and decoding, generating cryptographically random GUIDs and
 * implementing Proof Key for Code Exchange specs for the OAuth Authorization Code Flow using PKCE (rfc here: https://tools.ietf.org/html/rfc7636).
 * @public
 */

class CryptoProvider {
  constructor() {
    // Browser crypto needs to be validated first before any other classes can be set.
    this.pkceGenerator = new PkceGenerator();
  }
  /**
   * Creates a new random GUID - used to populate state and nonce.
   * @returns string (GUID)
   */


  createNewGuid() {
    return GuidGenerator.generateGuid();
  }
  /**
   * Encodes input string to base64.
   * @param input - string to be encoded
   */


  base64Encode(input) {
    return EncodingUtils.base64Encode(input);
  }
  /**
   * Decodes input string from base64.
   * @param input - string to be decoded
   */


  base64Decode(input) {
    return EncodingUtils.base64Decode(input);
  }
  /**
   * Generates PKCE codes used in Authorization Code Flow.
   */


  generatePkceCodes() {
    return this.pkceGenerator.generatePkceCodes();
  }
  /**
   * Generates a keypair, stores it and returns a thumbprint - not yet implemented for node
   */


  getPublicKeyThumbprint() {
    throw new Error("Method not implemented.");
  }
  /**
   * Signs the given object as a jwt payload with private key retrieved by given kid - currently not implemented for node
   */


  signJwt() {
    throw new Error("Method not implemented.");
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * This class deserializes cache entities read from the file into in memory object types defined internally
 */

class Deserializer {
  /**
   * Parse the JSON blob in memory and deserialize the content
   * @param cachedJson
   */
  static deserializeJSONBlob(jsonFile) {
    const deserializedCache = StringUtils.isEmpty(jsonFile) ? {} : JSON.parse(jsonFile);
    return deserializedCache;
  }
  /**
   * Deserializes accounts to AccountEntity objects
   * @param accounts
   */


  static deserializeAccounts(accounts) {
    const accountObjects = {};

    if (accounts) {
      Object.keys(accounts).map(function (key) {
        const serializedAcc = accounts[key];
        const mappedAcc = {
          homeAccountId: serializedAcc.home_account_id,
          environment: serializedAcc.environment,
          realm: serializedAcc.realm,
          localAccountId: serializedAcc.local_account_id,
          username: serializedAcc.username,
          authorityType: serializedAcc.authority_type,
          name: serializedAcc.name,
          clientInfo: serializedAcc.client_info,
          lastModificationTime: serializedAcc.last_modification_time,
          lastModificationApp: serializedAcc.last_modification_app
        };
        const account = new AccountEntity();
        CacheManager.toObject(account, mappedAcc);
        accountObjects[key] = account;
      });
    }

    return accountObjects;
  }
  /**
   * Deserializes id tokens to IdTokenEntity objects
   * @param idTokens
   */


  static deserializeIdTokens(idTokens) {
    const idObjects = {};

    if (idTokens) {
      Object.keys(idTokens).map(function (key) {
        const serializedIdT = idTokens[key];
        const mappedIdT = {
          homeAccountId: serializedIdT.home_account_id,
          environment: serializedIdT.environment,
          credentialType: serializedIdT.credential_type,
          clientId: serializedIdT.client_id,
          secret: serializedIdT.secret,
          realm: serializedIdT.realm
        };
        const idToken = new IdTokenEntity();
        CacheManager.toObject(idToken, mappedIdT);
        idObjects[key] = idToken;
      });
    }

    return idObjects;
  }
  /**
   * Deserializes access tokens to AccessTokenEntity objects
   * @param accessTokens
   */


  static deserializeAccessTokens(accessTokens) {
    const atObjects = {};

    if (accessTokens) {
      Object.keys(accessTokens).map(function (key) {
        const serializedAT = accessTokens[key];
        const mappedAT = {
          homeAccountId: serializedAT.home_account_id,
          environment: serializedAT.environment,
          credentialType: serializedAT.credential_type,
          clientId: serializedAT.client_id,
          secret: serializedAT.secret,
          realm: serializedAT.realm,
          target: serializedAT.target,
          cachedAt: serializedAT.cached_at,
          expiresOn: serializedAT.expires_on,
          extendedExpiresOn: serializedAT.extended_expires_on,
          refreshOn: serializedAT.refresh_on,
          keyId: serializedAT.key_id,
          tokenType: serializedAT.token_type
        };
        const accessToken = new AccessTokenEntity();
        CacheManager.toObject(accessToken, mappedAT);
        atObjects[key] = accessToken;
      });
    }

    return atObjects;
  }
  /**
   * Deserializes refresh tokens to RefreshTokenEntity objects
   * @param refreshTokens
   */


  static deserializeRefreshTokens(refreshTokens) {
    const rtObjects = {};

    if (refreshTokens) {
      Object.keys(refreshTokens).map(function (key) {
        const serializedRT = refreshTokens[key];
        const mappedRT = {
          homeAccountId: serializedRT.home_account_id,
          environment: serializedRT.environment,
          credentialType: serializedRT.credential_type,
          clientId: serializedRT.client_id,
          secret: serializedRT.secret,
          familyId: serializedRT.family_id,
          target: serializedRT.target,
          realm: serializedRT.realm
        };
        const refreshToken = new RefreshTokenEntity();
        CacheManager.toObject(refreshToken, mappedRT);
        rtObjects[key] = refreshToken;
      });
    }

    return rtObjects;
  }
  /**
   * Deserializes appMetadata to AppMetaData objects
   * @param appMetadata
   */


  static deserializeAppMetadata(appMetadata) {
    const appMetadataObjects = {};

    if (appMetadata) {
      Object.keys(appMetadata).map(function (key) {
        const serializedAmdt = appMetadata[key];
        const mappedAmd = {
          clientId: serializedAmdt.client_id,
          environment: serializedAmdt.environment,
          familyId: serializedAmdt.family_id
        };
        const amd = new AppMetadataEntity();
        CacheManager.toObject(amd, mappedAmd);
        appMetadataObjects[key] = amd;
      });
    }

    return appMetadataObjects;
  }
  /**
   * Deserialize an inMemory Cache
   * @param jsonCache
   */


  static deserializeAllCache(jsonCache) {
    return {
      accounts: jsonCache.Account ? this.deserializeAccounts(jsonCache.Account) : {},
      idTokens: jsonCache.IdToken ? this.deserializeIdTokens(jsonCache.IdToken) : {},
      accessTokens: jsonCache.AccessToken ? this.deserializeAccessTokens(jsonCache.AccessToken) : {},
      refreshTokens: jsonCache.RefreshToken ? this.deserializeRefreshTokens(jsonCache.RefreshToken) : {},
      appMetadata: jsonCache.AppMetadata ? this.deserializeAppMetadata(jsonCache.AppMetadata) : {}
    };
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
class Serializer {
  /**
   * serialize the JSON blob
   * @param data
   */
  static serializeJSONBlob(data) {
    return JSON.stringify(data);
  }
  /**
   * Serialize Accounts
   * @param accCache
   */


  static serializeAccounts(accCache) {
    const accounts = {};
    Object.keys(accCache).map(function (key) {
      const accountEntity = accCache[key];
      accounts[key] = {
        home_account_id: accountEntity.homeAccountId,
        environment: accountEntity.environment,
        realm: accountEntity.realm,
        local_account_id: accountEntity.localAccountId,
        username: accountEntity.username,
        authority_type: accountEntity.authorityType,
        name: accountEntity.name,
        client_info: accountEntity.clientInfo,
        last_modification_time: accountEntity.lastModificationTime,
        last_modification_app: accountEntity.lastModificationApp
      };
    });
    return accounts;
  }
  /**
   * Serialize IdTokens
   * @param idTCache
   */


  static serializeIdTokens(idTCache) {
    const idTokens = {};
    Object.keys(idTCache).map(function (key) {
      const idTEntity = idTCache[key];
      idTokens[key] = {
        home_account_id: idTEntity.homeAccountId,
        environment: idTEntity.environment,
        credential_type: idTEntity.credentialType,
        client_id: idTEntity.clientId,
        secret: idTEntity.secret,
        realm: idTEntity.realm
      };
    });
    return idTokens;
  }
  /**
   * Serializes AccessTokens
   * @param atCache
   */


  static serializeAccessTokens(atCache) {
    const accessTokens = {};
    Object.keys(atCache).map(function (key) {
      const atEntity = atCache[key];
      accessTokens[key] = {
        home_account_id: atEntity.homeAccountId,
        environment: atEntity.environment,
        credential_type: atEntity.credentialType,
        client_id: atEntity.clientId,
        secret: atEntity.secret,
        realm: atEntity.realm,
        target: atEntity.target,
        cached_at: atEntity.cachedAt,
        expires_on: atEntity.expiresOn,
        extended_expires_on: atEntity.extendedExpiresOn,
        refresh_on: atEntity.refreshOn,
        key_id: atEntity.keyId,
        token_type: atEntity.tokenType
      };
    });
    return accessTokens;
  }
  /**
   * Serialize refreshTokens
   * @param rtCache
   */


  static serializeRefreshTokens(rtCache) {
    const refreshTokens = {};
    Object.keys(rtCache).map(function (key) {
      const rtEntity = rtCache[key];
      refreshTokens[key] = {
        home_account_id: rtEntity.homeAccountId,
        environment: rtEntity.environment,
        credential_type: rtEntity.credentialType,
        client_id: rtEntity.clientId,
        secret: rtEntity.secret,
        family_id: rtEntity.familyId,
        target: rtEntity.target,
        realm: rtEntity.realm
      };
    });
    return refreshTokens;
  }
  /**
   * Serialize amdtCache
   * @param amdtCache
   */


  static serializeAppMetadata(amdtCache) {
    const appMetadata = {};
    Object.keys(amdtCache).map(function (key) {
      const amdtEntity = amdtCache[key];
      appMetadata[key] = {
        client_id: amdtEntity.clientId,
        environment: amdtEntity.environment,
        family_id: amdtEntity.familyId
      };
    });
    return appMetadata;
  }
  /**
   * Serialize the cache
   * @param jsonContent
   */


  static serializeAllCache(inMemCache) {
    return {
      Account: this.serializeAccounts(inMemCache.accounts),
      IdToken: this.serializeIdTokens(inMemCache.idTokens),
      AccessToken: this.serializeAccessTokens(inMemCache.accessTokens),
      RefreshToken: this.serializeRefreshTokens(inMemCache.refreshTokens),
      AppMetadata: this.serializeAppMetadata(inMemCache.appMetadata)
    };
  }

}

function ownKeys$4(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$4(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$4(Object(source), true).forEach(function (key) { _defineProperty$1(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$4(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
/**
 * This class implements Storage for node, reading cache from user specified storage location or an  extension library
 * @public
 */

class NodeStorage extends CacheManager {
  constructor(logger, clientId, cryptoImpl) {
    super(clientId, cryptoImpl);
    this.cache = {};
    this.changeEmitters = [];
    this.logger = logger;
  }
  /**
   * Queue up callbacks
   * @param func - a callback function for cache change indication
   */


  registerChangeEmitter(func) {
    this.changeEmitters.push(func);
  }
  /**
   * Invoke the callback when cache changes
   */


  emitChange() {
    this.changeEmitters.forEach(func => func.call(null));
  }
  /**
   * Converts cacheKVStore to InMemoryCache
   * @param cache - key value store
   */


  cacheToInMemoryCache(cache) {
    const inMemoryCache = {
      accounts: {},
      idTokens: {},
      accessTokens: {},
      refreshTokens: {},
      appMetadata: {}
    };

    for (const key in cache) {
      if (cache[key] instanceof AccountEntity) {
        inMemoryCache.accounts[key] = cache[key];
      } else if (cache[key] instanceof IdTokenEntity) {
        inMemoryCache.idTokens[key] = cache[key];
      } else if (cache[key] instanceof AccessTokenEntity) {
        inMemoryCache.accessTokens[key] = cache[key];
      } else if (cache[key] instanceof RefreshTokenEntity) {
        inMemoryCache.refreshTokens[key] = cache[key];
      } else if (cache[key] instanceof AppMetadataEntity) {
        inMemoryCache.appMetadata[key] = cache[key];
      } else {
        continue;
      }
    }

    return inMemoryCache;
  }
  /**
   * converts inMemoryCache to CacheKVStore
   * @param inMemoryCache - kvstore map for inmemory
   */


  inMemoryCacheToCache(inMemoryCache) {
    // convert in memory cache to a flat Key-Value map
    let cache = this.getCache();
    cache = _objectSpread$4(_objectSpread$4(_objectSpread$4(_objectSpread$4(_objectSpread$4({}, inMemoryCache.accounts), inMemoryCache.idTokens), inMemoryCache.accessTokens), inMemoryCache.refreshTokens), inMemoryCache.appMetadata);
    return cache;
  }
  /**
   * gets the current in memory cache for the client
   */


  getInMemoryCache() {
    this.logger.verbose("Getting in-memory cache"); // convert the cache key value store to inMemoryCache

    const inMemoryCache = this.cacheToInMemoryCache(this.getCache());
    return inMemoryCache;
  }
  /**
   * sets the current in memory cache for the client
   * @param inMemoryCache - key value map in memory
   */


  setInMemoryCache(inMemoryCache) {
    this.logger.verbose("Setting in-memory cache"); // convert and append the inMemoryCache to cacheKVStore

    const cache = this.inMemoryCacheToCache(inMemoryCache);
    this.setCache(cache);
    this.emitChange();
  }
  /**
   * get the current cache key-value store
   */


  getCache() {
    this.logger.verbose("Getting cache key-value store");
    return this.cache;
  }
  /**
   * sets the current cache (key value store)
   * @param cacheMap - key value map
   */


  setCache(cache) {
    this.logger.verbose("Setting cache key value store");
    this.cache = cache; // mark change in cache

    this.emitChange();
  }
  /**
   * Gets cache item with given key.
   * @param key - lookup key for the cache entry
   */


  getItem(key) {
    this.logger.verbosePii(`Item key: ${key}`); // read cache

    const cache = this.getCache();
    return cache[key];
  }
  /**
   * Gets cache item with given key-value
   * @param key - lookup key for the cache entry
   * @param value - value of the cache entry
   */


  setItem(key, value) {
    this.logger.verbosePii(`Item key: ${key}`); // read cache

    const cache = this.getCache();
    cache[key] = value; // write to cache

    this.setCache(cache);
  }
  /**
   * fetch the account entity
   * @param accountKey - lookup key to fetch cache type AccountEntity
   */


  getAccount(accountKey) {
    const account = this.getItem(accountKey);

    if (AccountEntity.isAccountEntity(account)) {
      return account;
    }

    return null;
  }
  /**
   * set account entity
   * @param account - cache value to be set of type AccountEntity
   */


  setAccount(account) {
    const accountKey = account.generateAccountKey();
    this.setItem(accountKey, account);
  }
  /**
   * fetch the idToken credential
   * @param idTokenKey - lookup key to fetch cache type IdTokenEntity
   */


  getIdTokenCredential(idTokenKey) {
    const idToken = this.getItem(idTokenKey);

    if (IdTokenEntity.isIdTokenEntity(idToken)) {
      return idToken;
    }

    return null;
  }
  /**
   * set idToken credential
   * @param idToken - cache value to be set of type IdTokenEntity
   */


  setIdTokenCredential(idToken) {
    const idTokenKey = idToken.generateCredentialKey();
    this.setItem(idTokenKey, idToken);
  }
  /**
   * fetch the accessToken credential
   * @param accessTokenKey - lookup key to fetch cache type AccessTokenEntity
   */


  getAccessTokenCredential(accessTokenKey) {
    const accessToken = this.getItem(accessTokenKey);

    if (AccessTokenEntity.isAccessTokenEntity(accessToken)) {
      return accessToken;
    }

    return null;
  }
  /**
   * set accessToken credential
   * @param accessToken -  cache value to be set of type AccessTokenEntity
   */


  setAccessTokenCredential(accessToken) {
    const accessTokenKey = accessToken.generateCredentialKey();
    this.setItem(accessTokenKey, accessToken);
  }
  /**
   * fetch the refreshToken credential
   * @param refreshTokenKey - lookup key to fetch cache type RefreshTokenEntity
   */


  getRefreshTokenCredential(refreshTokenKey) {
    const refreshToken = this.getItem(refreshTokenKey);

    if (RefreshTokenEntity.isRefreshTokenEntity(refreshToken)) {
      return refreshToken;
    }

    return null;
  }
  /**
   * set refreshToken credential
   * @param refreshToken - cache value to be set of type RefreshTokenEntity
   */


  setRefreshTokenCredential(refreshToken) {
    const refreshTokenKey = refreshToken.generateCredentialKey();
    this.setItem(refreshTokenKey, refreshToken);
  }
  /**
   * fetch appMetadata entity from the platform cache
   * @param appMetadataKey - lookup key to fetch cache type AppMetadataEntity
   */


  getAppMetadata(appMetadataKey) {
    const appMetadata = this.getItem(appMetadataKey);

    if (AppMetadataEntity.isAppMetadataEntity(appMetadataKey, appMetadata)) {
      return appMetadata;
    }

    return null;
  }
  /**
   * set appMetadata entity to the platform cache
   * @param appMetadata - cache value to be set of type AppMetadataEntity
   */


  setAppMetadata(appMetadata) {
    const appMetadataKey = appMetadata.generateAppMetadataKey();
    this.setItem(appMetadataKey, appMetadata);
  }
  /**
   * fetch server telemetry entity from the platform cache
   * @param serverTelemetrykey - lookup key to fetch cache type ServerTelemetryEntity
   */


  getServerTelemetry(serverTelemetrykey) {
    const serverTelemetryEntity = this.getItem(serverTelemetrykey);

    if (serverTelemetryEntity && ServerTelemetryEntity.isServerTelemetryEntity(serverTelemetrykey, serverTelemetryEntity)) {
      return serverTelemetryEntity;
    }

    return null;
  }
  /**
   * set server telemetry entity to the platform cache
   * @param serverTelemetryKey - lookup key to fetch cache type ServerTelemetryEntity
   * @param serverTelemetry - cache value to be set of type ServerTelemetryEntity
   */


  setServerTelemetry(serverTelemetryKey, serverTelemetry) {
    this.setItem(serverTelemetryKey, serverTelemetry);
  }
  /**
   * fetch authority metadata entity from the platform cache
   * @param key - lookup key to fetch cache type AuthorityMetadataEntity
   */


  getAuthorityMetadata(key) {
    const authorityMetadataEntity = this.getItem(key);

    if (authorityMetadataEntity && AuthorityMetadataEntity.isAuthorityMetadataEntity(key, authorityMetadataEntity)) {
      return authorityMetadataEntity;
    }

    return null;
  }
  /**
   * Get all authority metadata keys
   */


  getAuthorityMetadataKeys() {
    return this.getKeys().filter(key => {
      return this.isAuthorityMetadata(key);
    });
  }
  /**
   * set authority metadata entity to the platform cache
   * @param key - lookup key to fetch cache type AuthorityMetadataEntity
   * @param metadata - cache value to be set of type AuthorityMetadataEntity
   */


  setAuthorityMetadata(key, metadata) {
    this.setItem(key, metadata);
  }
  /**
   * fetch throttling entity from the platform cache
   * @param throttlingCacheKey - lookup key to fetch cache type ThrottlingEntity
   */


  getThrottlingCache(throttlingCacheKey) {
    const throttlingCache = this.getItem(throttlingCacheKey);

    if (throttlingCache && ThrottlingEntity.isThrottlingEntity(throttlingCacheKey, throttlingCache)) {
      return throttlingCache;
    }

    return null;
  }
  /**
   * set throttling entity to the platform cache
   * @param throttlingCacheKey - lookup key to fetch cache type ThrottlingEntity
   * @param throttlingCache - cache value to be set of type ThrottlingEntity
   */


  setThrottlingCache(throttlingCacheKey, throttlingCache) {
    this.setItem(throttlingCacheKey, throttlingCache);
  }
  /**
   * Removes the cache item from memory with the given key.
   * @param key - lookup key to remove a cache entity
   * @param inMemory - key value map of the cache
   */


  removeItem(key) {
    this.logger.verbosePii(`Item key: ${key}`); // read inMemoryCache

    let result = false;
    const cache = this.getCache();

    if (!!cache[key]) {
      delete cache[key];
      result = true;
    } // write to the cache after removal


    if (result) {
      this.setCache(cache);
      this.emitChange();
    }

    return result;
  }
  /**
   * Checks whether key is in cache.
   * @param key - look up key for a cache entity
   */


  containsKey(key) {
    return this.getKeys().includes(key);
  }
  /**
   * Gets all keys in window.
   */


  getKeys() {
    this.logger.verbose("Retrieving all cache keys"); // read cache

    const cache = this.getCache();
    return [...Object.keys(cache)];
  }
  /**
   * Clears all cache entries created by MSAL (except tokens).
   */


  clear() {
    this.logger.verbose("Clearing cache entries created by MSAL"); // read inMemoryCache

    const cacheKeys = this.getKeys(); // delete each element

    cacheKeys.forEach(key => {
      this.removeItem(key);
    });
    this.emitChange();
  }
  /**
   * Initialize in memory cache from an exisiting cache vault
   * @param cache - blob formatted cache (JSON)
   */


  static generateInMemoryCache(cache) {
    return Deserializer.deserializeAllCache(Deserializer.deserializeJSONBlob(cache));
  }
  /**
   * retrieves the final JSON
   * @param inMemoryCache - itemised cache read from the JSON
   */


  static generateJsonCache(inMemoryCache) {
    return Serializer.serializeAllCache(inMemoryCache);
  }

}

function ownKeys$3(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$3(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$3(Object(source), true).forEach(function (key) { _defineProperty$1(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$3(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
const defaultSerializedCache = {
  Account: {},
  IdToken: {},
  AccessToken: {},
  RefreshToken: {},
  AppMetadata: {}
};
/**
 * In-memory token cache manager
 * @public
 */

class TokenCache {
  constructor(storage, logger, cachePlugin) {
    this.cacheHasChanged = false;
    this.storage = storage;
    this.storage.registerChangeEmitter(this.handleChangeEvent.bind(this));

    if (cachePlugin) {
      this.persistence = cachePlugin;
    }

    this.logger = logger;
  }
  /**
   * Set to true if cache state has changed since last time serialize or writeToPersistence was called
   */


  hasChanged() {
    return this.cacheHasChanged;
  }
  /**
   * Serializes in memory cache to JSON
   */


  serialize() {
    this.logger.verbose("Serializing in-memory cache");
    let finalState = Serializer.serializeAllCache(this.storage.getInMemoryCache()); // if cacheSnapshot not null or empty, merge

    if (!StringUtils.isEmpty(this.cacheSnapshot)) {
      this.logger.verbose("Reading cache snapshot from disk");
      finalState = this.mergeState(JSON.parse(this.cacheSnapshot), finalState);
    } else {
      this.logger.verbose("No cache snapshot to merge");
    }

    this.cacheHasChanged = false;
    return JSON.stringify(finalState);
  }
  /**
   * Deserializes JSON to in-memory cache. JSON should be in MSAL cache schema format
   * @param cache - blob formatted cache
   */


  deserialize(cache) {
    this.logger.verbose("Deserializing JSON to in-memory cache");
    this.cacheSnapshot = cache;

    if (!StringUtils.isEmpty(this.cacheSnapshot)) {
      this.logger.verbose("Reading cache snapshot from disk");
      const deserializedCache = Deserializer.deserializeAllCache(this.overlayDefaults(JSON.parse(this.cacheSnapshot)));
      this.storage.setInMemoryCache(deserializedCache);
    } else {
      this.logger.verbose("No cache snapshot to deserialize");
    }
  }
  /**
   * Fetches the cache key-value map
   */


  getKVStore() {
    return this.storage.getCache();
  }
  /**
   * API that retrieves all accounts currently in cache to the user
   */


  async getAllAccounts() {
    this.logger.verbose("getAllAccounts called");
    let cacheContext;

    try {
      if (this.persistence) {
        cacheContext = new TokenCacheContext(this, false);
        await this.persistence.beforeCacheAccess(cacheContext);
      }

      return this.storage.getAllAccounts();
    } finally {
      if (this.persistence && cacheContext) {
        await this.persistence.afterCacheAccess(cacheContext);
      }
    }
  }
  /**
   * Returns the signed in account matching homeAccountId.
   * (the account object is created at the time of successful login)
   * or null when no matching account is found
   * @param homeAccountId - unique identifier for an account (uid.utid)
   */


  async getAccountByHomeId(homeAccountId) {
    const allAccounts = await this.getAllAccounts();

    if (!StringUtils.isEmpty(homeAccountId) && allAccounts && allAccounts.length) {
      return allAccounts.filter(accountObj => accountObj.homeAccountId === homeAccountId)[0] || null;
    } else {
      return null;
    }
  }
  /**
   * Returns the signed in account matching localAccountId.
   * (the account object is created at the time of successful login)
   * or null when no matching account is found
   * @param localAccountId - unique identifier of an account (sub/obj when homeAccountId cannot be populated)
   */


  async getAccountByLocalId(localAccountId) {
    const allAccounts = await this.getAllAccounts();

    if (!StringUtils.isEmpty(localAccountId) && allAccounts && allAccounts.length) {
      return allAccounts.filter(accountObj => accountObj.localAccountId === localAccountId)[0] || null;
    } else {
      return null;
    }
  }
  /**
   * API to remove a specific account and the relevant data from cache
   * @param account - AccountInfo passed by the user
   */


  async removeAccount(account) {
    this.logger.verbose("removeAccount called");
    let cacheContext;

    try {
      if (this.persistence) {
        cacheContext = new TokenCacheContext(this, true);
        await this.persistence.beforeCacheAccess(cacheContext);
      }

      this.storage.removeAccount(AccountEntity.generateAccountCacheKey(account));
    } finally {
      if (this.persistence && cacheContext) {
        await this.persistence.afterCacheAccess(cacheContext);
      }
    }
  }
  /**
   * Called when the cache has changed state.
   */


  handleChangeEvent() {
    this.cacheHasChanged = true;
  }
  /**
   * Merge in memory cache with the cache snapshot.
   * @param oldState - cache before changes
   * @param currentState - current cache state in the library
   */


  mergeState(oldState, currentState) {
    this.logger.verbose("Merging in-memory cache with cache snapshot");
    const stateAfterRemoval = this.mergeRemovals(oldState, currentState);
    return this.mergeUpdates(stateAfterRemoval, currentState);
  }
  /**
   * Deep update of oldState based on newState values
   * @param oldState - cache before changes
   * @param newState - updated cache
   */


  mergeUpdates(oldState, newState) {
    Object.keys(newState).forEach(newKey => {
      const newValue = newState[newKey]; // if oldState does not contain value but newValue does, add it

      if (!oldState.hasOwnProperty(newKey)) {
        if (newValue !== null) {
          oldState[newKey] = newValue;
        }
      } else {
        // both oldState and newState contain the key, do deep update
        const newValueNotNull = newValue !== null;
        const newValueIsObject = typeof newValue === "object";
        const newValueIsNotArray = !Array.isArray(newValue);
        const oldStateNotUndefinedOrNull = typeof oldState[newKey] !== "undefined" && oldState[newKey] !== null;

        if (newValueNotNull && newValueIsObject && newValueIsNotArray && oldStateNotUndefinedOrNull) {
          this.mergeUpdates(oldState[newKey], newValue);
        } else {
          oldState[newKey] = newValue;
        }
      }
    });
    return oldState;
  }
  /**
   * Removes entities in oldState that the were removed from newState. If there are any unknown values in root of
   * oldState that are not recognized, they are left untouched.
   * @param oldState - cache before changes
   * @param newState - updated cache
   */


  mergeRemovals(oldState, newState) {
    this.logger.verbose("Remove updated entries in cache");
    const accounts = oldState.Account ? this.mergeRemovalsDict(oldState.Account, newState.Account) : oldState.Account;
    const accessTokens = oldState.AccessToken ? this.mergeRemovalsDict(oldState.AccessToken, newState.AccessToken) : oldState.AccessToken;
    const refreshTokens = oldState.RefreshToken ? this.mergeRemovalsDict(oldState.RefreshToken, newState.RefreshToken) : oldState.RefreshToken;
    const idTokens = oldState.IdToken ? this.mergeRemovalsDict(oldState.IdToken, newState.IdToken) : oldState.IdToken;
    const appMetadata = oldState.AppMetadata ? this.mergeRemovalsDict(oldState.AppMetadata, newState.AppMetadata) : oldState.AppMetadata;
    return _objectSpread$3(_objectSpread$3({}, oldState), {}, {
      Account: accounts,
      AccessToken: accessTokens,
      RefreshToken: refreshTokens,
      IdToken: idTokens,
      AppMetadata: appMetadata
    });
  }
  /**
   * Helper to merge new cache with the old one
   * @param oldState - cache before changes
   * @param newState - updated cache
   */


  mergeRemovalsDict(oldState, newState) {
    const finalState = _objectSpread$3({}, oldState);

    Object.keys(oldState).forEach(oldKey => {
      if (!newState || !newState.hasOwnProperty(oldKey)) {
        delete finalState[oldKey];
      }
    });
    return finalState;
  }
  /**
   * Helper to overlay as a part of cache merge
   * @param passedInCache - cache read from the blob
   */


  overlayDefaults(passedInCache) {
    this.logger.verbose("Overlaying input cache with the default cache");
    return {
      Account: _objectSpread$3(_objectSpread$3({}, defaultSerializedCache.Account), passedInCache.Account),
      IdToken: _objectSpread$3(_objectSpread$3({}, defaultSerializedCache.IdToken), passedInCache.IdToken),
      AccessToken: _objectSpread$3(_objectSpread$3({}, defaultSerializedCache.AccessToken), passedInCache.AccessToken),
      RefreshToken: _objectSpread$3(_objectSpread$3({}, defaultSerializedCache.RefreshToken), passedInCache.RefreshToken),
      AppMetadata: _objectSpread$3(_objectSpread$3({}, defaultSerializedCache.AppMetadata), passedInCache.AppMetadata)
    };
  }

}

/* eslint-disable header/header */
const name = "@azure/msal-node";
const version = "1.1.0";

function ownKeys$2(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$2(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$2(Object(source), true).forEach(function (key) { _defineProperty$1(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$2(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
/**
 * Base abstract class for all ClientApplications - public and confidential
 * @public
 */

class ClientApplication {
  /**
   * Constructor for the ClientApplication
   */
  constructor(configuration) {
    this.config = buildAppConfiguration(configuration);
    this.cryptoProvider = new CryptoProvider();
    this.logger = new Logger(this.config.system.loggerOptions, name, version);
    this.storage = new NodeStorage(this.logger, this.config.auth.clientId, this.cryptoProvider);
    this.tokenCache = new TokenCache(this.storage, this.logger, this.config.cache.cachePlugin);
  }
  /**
   * Creates the URL of the authorization request, letting the user input credentials and consent to the
   * application. The URL targets the /authorize endpoint of the authority configured in the
   * application object.
   *
   * Once the user inputs their credentials and consents, the authority will send a response to the redirect URI
   * sent in the request and should contain an authorization code, which can then be used to acquire tokens via
   * `acquireTokenByCode(AuthorizationCodeRequest)`.
   */


  async getAuthCodeUrl(request) {
    this.logger.info("getAuthCodeUrl called");

    const validRequest = _objectSpread$2(_objectSpread$2(_objectSpread$2({}, request), this.initializeBaseRequest(request)), {}, {
      responseMode: request.responseMode || ResponseMode.QUERY,
      authenticationScheme: AuthenticationScheme.BEARER
    });

    const authClientConfig = await this.buildOauthClientConfiguration(validRequest.authority);
    this.logger.verbose("Auth client config generated");
    const authorizationCodeClient = new AuthorizationCodeClient(authClientConfig);
    return authorizationCodeClient.getAuthCodeUrl(validRequest);
  }
  /**
   * Acquires a token by exchanging the Authorization Code received from the first step of OAuth2.0
   * Authorization Code flow.
   *
   * `getAuthCodeUrl(AuthorizationCodeUrlRequest)` can be used to create the URL for the first step of OAuth2.0
   * Authorization Code flow. Ensure that values for redirectUri and scopes in AuthorizationCodeUrlRequest and
   * AuthorizationCodeRequest are the same.
   */


  async acquireTokenByCode(request) {
    this.logger.info("acquireTokenByCode called");

    const validRequest = _objectSpread$2(_objectSpread$2(_objectSpread$2({}, request), this.initializeBaseRequest(request)), {}, {
      authenticationScheme: AuthenticationScheme.BEARER
    });

    const serverTelemetryManager = this.initializeServerTelemetryManager(ApiId.acquireTokenByCode, validRequest.correlationId);

    try {
      const authClientConfig = await this.buildOauthClientConfiguration(validRequest.authority, serverTelemetryManager);
      this.logger.verbose("Auth client config generated");
      const authorizationCodeClient = new AuthorizationCodeClient(authClientConfig);
      return authorizationCodeClient.acquireToken(validRequest);
    } catch (e) {
      serverTelemetryManager.cacheFailedRequest(e);
      throw e;
    }
  }
  /**
   * Acquires a token by exchanging the refresh token provided for a new set of tokens.
   *
   * This API is provided only for scenarios where you would like to migrate from ADAL to MSAL. Otherwise, it is
   * recommended that you use `acquireTokenSilent()` for silent scenarios. When using `acquireTokenSilent()`, MSAL will
   * handle the caching and refreshing of tokens automatically.
   */


  async acquireTokenByRefreshToken(request) {
    this.logger.info("acquireTokenByRefreshToken called");

    const validRequest = _objectSpread$2(_objectSpread$2(_objectSpread$2({}, request), this.initializeBaseRequest(request)), {}, {
      authenticationScheme: AuthenticationScheme.BEARER
    });

    const serverTelemetryManager = this.initializeServerTelemetryManager(ApiId.acquireTokenByRefreshToken, validRequest.correlationId);

    try {
      const refreshTokenClientConfig = await this.buildOauthClientConfiguration(validRequest.authority, serverTelemetryManager);
      this.logger.verbose("Auth client config generated");
      const refreshTokenClient = new RefreshTokenClient(refreshTokenClientConfig);
      return refreshTokenClient.acquireToken(validRequest);
    } catch (e) {
      serverTelemetryManager.cacheFailedRequest(e);
      throw e;
    }
  }
  /**
   * Acquires a token silently when a user specifies the account the token is requested for.
   *
   * This API expects the user to provide an account object and looks into the cache to retrieve the token if present.
   * There is also an optional "forceRefresh" boolean the user can send to bypass the cache for access_token and id_token.
   * In case the refresh_token is expired or not found, an error is thrown
   * and the guidance is for the user to call any interactive token acquisition API (eg: `acquireTokenByCode()`).
   */


  async acquireTokenSilent(request) {
    const validRequest = _objectSpread$2(_objectSpread$2(_objectSpread$2({}, request), this.initializeBaseRequest(request)), {}, {
      forceRefresh: request.forceRefresh || false
    });

    const serverTelemetryManager = this.initializeServerTelemetryManager(ApiId.acquireTokenSilent, validRequest.correlationId, validRequest.forceRefresh);

    try {
      const silentFlowClientConfig = await this.buildOauthClientConfiguration(validRequest.authority, serverTelemetryManager);
      const silentFlowClient = new SilentFlowClient(silentFlowClientConfig);
      return silentFlowClient.acquireToken(validRequest);
    } catch (e) {
      serverTelemetryManager.cacheFailedRequest(e);
      throw e;
    }
  }
  /**
   * Gets the token cache for the application.
   */


  getTokenCache() {
    this.logger.info("getTokenCache called");
    return this.tokenCache;
  }
  /**
   * Returns the logger instance
   */


  getLogger() {
    return this.logger;
  }
  /**
   * Replaces the default logger set in configurations with new Logger with new configurations
   * @param logger - Logger instance
   */


  setLogger(logger) {
    this.logger = logger;
  }
  /**
   * Builds the common configuration to be passed to the common component based on the platform configurarion
   * @param authority - user passed authority in configuration
   * @param serverTelemetryManager - initializes servertelemetry if passed
   */


  async buildOauthClientConfiguration(authority, serverTelemetryManager, azureRegionConfiguration) {
    this.logger.verbose("buildOauthClientConfiguration called"); // using null assertion operator as we ensure that all config values have default values in buildConfiguration()

    this.logger.verbose(`building oauth client configuration with the authority: ${authority}`);
    const discoveredAuthority = await this.createAuthority(authority, azureRegionConfiguration);
    return {
      authOptions: {
        clientId: this.config.auth.clientId,
        authority: discoveredAuthority,
        clientCapabilities: this.config.auth.clientCapabilities
      },
      loggerOptions: {
        loggerCallback: this.config.system.loggerOptions.loggerCallback,
        piiLoggingEnabled: this.config.system.loggerOptions.piiLoggingEnabled
      },
      cryptoInterface: this.cryptoProvider,
      networkInterface: this.config.system.networkClient,
      storageInterface: this.storage,
      serverTelemetryManager: serverTelemetryManager,
      clientCredentials: {
        clientSecret: this.clientSecret,
        clientAssertion: this.clientAssertion ? this.getClientAssertion(discoveredAuthority) : undefined
      },
      libraryInfo: {
        sku: Constants$1.MSAL_SKU,
        version: version,
        cpu: process.arch || "",
        os: process.platform || ""
      },
      persistencePlugin: this.config.cache.cachePlugin,
      serializableCache: this.tokenCache
    };
  }

  getClientAssertion(authority) {
    return {
      assertion: this.clientAssertion.getJwt(this.cryptoProvider, this.config.auth.clientId, authority.tokenEndpoint),
      assertionType: Constants$1.JWT_BEARER_ASSERTION_TYPE
    };
  }
  /**
   * Generates a request with the default scopes & generates a correlationId.
   * @param authRequest - BaseAuthRequest for initialization
   */


  initializeBaseRequest(authRequest) {
    this.logger.verbose("initializeRequestScopes called"); // Default authenticationScheme to Bearer, log that POP isn't supported yet

    if (authRequest.authenticationScheme && authRequest.authenticationScheme === AuthenticationScheme.POP) {
      this.logger.verbose("Authentication Scheme 'pop' is not supported yet, setting Authentication Scheme to 'Bearer' for request");
    }

    authRequest.authenticationScheme = AuthenticationScheme.BEARER;
    return _objectSpread$2(_objectSpread$2({}, authRequest), {}, {
      scopes: [...(authRequest && authRequest.scopes || []), ...OIDC_DEFAULT_SCOPES],
      correlationId: authRequest && authRequest.correlationId || this.cryptoProvider.createNewGuid(),
      authority: authRequest.authority || this.config.auth.authority
    });
  }
  /**
   * Initializes the server telemetry payload
   * @param apiId - Id for a specific request
   * @param correlationId - GUID
   * @param forceRefresh - boolean to indicate network call
   */


  initializeServerTelemetryManager(apiId, correlationId, forceRefresh) {
    const telemetryPayload = {
      clientId: this.config.auth.clientId,
      correlationId: correlationId,
      apiId: apiId,
      forceRefresh: forceRefresh || false
    };
    return new ServerTelemetryManager(telemetryPayload, this.storage);
  }
  /**
   * Create authority instance. If authority not passed in request, default to authority set on the application
   * object. If no authority set in application object, then default to common authority.
   * @param authorityString - authority from user configuration
   */


  async createAuthority(authorityString, azureRegionConfiguration) {
    this.logger.verbose("createAuthority called");
    const authorityOptions = {
      protocolMode: this.config.auth.protocolMode,
      knownAuthorities: this.config.auth.knownAuthorities,
      cloudDiscoveryMetadata: this.config.auth.cloudDiscoveryMetadata,
      authorityMetadata: this.config.auth.authorityMetadata,
      azureRegionConfiguration
    };
    return await AuthorityFactory.createDiscoveredInstance(authorityString, this.config.system.networkClient, this.storage, authorityOptions);
  }

}

function ownKeys$1(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread$1(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys$1(Object(source), true).forEach(function (key) { _defineProperty$1(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys$1(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
/**
 * This class is to be used to acquire tokens for public client applications (desktop, mobile). Public client applications
 * are not trusted to safely store application secrets, and therefore can only request tokens in the name of an user.
 * @public
 */

class PublicClientApplication extends ClientApplication {
  /**
   * Important attributes in the Configuration object for auth are:
   * - clientID: the application ID of your application. You can obtain one by registering your application with our Application registration portal.
   * - authority: the authority URL for your application.
   *
   * AAD authorities are of the form https://login.microsoftonline.com/\{Enter_the_Tenant_Info_Here\}.
   * - If your application supports Accounts in one organizational directory, replace "Enter_the_Tenant_Info_Here" value with the Tenant Id or Tenant name (for example, contoso.microsoft.com).
   * - If your application supports Accounts in any organizational directory, replace "Enter_the_Tenant_Info_Here" value with organizations.
   * - If your application supports Accounts in any organizational directory and personal Microsoft accounts, replace "Enter_the_Tenant_Info_Here" value with common.
   * - To restrict support to Personal Microsoft accounts only, replace "Enter_the_Tenant_Info_Here" value with consumers.
   *
   * Azure B2C authorities are of the form https://\{instance\}/\{tenant\}/\{policy\}. Each policy is considered
   * its own authority. You will have to set the all of the knownAuthorities at the time of the client application
   * construction.
   *
   * ADFS authorities are of the form https://\{instance\}/adfs.
   */
  constructor(configuration) {
    super(configuration);
  }
  /**
   * Acquires a token from the authority using OAuth2.0 device code flow.
   * This flow is designed for devices that do not have access to a browser or have input constraints.
   * The authorization server issues a DeviceCode object with a verification code, an end-user code,
   * and the end-user verification URI. The DeviceCode object is provided through a callback, and the end-user should be
   * instructed to use another device to navigate to the verification URI to input credentials.
   * Since the client cannot receive incoming requests, it polls the authorization server repeatedly
   * until the end-user completes input of credentials.
   */


  async acquireTokenByDeviceCode(request) {
    this.logger.info("acquireTokenByDeviceCode called");
    const validRequest = Object.assign(request, this.initializeBaseRequest(request));
    const serverTelemetryManager = this.initializeServerTelemetryManager(ApiId.acquireTokenByDeviceCode, validRequest.correlationId);

    try {
      const deviceCodeConfig = await this.buildOauthClientConfiguration(validRequest.authority, serverTelemetryManager);
      this.logger.verbose("Auth client config generated");
      const deviceCodeClient = new DeviceCodeClient(deviceCodeConfig);
      return deviceCodeClient.acquireToken(validRequest);
    } catch (e) {
      serverTelemetryManager.cacheFailedRequest(e);
      throw e;
    }
  }
  /**
   * Acquires tokens with password grant by exchanging client applications username and password for credentials
   *
   * The latest OAuth 2.0 Security Best Current Practice disallows the password grant entirely.
   * More details on this recommendation at https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13#section-3.4
   * Microsoft's documentation and recommendations are at:
   * https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-authentication-flows#usernamepassword
   *
   * @param request - UsenamePasswordRequest
   */


  async acquireTokenByUsernamePassword(request) {
    this.logger.info("acquireTokenByUsernamePassword called");

    const validRequest = _objectSpread$1(_objectSpread$1({}, request), this.initializeBaseRequest(request));

    const serverTelemetryManager = this.initializeServerTelemetryManager(ApiId.acquireTokenByUsernamePassword, validRequest.correlationId);

    try {
      const usernamePasswordClientConfig = await this.buildOauthClientConfiguration(validRequest.authority, serverTelemetryManager);
      this.logger.verbose("Auth client config generated");
      const usernamePasswordClient = new UsernamePasswordClient(usernamePasswordClientConfig);
      return usernamePasswordClient.acquireToken(validRequest);
    } catch (e) {
      serverTelemetryManager.cacheFailedRequest(e);
      throw e;
    }
  }

}

/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */
/**
 * Client assertion of type jwt-bearer used in confidential client flows
 * @public
 */

class ClientAssertion {
  /**
   * Initialize the ClientAssertion class from the clientAssertion passed by the user
   * @param assertion - refer https://tools.ietf.org/html/rfc7521
   */
  static fromAssertion(assertion) {
    const clientAssertion = new ClientAssertion();
    clientAssertion.jwt = assertion;
    return clientAssertion;
  }
  /**
   * Initialize the ClientAssertion class from the certificate passed by the user
   * @param thumbprint - identifier of a certificate
   * @param privateKey - secret key
   * @param publicCertificate - electronic document provided to prove the ownership of the public key
   */


  static fromCertificate(thumbprint, privateKey, publicCertificate) {
    const clientAssertion = new ClientAssertion();
    clientAssertion.privateKey = privateKey;
    clientAssertion.thumbprint = thumbprint;

    if (publicCertificate) {
      clientAssertion.publicCertificate = this.parseCertificate(publicCertificate);
    }

    return clientAssertion;
  }
  /**
   * Update JWT for certificate based clientAssertion, if passed by the user, uses it as is
   * @param cryptoProvider - library's crypto helper
   * @param issuer - iss claim
   * @param jwtAudience - aud claim
   */


  getJwt(cryptoProvider, issuer, jwtAudience) {
    // if assertion was created from certificate, check if jwt is expired and create new one.
    if (this.privateKey && this.thumbprint) {
      if (this.jwt && !this.isExpired() && issuer === this.issuer && jwtAudience === this.jwtAudience) {
        return this.jwt;
      }

      return this.createJwt(cryptoProvider, issuer, jwtAudience);
    }
    /*
     * if assertion was created by caller, then we just append it. It is up to the caller to
     * ensure that it contains necessary claims and that it is not expired.
     */


    if (this.jwt) {
      return this.jwt;
    }

    throw ClientAuthError.createInvalidAssertionError();
  }
  /**
   * JWT format and required claims specified: https://tools.ietf.org/html/rfc7523#section-3
   */


  createJwt(cryptoProvider, issuer, jwtAudience) {
    this.issuer = issuer;
    this.jwtAudience = jwtAudience;
    const issuedAt = TimeUtils.nowSeconds();
    this.expirationTime = issuedAt + 600;
    const header = {
      [JwtConstants.ALGORITHM]: JwtConstants.RSA_256,
      [JwtConstants.X5T]: EncodingUtils.base64EncodeUrl(this.thumbprint, "hex")
    };

    if (this.publicCertificate) {
      Object.assign(header, {
        [JwtConstants.X5C]: this.publicCertificate
      });
    }

    const payload = {
      [JwtConstants.AUDIENCE]: this.jwtAudience,
      [JwtConstants.EXPIRATION_TIME]: this.expirationTime,
      [JwtConstants.ISSUER]: this.issuer,
      [JwtConstants.SUBJECT]: this.issuer,
      [JwtConstants.NOT_BEFORE]: issuedAt,
      [JwtConstants.JWT_ID]: cryptoProvider.createNewGuid()
    };
    this.jwt = sign(payload, this.privateKey, {
      header: header
    });
    return this.jwt;
  }
  /**
   * Utility API to check expiration
   */


  isExpired() {
    return this.expirationTime < TimeUtils.nowSeconds();
  }
  /**
   * Extracts the raw certs from a given certificate string and returns them in an array.
   * @param publicCertificate - electronic document provided to prove the ownership of the public key
   */


  static parseCertificate(publicCertificate) {
    /**
     * This is regex to identify the certs in a given certificate string.
     * We want to look for the contents between the BEGIN and END certificate strings, without the associated newlines.
     * The information in parens "(.+?)" is the capture group to represent the cert we want isolated.
     * "." means any string character, "+" means match 1 or more times, and "?" means the shortest match.
     * The "g" at the end of the regex means search the string globally, and the "s" enables the "." to match newlines.
     */
    const regexToFindCerts = /-----BEGIN CERTIFICATE-----\n(.+?)\n-----END CERTIFICATE-----/gs;
    const certs = [];
    let matches;

    while ((matches = regexToFindCerts.exec(publicCertificate)) !== null) {
      // matches[1] represents the first parens capture group in the regex.
      certs.push(matches[1].replace(/\n/, ""));
    }

    return certs;
  }

}

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) { symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); } keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty$1(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }
/**
 *  This class is to be used to acquire tokens for confidential client applications (webApp, webAPI). Confidential client applications
 *  will configure application secrets, client certificates/assertions as applicable
 * @public
 */

class ConfidentialClientApplication extends ClientApplication {
  /**
   * Constructor for the ConfidentialClientApplication
   *
   * Required attributes in the Configuration object are:
   * - clientID: the application ID of your application. You can obtain one by registering your application with our application registration portal
   * - authority: the authority URL for your application.
   * - client credential: Must set either client secret, certificate, or assertion for confidential clients. You can obtain a client secret from the application registration portal.
   *
   * In Azure AD, authority is a URL indicating of the form https://login.microsoftonline.com/\{Enter_the_Tenant_Info_Here\}.
   * If your application supports Accounts in one organizational directory, replace "Enter_the_Tenant_Info_Here" value with the Tenant Id or Tenant name (for example, contoso.microsoft.com).
   * If your application supports Accounts in any organizational directory, replace "Enter_the_Tenant_Info_Here" value with organizations.
   * If your application supports Accounts in any organizational directory and personal Microsoft accounts, replace "Enter_the_Tenant_Info_Here" value with common.
   * To restrict support to Personal Microsoft accounts only, replace "Enter_the_Tenant_Info_Here" value with consumers.
   *
   * In Azure B2C, authority is of the form https://\{instance\}/tfp/\{tenant\}/\{policyName\}/
   * Full B2C functionality will be available in this library in future versions.
   *
   * @param Configuration - configuration object for the MSAL ConfidentialClientApplication instance
   */
  constructor(configuration) {
    super(configuration);
    this.setClientCredential(this.config);
  }
  /**
   * Acquires tokens from the authority for the application (not for an end user).
   */


  async acquireTokenByClientCredential(request) {
    this.logger.info("acquireTokenByClientCredential called");

    const validRequest = _objectSpread(_objectSpread({}, request), this.initializeBaseRequest(request));

    const azureRegionConfiguration = {
      azureRegion: validRequest.azureRegion,
      environmentRegion: process.env[REGION_ENVIRONMENT_VARIABLE]
    };
    const serverTelemetryManager = this.initializeServerTelemetryManager(ApiId.acquireTokenByClientCredential, validRequest.correlationId, validRequest.skipCache);

    try {
      const clientCredentialConfig = await this.buildOauthClientConfiguration(validRequest.authority, serverTelemetryManager, azureRegionConfiguration);
      this.logger.verbose("Auth client config generated");
      const clientCredentialClient = new ClientCredentialClient(clientCredentialConfig);
      return clientCredentialClient.acquireToken(validRequest);
    } catch (e) {
      serverTelemetryManager.cacheFailedRequest(e);
      throw e;
    }
  }
  /**
   * Acquires tokens from the authority for the application.
   *
   * Used in scenarios where the current app is a middle-tier service which was called with a token
   * representing an end user. The current app can use the token (oboAssertion) to request another
   * token to access downstream web API, on behalf of that user.
   *
   * The current middle-tier app has no user interaction to obtain consent.
   * See how to gain consent upfront for your middle-tier app from this article.
   * https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow#gaining-consent-for-the-middle-tier-application
   */


  async acquireTokenOnBehalfOf(request) {
    this.logger.info("acquireTokenOnBehalfOf called");

    const validRequest = _objectSpread(_objectSpread({}, request), this.initializeBaseRequest(request));

    const clientCredentialConfig = await this.buildOauthClientConfiguration(validRequest.authority);
    this.logger.verbose("Auth client config generated");
    const oboClient = new OnBehalfOfClient(clientCredentialConfig);
    return oboClient.acquireToken(validRequest);
  }

  setClientCredential(configuration) {
    const clientSecretNotEmpty = !StringUtils.isEmpty(configuration.auth.clientSecret);
    const clientAssertionNotEmpty = !StringUtils.isEmpty(configuration.auth.clientAssertion);
    const certificate = configuration.auth.clientCertificate;
    const certificateNotEmpty = !StringUtils.isEmpty(certificate.thumbprint) || !StringUtils.isEmpty(certificate.privateKey); // Check that at most one credential is set on the application

    if (clientSecretNotEmpty && clientAssertionNotEmpty || clientAssertionNotEmpty && certificateNotEmpty || clientSecretNotEmpty && certificateNotEmpty) {
      throw ClientAuthError.createInvalidCredentialError();
    }

    if (clientSecretNotEmpty) {
      this.clientSecret = configuration.auth.clientSecret;
      return;
    }

    if (clientAssertionNotEmpty) {
      this.clientAssertion = ClientAssertion.fromAssertion(configuration.auth.clientAssertion);
      return;
    }

    if (!certificateNotEmpty) {
      throw ClientAuthError.createInvalidCredentialError();
    } else {
      this.clientAssertion = ClientAssertion.fromCertificate(certificate.thumbprint, certificate.privateKey, configuration.auth.clientCertificate?.x5c);
    }
  }

}

export { AuthError, AuthErrorMessage, ClientApplication, ClientAssertion, ClientAuthError, ClientAuthErrorMessage, ClientConfigurationError, ClientConfigurationErrorMessage, ConfidentialClientApplication, CryptoProvider, InteractionRequiredAuthError, LogLevel, Logger, NodeStorage, PromptValue, ProtocolMode, PublicClientApplication, ResponseMode, ServerError, TokenCache, TokenCacheContext, buildAppConfiguration };
//# sourceMappingURL=index.js.map

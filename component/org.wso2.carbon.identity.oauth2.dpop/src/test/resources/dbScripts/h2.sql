CREATE TABLE IF NOT EXISTS IDN_OAUTH_CONSUMER_APPS (
    ID INTEGER NOT NULL AUTO_INCREMENT,
    CONSUMER_KEY VARCHAR (255),
    CONSUMER_SECRET VARCHAR (2048),
    USERNAME VARCHAR (255),
    TENANT_ID INTEGER DEFAULT 0,
    USER_DOMAIN VARCHAR(50),
    APP_NAME VARCHAR (255),
    OAUTH_VERSION VARCHAR (128),
    CALLBACK_URL VARCHAR (2048),
    GRANT_TYPES VARCHAR (1024),
    PKCE_MANDATORY CHAR(1) DEFAULT '0',
    PKCE_SUPPORT_PLAIN CHAR(1) DEFAULT '0',
    APP_STATE VARCHAR (25) DEFAULT 'ACTIVE',
    USER_ACCESS_TOKEN_EXPIRE_TIME BIGINT DEFAULT 3600,
    APP_ACCESS_TOKEN_EXPIRE_TIME BIGINT DEFAULT 3600,
    REFRESH_TOKEN_EXPIRE_TIME BIGINT DEFAULT 84600,
    ID_TOKEN_EXPIRE_TIME BIGINT DEFAULT 3600,
    CONSTRAINT CONSUMER_KEY_CONSTRAINT UNIQUE (TENANT_ID, CONSUMER_KEY),
    PRIMARY KEY (ID)
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_ACCESS_TOKEN (
    TOKEN_ID VARCHAR (255),
    ACCESS_TOKEN VARCHAR (2048),
    REFRESH_TOKEN VARCHAR (2048),
    CONSUMER_KEY_ID INTEGER,
    AUTHZ_USER VARCHAR (100),
    TENANT_ID INTEGER,
    USER_DOMAIN VARCHAR(50),
    USER_TYPE VARCHAR (25),
    GRANT_TYPE VARCHAR (50),
    TIME_CREATED TIMESTAMP DEFAULT 0,
    REFRESH_TOKEN_TIME_CREATED TIMESTAMP DEFAULT 0,
    VALIDITY_PERIOD BIGINT,
    REFRESH_TOKEN_VALIDITY_PERIOD BIGINT,
    TOKEN_SCOPE_HASH VARCHAR (32),
    TOKEN_STATE VARCHAR (25) DEFAULT 'ACTIVE',
    TOKEN_STATE_ID VARCHAR (128) DEFAULT 'NONE',
    SUBJECT_IDENTIFIER VARCHAR(255),
    ACCESS_TOKEN_HASH VARCHAR (512),
    REFRESH_TOKEN_HASH VARCHAR (512),
    IDP_ID INTEGER DEFAULT -1 NOT NULL,
    TOKEN_BINDING_REF VARCHAR (32) DEFAULT 'NONE',
    CONSENTED_TOKEN VARCHAR(6),
    AUTHORIZED_ORGANIZATION VARCHAR(36) DEFAULT 'NONE' NOT NULL,
    PRIMARY KEY (TOKEN_ID),
    FOREIGN KEY (CONSUMER_KEY_ID) REFERENCES IDN_OAUTH_CONSUMER_APPS(ID) ON DELETE CASCADE,
    CONSTRAINT CON_APP_KEY UNIQUE (CONSUMER_KEY_ID,AUTHZ_USER,TENANT_ID,USER_DOMAIN,USER_TYPE,TOKEN_SCOPE_HASH,
                                   TOKEN_STATE,TOKEN_STATE_ID,IDP_ID,TOKEN_BINDING_REF,AUTHORIZED_ORGANIZATION)
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_TOKEN_BINDING (
    TOKEN_ID VARCHAR (255),
    TOKEN_BINDING_TYPE VARCHAR (32),
    TOKEN_BINDING_REF VARCHAR (32),
    TOKEN_BINDING_VALUE VARCHAR (1024),
    TENANT_ID INTEGER DEFAULT -1,
    UNIQUE (TOKEN_ID,TOKEN_BINDING_TYPE,TOKEN_BINDING_VALUE),
    FOREIGN KEY (TOKEN_ID) REFERENCES IDN_OAUTH2_ACCESS_TOKEN(TOKEN_ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_AUTHORIZATION_CODE (
    CODE_ID VARCHAR (255),
    AUTHORIZATION_CODE VARCHAR (2048),
    CONSUMER_KEY_ID INTEGER,
    CALLBACK_URL VARCHAR (2048),
    SCOPE VARCHAR(2048),
    AUTHZ_USER VARCHAR (100),
    TENANT_ID INTEGER,
    USER_DOMAIN VARCHAR(50),
    TIME_CREATED TIMESTAMP,
    VALIDITY_PERIOD BIGINT,
    STATE VARCHAR (25) DEFAULT 'ACTIVE',
    TOKEN_ID VARCHAR(255),
    SUBJECT_IDENTIFIER VARCHAR(255),
    PKCE_CODE_CHALLENGE VARCHAR (255),
    PKCE_CODE_CHALLENGE_METHOD VARCHAR(128),
    AUTHORIZATION_CODE_HASH VARCHAR (512),
    IDP_ID INTEGER DEFAULT -1 NOT NULL,
    PRIMARY KEY (CODE_ID),
    FOREIGN KEY (CONSUMER_KEY_ID) REFERENCES IDN_OAUTH_CONSUMER_APPS(ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_DPOP_JKT (
    CODE_ID   VARCHAR(255),
    DPOP_JKT  VARCHAR(255),
    PRIMARY KEY (CODE_ID),
    FOREIGN KEY (CODE_ID) REFERENCES IDN_OAUTH2_AUTHORIZATION_CODE(CODE_ID) ON DELETE CASCADE
);

INSERT INTO IDN_OAUTH_CONSUMER_APPS (
    CONSUMER_KEY, CONSUMER_SECRET, USERNAME, TENANT_ID, USER_DOMAIN,
    APP_NAME, OAUTH_VERSION, CALLBACK_URL, GRANT_TYPES,
    PKCE_MANDATORY, PKCE_SUPPORT_PLAIN, APP_STATE,
    USER_ACCESS_TOKEN_EXPIRE_TIME, APP_ACCESS_TOKEN_EXPIRE_TIME,
    REFRESH_TOKEN_EXPIRE_TIME, ID_TOKEN_EXPIRE_TIME
) VALUES (
    'dummyKey123', 'dummySecret456', 'admin', 1, 'PRIMARY',
    'TestApp', 'OAuth2', 'https://callback.url', 'authorization_code refresh_token',
    '0', '0', 'ACTIVE',
    3600, 3600, 86400, 3600
);

INSERT INTO IDN_OAUTH2_ACCESS_TOKEN (
    TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN, CONSUMER_KEY_ID, AUTHZ_USER,
    TENANT_ID, USER_DOMAIN, USER_TYPE, GRANT_TYPE, TIME_CREATED,
    REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_VALIDITY_PERIOD,
    TOKEN_SCOPE_HASH, TOKEN_STATE, TOKEN_STATE_ID, SUBJECT_IDENTIFIER,
    ACCESS_TOKEN_HASH, REFRESH_TOKEN_HASH, IDP_ID, TOKEN_BINDING_REF,
    CONSENTED_TOKEN, AUTHORIZED_ORGANIZATION
) VALUES (
    'token123', 'access-token-abc', 'bde76f62-d955-381a-be3b-5adf16abae44', 1, 'admin',
    1, 'PRIMARY', 'APPLICATION', 'authorization_code', CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP, 3600, 86400,
    'dummyScopeHash', 'ACTIVE', 'NONE', 'subject123',
    'accessHashVal', '{"hash":"75deb4bb4a2f891d5358ec15114670f198f90f4af18146cda2e6c6061e9f33e1","algorithm":"SHA-256"}', 1, 'bindRef123',
    'true', 'org1'
);

INSERT INTO IDN_OAUTH2_TOKEN_BINDING (
    TOKEN_ID, TOKEN_BINDING_TYPE, TOKEN_BINDING_REF, TOKEN_BINDING_VALUE, TENANT_ID
) VALUES (
    'token123', 'DPoP', 'bindRef123', 'sampleBindingValue', 1
);

INSERT INTO IDN_OAUTH2_AUTHORIZATION_CODE (
    CODE_ID, AUTHORIZATION_CODE, CONSUMER_KEY_ID, CALLBACK_URL, SCOPE, AUTHZ_USER, TENANT_ID, USER_DOMAIN,
    TIME_CREATED, VALIDITY_PERIOD, STATE, TOKEN_ID, SUBJECT_IDENTIFIER, PKCE_CODE_CHALLENGE,
    PKCE_CODE_CHALLENGE_METHOD, AUTHORIZATION_CODE_HASH, IDP_ID
) VALUES (
    'sampleCodeId', '123456712638', 1, 'https://localhost/callback', 'openid email profile',
    'admin', -1234, 'PRIMARY', CURRENT_TIMESTAMP, 300000, 'ACTIVE', 'sample-token-id-123', 'sample-subject-id',
    'challengeSample', 'S256', '{"hash":"6bb77827142a402d9e561f519994ae689b88f2c2ea31c686f9531d210f064445","algorithm":"SHA-256"}', 1
);

import { registerAs } from '@nestjs/config';
import * as Joi from 'joi';

export default registerAs('iam', () => {
  const config = {
    routePathPrefix: process.env.IAM_ROUTE_PATH_PREFIX || '',
    auth: {
      methods: (process.env.IAM_AUTH_METHODS || '').split(','),
      passwordless: {
        tokenTtl: process.env.IAM_AUTH_PASSWORDLESS_TOKEN_TTL,
      },
    },
    cookie: {
      sameSite: process.env.IAM_COOKIE_SAME_SITE,
      secure: process.env.IAM_COOKIE_SECURE,
    },
    jwt: {
      accessTokenTtl: process.env.IAM_JWT_ACCESS_TOKEN_TTL,
      audience: process.env.IAM_JWT_TOKEN_AUDIENCE,
      issuer: process.env.IAM_JWT_TOKEN_ISSUER,
      refreshTokenTtl: process.env.IAM_JWT_REFRESH_TOKEN_TTL,
      secret: process.env.IAM_JWT_SECRET,
    },
  };

  const validationResult = Joi.object({
    auth: Joi.object({
      methods: Joi.array()
        .items(Joi.string().valid('basic', 'passwordless'))
        .min(1)
        .required()
        .messages({
          '*': 'Environment variable IAM_AUTH_METHODS is required (e.g. basic,passwordless (comma separated))',
        }),
      passwordless: Joi.any().when('methods', {
        is: Joi.array().items().has('passwordless'),
        then: Joi.object({
          tokenTtl: Joi.number().positive().required().messages({
            '*': 'Environment variable IAM_AUTH_PASSWORDLESS_TOKEN_TTL is required (e.g. 300 for 5 minutes)',
          }),
        }),
      }),
    }),
    cookie: Joi.object({
      sameSite: Joi.valid('lax', 'strict', 'none').required().messages({
        '*': 'Environment variable IAM_COOKIE_SAME_SITE is required (lax, strict or none)',
      }),
      secure: Joi.valid('1', '0').required().messages({
        '*': 'Environment variable IAM_COOKIE_SECURE is required (1 or 0)',
      }),
    }),
    jwt: Joi.object({
      accessTokenTtl: Joi.number().positive().required().messages({
        '*': 'Environment variable IAM_JWT_ACCESS_TOKEN_TTL is required (e.g. 3600 for 1 hour)',
      }),
      audience: Joi.string().required().messages({
        '*': 'Environment variable IAM_JWT_TOKEN_AUDIENCE is required (e.g. localhost)',
      }),
      issuer: Joi.string().required().messages({
        '*': 'Environment variable IAM_JWT_TOKEN_ISSUER is required (e.g. localhost)',
      }),
      refreshTokenTtl: Joi.number().positive().required().messages({
        '*': 'Environment variable IAM_JWT_REFRESH_TOKEN_TTL is required (e.g. 86400 for 1 day)',
      }),
      secret: Joi.string().required().messages({
        '*': 'Environment variable IAM_JWT_SECRET is required (e.g. superSecretString)',
      }),
    }),
    routePathPrefix: Joi.string().allow('').optional().messages({
      '*': 'Environment variable IAM_ROUTE_PATH_PREFIX must be a string (e.g. /api)',
    }),
  }).validate(config, { abortEarly: false });

  if (validationResult.error) {
    throw validationResult.error;
  }

  return {
    ...config,
    auth: {
      ...config.auth,
      passwordless: {
        ...config.auth.passwordless,
        tokenTtl: config.auth.passwordless.tokenTtl
          ? parseInt(config.auth.passwordless.tokenTtl, 10)
          : undefined,
      },
    },
    jwt: {
      ...config.jwt,
      accessTokenTtl: parseInt(config.jwt.accessTokenTtl, 10),
      refreshTokenTtl: parseInt(config.jwt.refreshTokenTtl, 10),
    },
    cookie: {
      sameSite: config.cookie.sameSite as 'lax' | 'strict' | 'none',
      secure: config.cookie.secure === '1',
    },
  };
});

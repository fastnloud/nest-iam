import { registerAs } from '@nestjs/config';
import * as Joi from 'joi';

export default registerAs('iam', () => {
  const config = {
    cookie: {
      httpOnly: process.env.IAM_COOKIE_HTTP_ONLY,
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
    cookie: Joi.object({
      httpOnly: Joi.valid('1', '0').required().messages({
        '*': 'Environment variable IAM_COOKIE_HTTP_ONLY is required (1 or 0)',
      }),
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
  }).validate(config, { abortEarly: false });

  if (validationResult.error) {
    throw validationResult.error;
  }

  return {
    jwt: {
      ...config.jwt,
      accessTokenTtl: parseInt(config.jwt.accessTokenTtl, 10),
      refreshTokenTtl: parseInt(config.jwt.refreshTokenTtl, 10),
    },
    cookie: {
      httpOnly: config.cookie.httpOnly === '1',
      sameSite: config.cookie.sameSite as 'lax' | 'strict' | 'none',
      secure: config.cookie.secure === '1',
    },
  };
});

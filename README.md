## Description

Identity access management module for Nest that provides a simple customizable authentication service interface.

## Installation

```bash
$ npm i --save @fastnloud/nest-iam
```

## Setup

Create an `AuthService` that implements the `IAuthService` interface:

```ts
import { IAuthService, IToken, IUser } from '@fastnloud/nest-iam';
import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService implements IAuthService {
  public async getValidTokenOrFail(id: string, type: string): Promise<IToken> {}
  public async getValidUserOrFail(username: string): Promise<IUser> {}
  public async getUserOrFail(id: string): Promise<IUser> {}
  public async removeToken(id: string): Promise<void> {}
  public async saveToken(userId: string, token: IToken): Promise<void> {}
}
```

Import module:

```ts
import { IAuthService, IamModule } from '@fastnloud/nest-iam';
import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';
import { AuthService } from './services/auth.service';

@Module({
  imports: [
    CqrsModule,
    IamModule.registerAsync({
      imports: [UserModule],
      useFactory: (authService: IAuthService) => {
        return {
          authService,
        };
      },
      inject: [AuthService],
    }),
  ],
  exports: [AuthService],
})
export class UserModule {}
```

A sample `.env` file looks something like this:

```
IAM_AUTH_METHODS=basic,passwordless
IAM_AUTH_PASSWORDLESS_TOKEN_TTL=300
IAM_COOKIE_HTTP_ONLY=1
IAM_COOKIE_SAME_SITE=lax
IAM_COOKIE_SECURE=0
IAM_JWT_ACCESS_TOKEN_TTL=3600
IAM_JWT_REFRESH_TOKEN_TTL=86400
IAM_JWT_SECRET=superSecretString
IAM_JWT_TOKEN_AUDIENCE=localhost
IAM_JWT_TOKEN_ISSUER=localhost
IAM_ROUTE_PATH_PREFIX=/api
```

## Usage

All routes will be set to private by default. Use the `Auth` decorator provided by this module to change the `AuthType` of specific routes.

For example:

```ts
import { Auth, AuthType } from '@fastnloud/nest-iam';
import { Controller } from '@nestjs/common';

@Controller('/public')
@Auth(AuthType.None)
export class MyController {}
```

Roles (if implemented) can be applied similarly by using the `Roles` decorator:

```ts
import { Roles } from '@fastnloud/nest-iam';
import { Controller } from '@nestjs/common';

@Controller('/admin')
@Roles('admin', 'guest')
export class MyController {}
```

To login, logout or to refresh tokens use these endpoints:

```js
fetch(
  new Request('http://localhost:3000/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
    headers: new Headers({ 'Content-Type': 'application/json' }),
    credentials: 'include',
    mode: 'cors',
  }),
);
```

```js
fetch(
  new Request('http://localhost:3000/auth/logout', {
    method: 'GET',
    credentials: 'include',
    mode: 'cors',
  }),
);
```

```js
fetch(
  new Request('http://localhost:3000/auth/refresh_tokens', {
    method: 'GET',
    credentials: 'include',
    mode: 'cors',
  }),
);
```

The `login` and `refresh_tokens` endpoints will return an access token (JWT) in the response. The logout endpoint will return a 204 (No Content) given that no errors are thrown.

A decoded JWT payload may look something like this:

```json
{
  "sub": "1",
  "username": "john.doe@example.com",
  "roles": ["guest"],
  "iat": 1681660389,
  "exp": 1681663989,
  "aud": "localhost",
  "iss": "localhost"
}
```

Run `npx hash-password` to hash passwords via the CLI.

## License

nest-iam is [MIT licensed](LICENSE).

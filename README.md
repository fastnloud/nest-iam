## Description

Identity access management module for Nest that provides a customizable
authentication service interface supporting multiple authentication methods and
role-based access control.

The goal of this module is to provide a simple interface that can be used to
implement authentication and authorization in your application. It is not meant
to be a full-fledged identity access management solution. It does not provide
any user management functionality for example but instead relies on your own
implementation.

## Installation

```bash
$ npm i --save @fastnloud/nest-iam
```

## Setup

Create a service that implements the `IAuthService` interface in your project:

```ts
import { IAuthService, IToken, IUser } from '@fastnloud/nest-iam';
import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService implements IAuthService {
  public async findOneUserOrFail(id: string): Promise<IUser> {}
  public async findOneValidTokenOrFail(
    id: string,
    type: string,
  ): Promise<IToken> {}
  public async findOneValidUserOrFail(username: string): Promise<IUser> {}
  public async removeTokenOrFail(id: string): Promise<void> {}
  public async saveTokenOrFail(userId: string, token: IToken): Promise<void> {}
}
```

Import the `IamModule` and register it in your `AppModule`:

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

## Configuration

Add the following environment variables to your `.env` file and change the
values to your needs:

```
IAM_AUTH_METHODS=basic,passwordless
IAM_AUTH_PASSWORDLESS_TOKEN_TTL=300
IAM_COOKIE_SAME_SITE=lax
IAM_COOKIE_SECURE=1
IAM_JWT_ACCESS_TOKEN_TTL=3600
IAM_JWT_REFRESH_TOKEN_TTL=86400
IAM_JWT_SECRET=superSecretString
IAM_JWT_TOKEN_AUDIENCE=localhost
IAM_JWT_TOKEN_ISSUER=localhost
IAM_ROUTE_PATH_PREFIX=
```

When in local development, you can set `IAM_COOKIE_SECURE` to `0` to disable the
secure flag on the cookie. This will allow you to use the cookie over HTTP
instead of HTTPS.

The `IAM_ROUTE_PATH_PREFIX` environment variable is optional and will be left
empty if not set. Whenver this module is served from another path this value
should be updated accordingly.

## Example

This is an example of a service that implements the `IAuthService` interface
using TypeORM:

```ts
import { IAuthService, IToken, IUser, TokenType } from '@fastnloud/nest-iam';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { MoreThan, Repository } from 'typeorm';
import { UserToken } from './entities/user-token.entity';
import { User } from './entities/user.entity';

/**
 * This example uses TypeORM to manage the entities but you can use any ORM or
 * database you like as long as the returned entites match the corresponding
 * interface.
 */
@Injectable()
export class AuthService implements IAuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserToken)
    private readonly userTokenRepository: Repository<UserToken>,
  ) {}

  /*
   * Find one token by id, type and requestId that is not expired.
   *
   * Note that the requestId is optional and will only be set if a token is
   * requested via the passwordless flow to ensure the token can only be used
   * by the same client that requested it.
   *
   * This method should throw an error if the token does not exist or is
   * expired.
   */
  public async findOneValidTokenOrFail(
    id: string,
    type: string,
    requestId?: string,
  ): Promise<IToken> {
    const token = await this.userTokenRepository.findOneOrFail({
      where: {
        id,
        type,
        requestId,
        expiresAt: MoreThan(new Date()),
      },
    });

    return token;
  }

  /*
   * Find one user by username (in this case email). Additional checks can be
   * added here. For example, you could check if the user is active or not or
   * if the user is not blocked.
   *
   * This method should throw an error if the user does not exist or fails any
   * additional checks.
   */
  public async findOneValidUserOrFail(username: string): Promise<IUser> {
    const user = await this.userRepository.findOneOrFail({
      where: {
        email: username,
      },
    });

    // additional checks here
    if (!user.isActive()) {
      throw new UnauthorizedException();
    }

    return user;
  }

  /*
   * Find one user by id.
   *
   * This method should throw an error if the user does not exist.
   */
  public async findOneUserOrFail(id: string): Promise<IUser> {
    const user = await this.userRepository.findOneOrFail({
      where: {
        id: +id,
      },
    });

    return user;
  }

  /*
   * Remove token by id. This method is called when a user logs out or when a
   * token is refreshed.
   *
   * This method should throw an error if the token cannot be removed.
   */
  public async removeTokenOrFail(id: string): Promise<void> {
    const token = await this.userTokenRepository.findOneOrFail({
      where: {
        id,
      },
    });

    await this.userTokenRepository.remove(token);
  }

  /*
   * Save a token. This method is called when a user logs in, when a token is
   * refreshed or when a token is requested via the passwordless flow.
   *
   * If the token was requested via the passwordless flow, this would be the
   * place to send an email (for example) with a link containing the token so
   * the user can actually login.
   *
   * Note that this method is not used to save access tokens. Access tokens are
   * stateless and therefor are not saved in the database. The TTL of access
   * tokens (and passwordless tokes) should be as short as possible (for
   * example 5 minutes) to limit the chance of a stolen token being used by
   * someone else.
   *
   * Refresh tokens on the other hand are saved in the database and are used to
   * refresh access tokens. The TTL of refresh tokens are usually much longer
   * (for example 1 day) to allow users to stay logged in for a longer period of
   * time.
   *
   * This method should throw an error if the token cannot be saved.
   */
  public async saveTokenOrFail(token: IToken): Promise<void> {
    await this.userTokenRepository.save({
      user: {
        id: +token.getUserId(),
      },
      id: token.getId(),
      requestId: token.getRequestId(),
      type: token.getType(),
      expiresAt: token.getExpiresAt(),
    });

    if (token.getType() === TokenType.Passwordless) {
      // send email with token here
    }
  }
}
```

## Usage

All routes will be set to private by default. Use the `Auth` decorator provided
by this module to change the `AuthType` of specific routes.

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
@Roles('admin', 'superAdmin')
export class MyController {}
```

## Basic authentication

To login, logout or to refresh tokens you can use these endpoints:

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

The `login` and `refresh_tokens` endpoints will return an access token (JWT) in
the response. The logout endpoint will return a 204 (No Content) given that no
errors are thrown.

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

Additionally an `activeUser` cookie will be set containing user information that
can be used on the client side.

Decoded cookie payload:

```json
{
  "id": "1",
  "username": "john.doe@example.com",
  "roles": ["guest"]
}
```

Run `npx hash-password` to hash passwords via the CLI. This can be useful when
you need to insert users into the database directly.

This module also provides a bycrypt hasher that can be used to hash passwords
programmatically.

## Passwordless authentication

In contrast to basic authentication, passwordless authentication does not
require a password. Instead, a token is sent to the user that can be used to
login. This token can be sent via email for example. This logic you must
implement yourself when the token is saved. This allows you full control over
how the token is sent to the user.

To request a token, use this endpoint:

```js
fetch(
  new Request('http://localhost:3000/auth/passwordless_login', {
    method: 'POST',
    body: JSON.stringify({ username }),
    headers: new Headers({ 'Content-Type': 'application/json' }),
    credentials: 'include',
    mode: 'cors',
  }),
);
```

Note that a cookie will be set that contains the `requestId` of the token that
was requested. This cookie is used to ensure the token can only be used by the
same client that requested it. This limits the chance of the token being
intercepted and used by someone else.

To login with the requested token, use this endpoint:

```js
fetch(
  new Request('http://localhost:3000/auth/passwordless_login/:token', {
    method: 'GET',
    credentials: 'include',
    mode: 'cors',
  }),
);
```

## License

nest-iam is [MIT licensed](LICENSE).

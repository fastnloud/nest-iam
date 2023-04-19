import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ApiOkResponse } from '@nestjs/swagger';
import { randomUUID } from 'crypto';
import iamConfig from '../configs/iam.config';
import {
  IAM_LOGIN_PATH,
  IAM_LOGOUT_PATH,
  IAM_REFRESH_TOKENS_PATH,
} from '../constants/iam.constants';
import { ActiveUser } from '../decorators/active-user.decorator';
import { Auth } from '../decorators/auth.decorator';
import { LoginDto } from '../dtos/login.dto';
import { AuthType } from '../enums/auth-type.enum';
import { TokenType } from '../enums/token-type.enum';
import { AccessTokenGenerator } from '../generators/access-token.generator';
import { RefreshTokenGenerator } from '../generators/refresh-token.generator';
import { BcryptHasher } from '../hashers/bcrypt.hasher';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IActiveUser } from '../interfaces/active-user.interface';
import { IModuleOptions } from '../interfaces/module-options.interface';
import { IRefreshTokenJwtPayload } from '../interfaces/refresh-token-jwt-payload.interface';
import { EventBus } from '@nestjs/cqrs';
import { LoggedInEvent } from '../events/logged-in.event';
import { LoggedOutEvent } from '../events/logged-out.event';
import { AccessTokenDto } from '../dtos/access-token.dto';

@Controller()
export class AuthController {
  constructor(
    private readonly eventBus: EventBus,
    private readonly hasher: BcryptHasher,
    private readonly accessTokenGenerator: AccessTokenGenerator,
    private readonly refreshTokenGenerator: RefreshTokenGenerator,
    private readonly jwtService: JwtService,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: AccessTokenDto })
  @Auth(AuthType.None)
  @Post(IAM_LOGIN_PATH)
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) response: any,
  ) {
    try {
      const user = await this.moduleOptions.authService.checkUser(
        loginDto.username,
      );

      if (!(await this.hasher.compare(loginDto.password, user.getPassword()))) {
        throw new UnauthorizedException();
      }

      const accessToken = await this.accessTokenGenerator.generate(user);
      const refreshToken = await this.refreshTokenGenerator.generate(
        randomUUID(),
        user,
      );

      await this.moduleOptions.authService.saveToken(user.getId(), {
        id: refreshToken.id,
        type: TokenType.RefreshToken,
        expiresAt: refreshToken.expiresAt,
      });

      response.cookie(TokenType.AccessToken, accessToken.jwt, {
        secure: this.config.cookie.secure,
        httpOnly: this.config.cookie.httpOnly,
        sameSite: this.config.cookie.sameSite,
        expires: accessToken.expiresAt,
      });

      response.cookie(TokenType.RefreshToken, refreshToken.jwt, {
        secure: this.config.cookie.secure,
        httpOnly: this.config.cookie.httpOnly,
        sameSite: this.config.cookie.sameSite,
        expires: refreshToken.expiresAt,
        path: IAM_REFRESH_TOKENS_PATH,
      });

      this.eventBus.publish(new LoggedInEvent(user.getId()));

      return new AccessTokenDto(accessToken.jwt);
    } catch {
      throw new UnauthorizedException();
    }
  }

  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: AccessTokenDto })
  @Auth(AuthType.None)
  @Get(IAM_REFRESH_TOKENS_PATH)
  async refreshTokens(
    @Req() request: any,
    @Res({ passthrough: true }) response: any,
  ) {
    try {
      const refreshTokenJwtPayload: IRefreshTokenJwtPayload =
        await this.jwtService.verifyAsync(
          request.cookies[TokenType.RefreshToken],
        );

      await this.moduleOptions.authService.checkToken(
        refreshTokenJwtPayload.id,
        TokenType.RefreshToken,
      );

      const user = await this.moduleOptions.authService.getUser(
        refreshTokenJwtPayload.sub,
      );

      await this.moduleOptions.authService.checkUser(user.getUsername());

      const newAccessToken = await this.accessTokenGenerator.generate(user);
      const newRefreshToken = await this.refreshTokenGenerator.generate(
        randomUUID(),
        user,
      );

      await this.moduleOptions.authService.removeToken(
        refreshTokenJwtPayload.id,
      );

      await this.moduleOptions.authService.saveToken(user.getId(), {
        id: newRefreshToken.id,
        type: TokenType.RefreshToken,
        expiresAt: newRefreshToken.expiresAt,
      });

      response.cookie(TokenType.AccessToken, newAccessToken.jwt, {
        secure: this.config.cookie.secure,
        httpOnly: this.config.cookie.httpOnly,
        sameSite: this.config.cookie.sameSite,
        expires: newAccessToken.expiresAt,
      });

      response.cookie(TokenType.RefreshToken, newRefreshToken.jwt, {
        secure: this.config.cookie.secure,
        httpOnly: this.config.cookie.httpOnly,
        sameSite: this.config.cookie.sameSite,
        expires: newRefreshToken.expiresAt,
        path: IAM_REFRESH_TOKENS_PATH,
      });

      return new AccessTokenDto(newAccessToken.jwt);
    } catch {
      throw new UnauthorizedException();
    }
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Auth(AuthType.None)
  @Get(IAM_LOGOUT_PATH)
  async logout(
    @ActiveUser() activeUser: IActiveUser,
    @Res({ passthrough: true }) response: any,
  ) {
    response.clearCookie(TokenType.AccessToken);

    if (!activeUser) {
      return;
    }

    await this.moduleOptions.authService.logout(activeUser.userId);

    this.eventBus.publish(new LoggedOutEvent(activeUser.userId));
  }
}

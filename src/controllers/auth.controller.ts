import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  NotFoundException,
  Param,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { EventBus } from '@nestjs/cqrs';
import { JwtService } from '@nestjs/jwt';
import {
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import iamConfig from '../configs/iam.config';
import { ActiveUser } from '../decorators/active-user.decorator';
import { Auth } from '../decorators/auth.decorator';
import { LoginRequestDto } from '../dtos/login-request.dto';
import { LoginResponseDto } from '../dtos/login-response.dto';
import { PasswordlessLoginRequestRequestDto } from '../dtos/passwordless-login-request-request.dto';
import { AuthType } from '../enums/auth-type.enum';
import { CookieName } from '../enums/cookie-name.enum';
import { TokenType } from '../enums/token-type.enum';
import { LoggedInEvent } from '../events/logged-in.event';
import { LoggedOutEvent } from '../events/logged-out.event';
import { BcryptHasher } from '../hashers/bcrypt.hasher';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IActiveUser } from '../interfaces/active-user.interface';
import { IModuleOptions } from '../interfaces/module-options.interface';
import { IRefreshTokenJwtPayload } from '../interfaces/refresh-token-jwt-payload.interface';
import { LoginProcessor } from '../processors/login.processor';
import { LogoutProcessor } from '../processors/logout.processor';
import { PasswordlessLoginRequestProcessor } from '../processors/passwordless-login-request.processor';

@Controller()
@ApiTags('Auth')
export class AuthController {
  constructor(
    private readonly eventBus: EventBus,
    private readonly hasher: BcryptHasher,
    private readonly loginProcessor: LoginProcessor,
    private readonly logoutProcessor: LogoutProcessor,
    private readonly passwordlessLoginRequestProcessor: PasswordlessLoginRequestProcessor,
    private readonly jwtService: JwtService,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  @HttpCode(HttpStatus.OK)
  @ApiOperation({ operationId: 'authLogin' })
  @ApiOkResponse({ type: LoginResponseDto })
  @Auth(AuthType.None)
  @Post('/auth/login')
  async login(
    @Body() dto: LoginRequestDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<LoginResponseDto> {
    if (!this.config.auth.methods.includes('basic')) {
      throw new NotFoundException();
    }

    try {
      const user = await this.moduleOptions.authService.findOneValidUserOrFail(
        dto.username,
        { request },
      );

      if (!(await this.hasher.compare(dto.password, user.getPassword()))) {
        throw new UnauthorizedException();
      }

      const login = await this.loginProcessor.process(user, request, response);

      this.eventBus.publish(new LoggedInEvent(user.getId(), { request }));

      return {
        accessToken: login.accessToken,
        refreshToken: login.refreshToken,
      };
    } catch {
      throw new UnauthorizedException();
    }
  }

  @HttpCode(HttpStatus.OK)
  @ApiOperation({ operationId: 'authPasswordlessLogin' })
  @ApiOkResponse({ type: LoginResponseDto })
  @Auth(AuthType.None)
  @Get('/auth/passwordless_login/:id')
  async passwordlessLogin(
    @Param('id') tokenId: string,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<LoginResponseDto> {
    if (!this.config.auth.methods.includes('passwordless')) {
      throw new NotFoundException();
    }

    if (!request.cookies[CookieName.PasswordlessLoginToken]) {
      throw new UnauthorizedException();
    }

    try {
      const token =
        await this.moduleOptions.authService.findOneValidTokenOrFail(
          tokenId,
          TokenType.PasswordlessLoginToken,
          { request },
        );
      const user = await this.moduleOptions.authService.findOneUserOrFail(
        token.getUserId(),
        { request },
      );

      await this.moduleOptions.authService.findOneValidUserOrFail(
        user.getUsername(),
        { request },
      );
      await this.moduleOptions.authService.removeTokenOrFail(tokenId, {
        request,
      });

      const login = await this.loginProcessor.process(user, request, response);

      this.eventBus.publish(new LoggedInEvent(user.getId(), { request }));

      return {
        accessToken: login.accessToken,
        refreshToken: login.refreshToken,
      };
    } catch {
      throw new UnauthorizedException();
    }
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ operationId: 'authPasswordlessLoginRequest' })
  @ApiNoContentResponse()
  @Auth(AuthType.None)
  @Post('/auth/passwordless_login')
  async passwordlessLoginRequest(
    @Body() dto: PasswordlessLoginRequestRequestDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void> {
    if (!this.config.auth.methods.includes('passwordless')) {
      throw new NotFoundException();
    }

    try {
      const user = await this.moduleOptions.authService.findOneValidUserOrFail(
        dto.username,
        { request },
      );

      await this.passwordlessLoginRequestProcessor.process(
        user,
        request,
        response,
      );
    } catch {
      throw new NotFoundException();
    }
  }

  @HttpCode(HttpStatus.OK)
  @ApiOperation({ operationId: 'authRefreshTokens' })
  @ApiOkResponse({ type: LoginResponseDto })
  @Auth(AuthType.None)
  @Get('/auth/refresh_tokens')
  async refreshTokens(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<LoginResponseDto> {
    try {
      const refreshTokenJwtPayload: IRefreshTokenJwtPayload =
        await this.jwtService.verifyAsync(
          request.cookies[CookieName.RefreshToken],
        );

      await this.moduleOptions.authService.findOneValidTokenOrFail(
        refreshTokenJwtPayload.id,
        TokenType.RefreshToken,
        { request },
      );

      const user = await this.moduleOptions.authService.findOneUserOrFail(
        refreshTokenJwtPayload.sub,
        { request },
      );

      await this.moduleOptions.authService.findOneValidUserOrFail(
        user.getUsername(),
        { request },
      );
      await this.moduleOptions.authService.removeTokenOrFail(
        refreshTokenJwtPayload.id,
        { request },
      );

      const login = await this.loginProcessor.process(user, request, response);

      return {
        accessToken: login.accessToken,
        refreshToken: login.refreshToken,
      };
    } catch {
      throw new UnauthorizedException();
    }
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ operationId: 'authLogout' })
  @ApiNoContentResponse()
  @Auth(AuthType.None)
  @Get('/auth/logout')
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
    @ActiveUser() activeUser: IActiveUser,
  ) {
    await this.logoutProcessor.process(request, response);

    if (!activeUser) {
      return;
    }

    this.eventBus.publish(new LoggedOutEvent(activeUser.userId, { request }));
  }
}

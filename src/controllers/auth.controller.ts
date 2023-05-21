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
import { JwtService } from '@nestjs/jwt';
import {
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { ActiveUser } from '../decorators/active-user.decorator';
import { Auth } from '../decorators/auth.decorator';
import { AuthType } from '../enums/auth-type.enum';
import { TokenType } from '../enums/token-type.enum';
import { BcryptHasher } from '../hashers/bcrypt.hasher';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IActiveUser } from '../interfaces/active-user.interface';
import { IModuleOptions } from '../interfaces/module-options.interface';
import { IRefreshTokenJwtPayload } from '../interfaces/refresh-token-jwt-payload.interface';
import { EventBus } from '@nestjs/cqrs';
import { LoggedInEvent } from '../events/logged-in.event';
import { LoggedOutEvent } from '../events/logged-out.event';
import { LoginResponseDto } from '../dtos/login-response.dto';
import { LoginProcessor } from '../processors/login.processor';
import { LoginRequestDto } from '../dtos/login-request.dto';
import { Request, Response } from 'express';
import iamConfig from '../configs/iam.config';
import { ConfigType } from '@nestjs/config';
import { LogoutProcessor } from 'src/processors/logout.processor';
import { PasswordlessLoginRequestRequestDto } from 'src/dtos/passwordless-login-request-request.dto';
import { PasswordlessLoginRequestProcessor } from 'src/processors/passwordless-login-request.processor';

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
    @Body() request: LoginRequestDto,
    @Res({ passthrough: true }) response: Response,
  ): Promise<LoginResponseDto> {
    if (!this.config.auth.methods.includes('basic')) {
      throw new NotFoundException();
    }

    try {
      const user = await this.moduleOptions.authService.checkUser(
        request.username,
      );

      if (!(await this.hasher.compare(request.password, user.getPassword()))) {
        throw new UnauthorizedException();
      }

      const login = await this.loginProcessor.process(user, response);

      this.eventBus.publish(new LoggedInEvent(user.getId()));

      return {
        accessToken: login.accessToken,
        refreshToken: login.refreshToken,
      };
    } catch {
      throw new UnauthorizedException();
    }
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ operationId: 'authPasswordlessLogin' })
  @ApiOkResponse({ type: LoginResponseDto })
  @Auth(AuthType.None)
  @Get('/auth/passwordless_login/:id')
  async passwordlessLogin(
    @Param('id') tokenId: string,
    @Res({ passthrough: true }) response: Response,
    @Req() request: Request,
  ): Promise<LoginResponseDto> {
    if (!this.config.auth.methods.includes('passwordless')) {
      throw new NotFoundException();
    }

    try {
      const token = await this.moduleOptions.authService.checkToken(
        tokenId,
        TokenType.PasswordlessLoginToken,
        request.cookies[TokenType.PasswordlessLoginToken],
      );
      const user = await this.moduleOptions.authService.getUser(
        token.getUserId(),
      );

      await this.moduleOptions.authService.checkUser(user.getUsername());
      await this.moduleOptions.authService.removeToken(tokenId);

      const login = await this.loginProcessor.process(user, response);

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
    @Body() request: PasswordlessLoginRequestRequestDto,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void> {
    if (!this.config.auth.methods.includes('passwordless')) {
      throw new NotFoundException();
    }

    try {
      const user = await this.moduleOptions.authService.checkUser(
        request.username,
      );

      await this.passwordlessLoginRequestProcessor.process(user, response);
    } catch {}
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
      await this.moduleOptions.authService.removeToken(
        refreshTokenJwtPayload.id,
      );

      const login = await this.loginProcessor.process(user, response);

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
  @Auth(AuthType.None)
  @Get('/auth/logout')
  async logout(
    @Req() request: Request,
    @ActiveUser() activeUser: IActiveUser,
    @Res({ passthrough: true }) response: Response,
  ) {
    this.logoutProcessor.process(request, response);

    if (!activeUser) {
      return;
    }

    this.eventBus.publish(new LoggedOutEvent(activeUser.userId));
  }
}

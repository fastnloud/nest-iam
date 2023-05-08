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
import iamConfig from '../configs/iam.config';
import {
  IAM_LOGIN_PATH,
  IAM_LOGOUT_PATH,
  IAM_REFRESH_TOKENS_PATH,
} from '../constants/iam.constants';
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

@Controller()
export class AuthController {
  constructor(
    private readonly eventBus: EventBus,
    private readonly hasher: BcryptHasher,
    private readonly loginProcessor: LoginProcessor,
    private readonly jwtService: JwtService,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: LoginResponseDto })
  @Auth(AuthType.None)
  @Post(IAM_LOGIN_PATH)
  async login(
    @Body() request: LoginRequestDto,
    @Res({ passthrough: true }) response: any,
  ): Promise<LoginResponseDto> {
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

  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({ type: LoginResponseDto })
  @Auth(AuthType.None)
  @Get(IAM_REFRESH_TOKENS_PATH)
  async refreshTokens(
    @Req() request: any,
    @Res({ passthrough: true }) response: any,
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
  @Auth(AuthType.None)
  @Get(IAM_LOGOUT_PATH)
  async logout(
    @Req() request: any,
    @ActiveUser() activeUser: IActiveUser,
    @Res({ passthrough: true }) response: any,
  ) {
    response.clearCookie(TokenType.AccessToken);

    if (!activeUser) {
      return;
    }

    this.eventBus.publish(new LoggedOutEvent(activeUser.userId));
  }
}

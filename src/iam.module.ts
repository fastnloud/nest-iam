import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { CqrsModule } from '@nestjs/cqrs';
import { JwtModule } from '@nestjs/jwt';
import iamConfig from './configs/iam.config';
import { AuthController } from './controllers/auth.controller';
import { AccessTokenGenerator } from './generators/access-token.generator';
import { RefreshTokenGenerator } from './generators/refresh-token.generator';
import { AccessTokenGuard } from './guards/access-token.guard';
import { AuthGuard } from './guards/auth.guard';
import { NoneGuard } from './guards/none.guard';
import { RolesGuard } from './guards/roles.guard';
import { BcryptHasher } from './hashers/bcrypt.hasher';
import { ConfigurableModuleClass } from './iam.module-definition';
import { LoginProcessor } from './processors/login.processor';
import { LogoutProcessor } from './processors/logout.processor';

@Module({
  imports: [
    ConfigModule.forFeature(iamConfig),
    CqrsModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        secret: config.get('iam.jwt.secret'),
        signOptions: {
          audience: config.get('iam.jwt.audience'),
          issuer: config.get('iam.jwt.issuer'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    AccessTokenGenerator,
    AccessTokenGuard,
    AuthGuard,
    BcryptHasher,
    LoginProcessor,
    LogoutProcessor,
    NoneGuard,
    RefreshTokenGenerator,
    RolesGuard,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
  exports: [BcryptHasher, LoginProcessor],
  controllers: [AuthController],
})
export class IamModule extends ConfigurableModuleClass {}

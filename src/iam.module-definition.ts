import { ConfigurableModuleBuilder } from '@nestjs/common';
import { IModuleOptions } from './interfaces/module-options.interface';

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } =
  new ConfigurableModuleBuilder<IModuleOptions>()
    .setClassMethodName('register')
    .build();

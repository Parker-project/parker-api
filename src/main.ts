import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from 'cookie-parser';
import { WinstonModule } from 'nest-winston';
import 'dotenv/config';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';  

import { AppModule } from './app.module';
import { winstonLoggerConfig } from './common/logger/logger';


async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonLoggerConfig)
  });
  app.setGlobalPrefix('api');

  const configService = app.get(ConfigService);
  const config = new DocumentBuilder()
    .setTitle('Parker API')
    .setVersion('1.0')
    .addTag('Categories')
    .addCookieAuth('access_token')
    .build();
  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, documentFactory);
  app.use(cookieParser());
  await app.listen(configService.get('PORT') || 3000);
}
bootstrap();

import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from 'cookie-parser';
import { WinstonModule } from 'nest-winston';
import 'dotenv/config';

import { AppModule } from './app.module';
import { winstonLoggerConfig } from './common/logger/logger';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';


async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonLoggerConfig),
  });
  app.setGlobalPrefix('api');
  app.useGlobalFilters(new AllExceptionsFilter());
  
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

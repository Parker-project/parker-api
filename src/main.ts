import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from 'cookie-parser';
import { WinstonModule } from 'nest-winston';
import 'dotenv/config';
import { ValidationPipe } from '@nestjs/common';

import { AppModule } from './app.module';
import { winstonLoggerConfig } from './common/logger/logger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonLoggerConfig)
  });
  app.setGlobalPrefix('api');

  app.enableCors({
    origin: ['http://localhost:5174', 'http://localhost:5173'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  });

  app.useGlobalPipes(new ValidationPipe());

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

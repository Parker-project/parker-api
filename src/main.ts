import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from 'cookie-parser';
import * as session from 'express-session';
import { WinstonModule } from 'nest-winston';
import 'dotenv/config';
import { ValidationPipe } from '@nestjs/common';
import * as passport from 'passport';

import { AppModule } from './app.module';
import { winstonLoggerConfig } from './common/logger/logger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonLoggerConfig)
  });
  app.setGlobalPrefix('api');

  const configService = app.get(ConfigService);

  app.enableCors({
    origin: [configService.getOrThrow<string>('FRONTEND_URL'), 'http://localhost:5174', 'http://localhost:5173'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    exposedHeaders: ['Set-Cookie'],
  });

  app.useGlobalPipes(new ValidationPipe());


  // Add session middleware
  app.use(
    session({
      secret: configService.getOrThrow<string>('SESSION_SECRET'),
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      },
    }),
  );

  // Initialize Passport and restore authentication state from session
  app.use(passport.initialize());
  app.use(passport.session());

  // Configure Passport session serialization
  passport.serializeUser((user: any, done) => {
    done(null, user);
  });

  passport.deserializeUser((user: any, done) => {
    done(null, user);
  });

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

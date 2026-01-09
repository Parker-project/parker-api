import { NestFactory } from '@nestjs/core';
import { ReportsModule } from './reports.module';
import { ValidationPipe } from '@nestjs/common';
import { WinstonModule } from 'nest-winston';
import { winstonLoggerConfig } from 'libs/common/logger/logger';

async function bootstrap() {
  const app = await NestFactory.create(ReportsModule, {
    logger: WinstonModule.createLogger(winstonLoggerConfig),
  });  app.useGlobalPipes(new ValidationPipe({ transform: true }));
  app.setGlobalPrefix('api/reports');
  await app.listen(3002);
  console.log('Report Service is running on port 3002');
}
bootstrap();

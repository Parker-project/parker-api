import { Module } from '@nestjs/common';
import { WinstonModule } from 'nest-winston';
import { winstonLoggerConfig } from './logger';

@Module({
  imports: [
    WinstonModule.forRoot(winstonLoggerConfig),
  ],
  exports: [WinstonModule], 
})
export class LoggerModule {}
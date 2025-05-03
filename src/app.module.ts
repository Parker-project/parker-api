import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { LoggerModule } from './common/logger/logger.module';
import { ReportsModule } from './reports/reports.module';
import { ReportsclearnestService } from './g/reportsclearnest/reportsclearnest.service';

@Module({
  imports: [AuthModule, UserModule, MongooseModule.forRoot(process.env.MONGO_URI || 'mongodb://localhost:27017/parker'), LoggerModule, ReportsModule,
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    ReportsModule
  ],
  controllers: [AppController],
  providers: [AppService, ReportsclearnestService],
})
export class AppModule { }

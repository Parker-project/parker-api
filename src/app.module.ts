import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { ReportsModule } from 'apps/report-service/src/reports.module';
import { OcrModule } from './ocr/ocr.module';

@Module({
  imports: [AuthModule, UserModule, MongooseModule.forRoot(process.env.MONGO_URI || 'mongodb://localhost:27017/parker'), ReportsModule,
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    ReportsModule,
    OcrModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }

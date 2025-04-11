import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';

@Module({
imports: [AuthModule, UserModule, MongooseModule.forRoot(process.env.MONGO_URI || 'mongodb://localhost:27017/parker'),
  ConfigModule.forRoot({
    isGlobal: true, 
    envFilePath: '.env', 
  }) 
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

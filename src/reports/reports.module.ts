import { MongooseModule } from '@nestjs/mongoose';
import { Module } from '@nestjs/common';
import { WinstonModule } from 'nest-winston';

import { Report, ReportSchema } from './report.schema';
import { ReportsService } from './reports.service';
import { ReportsController } from './reports.controller';
import { User, UserSchema } from '../user/user.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Report.name, schema: ReportSchema },
      { name: User.name, schema: UserSchema }
    ]),
  ],
  controllers: [ReportsController],
  providers: [ReportsService],
})
export class ReportsModule { }

import { MongooseModule } from '@nestjs/mongoose';
import { Module } from '@nestjs/common';
import { WinstonModule } from 'nest-winston';

import { Report, ReportSchema } from './report.schema';
import { ReportsService } from './reports.service';
import { ReportsController } from './reports.controller';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Report.name, schema: ReportSchema }]), //WinstonModule
  ],
  controllers: [ReportsController],
  providers: [ReportsService],
})
export class ReportsModule {}

import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ReportsController } from './reports.controller';
import { ReportsService } from './reports.service';
import { Report, ReportSchema } from './report.schema';

@Module({
  imports: [
    MongooseModule.forRoot(process.env.MONGO_URI || 'mongodb://localhost:27017/reports'),
    MongooseModule.forFeature([{ name: Report.name, schema: ReportSchema }])
  ],
  controllers: [ReportsController],
  providers: [ReportsService],
})
export class ReportsModule {}

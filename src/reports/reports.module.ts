import { MongooseModule } from '@nestjs/mongoose';
import { Module } from '@nestjs/common';
import * as fs from 'fs';
import { Report, ReportSchema } from './report.schema';
import { ReportsService } from './reports.service';
import { ReportsController } from './reports.controller';
import { MulterModule } from '@nestjs/platform-express';
import { User, UserSchema } from '../user/user.schema';

// Ensure uploads directory exists
const uploadsDir = './uploads';
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Report.name, schema: ReportSchema },
      { name: User.name, schema: UserSchema },
    ]),
    MulterModule.register({
      dest: './uploads',
    }),
  ],
  controllers: [ReportsController],
  providers: [ReportsService],
  exports: [ReportsService],
})
export class ReportsModule {}

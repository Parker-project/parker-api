import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Report } from './report.schema';
import { CreateReportDto } from './dto/create-report.dto';

@Injectable()
export class ReportsService {
  constructor(@InjectModel(Report.name) private reportModel: Model<Report>) {}

  async createReport(createReportDto:CreateReportDto,userId: string) {
    return this.reportModel.create({ userId });
  }

  async getReportsByUserId(userId: string) {
    return this.reportModel.find({ userId }).exec();
  }

  async getAllReports() {
    return this.reportModel.find().exec();
  }

  async updateReportStatus(reportId: string, status: string) {
    return this.reportModel.findByIdAndUpdate(reportId, { status }, { new: true }).exec();
  }
}

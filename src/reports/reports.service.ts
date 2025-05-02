import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { Inject } from '@nestjs/common';

import { Report } from './report.schema';
import { CreateReportDto } from './dto/create-report.dto';
@Injectable()
export class ReportsService {
  constructor(
    @InjectModel(Report.name) private reportModel: Model<Report>,
    @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger,
  ) {}

  async createReport(createReportDto: CreateReportDto, userId: string) {
    try {
      this.logger.log(`Creating report for user ${userId}`);
      const report = await this.reportModel.create({ ...createReportDto, userId });
      this.logger.debug(`Created report with id: ${report._id}`);
      return report;
    } catch (error) {
      this.logger.error(`Failed to create report: ${error.message}`);
      throw new InternalServerErrorException('Failed to create report');
    }
  }

  async getReportsByUserId(userId: string) {
    try {
      this.logger.log(`Fetching reports for user ${userId}`);
      const reports = await this.reportModel.find({ userId }).exec();
      this.logger.debug(`Found ${reports.length} reports for user ${userId}`);
      return reports;
    } catch (error) {
      this.logger.error(`Failed to fetch reports: ${error.message}`);
      throw new InternalServerErrorException('Failed to fetch user reports');
    }
  }

  async getAllReports() {
    try {
      this.logger.log(`Fetching all reports`);
      const reports = await this.reportModel.find().exec();
      this.logger.debug(`Found ${reports.length} total reports`);
      return reports;
    } catch (error) {
      this.logger.error(`Failed to fetch all reports: ${error.message}`);
      throw new InternalServerErrorException('Failed to fetch all reports');
    }
  }

  async updateReportStatus(reportId: string, status: string) {
    try {
      this.logger.log(`Updating status of report ${reportId} to ${status}`);
      const updatedReport = await this.reportModel.findByIdAndUpdate(
        reportId,
        { status },
        { new: true },
      ).exec();

      if (updatedReport) {
        this.logger.debug(`Updated report ${reportId} successfully`);
      } else {
        this.logger.warn(`Report ${reportId} not found for update`);
      }

      return updatedReport;
    } catch (error) {
      this.logger.error(`Failed to update report status: ${error.message}`);
      throw new InternalServerErrorException('Failed to update report status');
    }
  }
}

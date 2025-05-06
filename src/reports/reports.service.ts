import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { Inject } from '@nestjs/common';

import { Report } from './report.schema';
import { CreateReportDto } from './dto/create-report.dto';
@Injectable()
export class ReportsService {
  constructor(
    @InjectModel(Report.name) private reportModel: Model<Report>,
    @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger,
  ) { }

  async createReport(createReportDto: CreateReportDto, userId: string) {
    try {
      this.logger.log(`Creating report for ${userId ? userId : 'anonymous'}`);
      const report = await this.reportModel.create({ ...createReportDto, userId: userId ? new Types.ObjectId(userId) : undefined });
      this.logger.debug(`Created report with id: ${report._id}`);
      return report;
    } catch (error) {
      this.logger.error(`Failed to create report: ${error.message}`);
      throw new InternalServerErrorException('Failed to create report');
    }
  }

  async getReport(reportId: string) {
    try {
      this.logger.log(`Fetching report details for ${reportId}`);
      const report = await this.reportModel.findById(reportId);
      this.logger.debug(`Found report ${reportId}`);
      return report;
    } catch (error) {
      this.logger.error(`Failed to fetch report: ${error.message}`);
      throw new InternalServerErrorException('Failed to fetch report');
    }
  }

  async getAllReports(sort?: string) {
    try {
      this.logger.log(`Fetching all reports with sort: ${sort || 'none'}`);
      const query = this.reportModel.find();

      if (sort) {
        query.sort(sort);
      }

      const reports = await query.exec();
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

import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { Inject } from '@nestjs/common';

import { Report } from './report.schema';
import { CreateReportDto } from './dto/create-report.dto';
import { ReportStatus } from 'src/common/enums/report-state.enum';
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
  async getReportsByUserId(userId: string) {
    try {
      this.logger.log(`Fetching report details for ${userId}`);
      const objectId = new Types.ObjectId(userId)
      const reports = await this.reportModel.find({ userId: objectId });
      this.logger.log(`Found reports for user: ${userId}`);
      return reports || [];
    } catch (error) {
      this.logger.error(`Failed to fetch reports: ${error.message} for ${userId}`);
      throw new InternalServerErrorException('Failed to fetch reports');
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
      return reports || [];
    } catch (error) {
      this.logger.error(`Failed to fetch all reports: ${error.message}`);
      throw new InternalServerErrorException('Failed to fetch all reports');
    }
  }

  async updateReportStatus(reportId: string, status: ReportStatus) {
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

  async getReportsByStatus(status: ReportStatus) {
    try {
      this.logger.log(`Fetching reports with status: ${status}`);
      const reports = await this.reportModel.find({ status });
      this.logger.debug(`Found ${reports.length} reports with status ${status}`);
      return reports || [];
    } catch (error) {
      this.logger.error(`Failed to fetch reports by status: ${error.message}`);
      throw new InternalServerErrorException('Failed to fetch reports by status');
    }
  }

  async deleteReport(reportId: string) {
    try {
      this.logger.log(`Deleting report ${reportId}`);
      const deletedReport = await this.reportModel.findByIdAndDelete(reportId);

      if (deletedReport) {
        this.logger.debug(`Deleted report ${reportId} successfully`);
        return { message: 'Report deleted successfully' };
      } else {
        this.logger.warn(`Report ${reportId} not found for deletion`);
        return { message: 'Report not found' };
      }
    } catch (error) {
      this.logger.error(`Failed to delete report: ${error.message}`);
      throw new InternalServerErrorException('Failed to delete report');
    }
  }

  async getReportsByDate(sortOrder: 'asc' | 'desc' = 'desc') {
    try {
      this.logger.log(`Fetching reports sorted by date ${sortOrder}`);
      const sortDirection = sortOrder === 'asc' ? 1 : -1;
      const reports = await this.reportModel.find().sort({ createdAt: sortDirection });
      this.logger.debug(`Found ${reports.length} reports sorted by date`);
      return reports || [];
    } catch (error) {
      this.logger.error(`Failed to fetch reports by date: ${error.message}`);
      throw new InternalServerErrorException('Failed to fetch reports by date');
    }
  }
}

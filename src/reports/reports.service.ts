import { Injectable, InternalServerErrorException, Logger, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { Inject } from '@nestjs/common';
import * as fs from 'fs';
import { Report } from './report.schema';
import { CreateReportDto } from './dto/create-report.dto';
import { ReportStatus } from '../common/enums/report-state.enum';
import { AssignInspectorDto } from './dto/assign-inspector.dto';
import { User } from '../user/user.schema';
import { Role } from '../common/enums/role.enum';

@Injectable()
export class ReportsService {
  constructor(
    @InjectModel(Report.name) private reportModel: Model<Report>,
    @InjectModel(User.name) private userModel: Model<User>,
    @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger,
  ) { }

  private async getRandomInspector(): Promise<string | null> {
    try {
      const inspectors = await this.userModel.find({
        role: { $in: [Role.Inspector] }
      }).select('_id');

      if (inspectors.length === 0) {
        this.logger.warn('No inspectors found in the system');
        return null;
      }

      const randomIndex = Math.floor(Math.random() * inspectors.length);
      const randomInspector = inspectors[randomIndex];

      this.logger.debug(`Selected random inspector with ID: ${randomInspector._id}`);
      return randomInspector._id as string;
    } catch (error) {
      this.logger.error(`Failed to get random inspector: ${error.message}`);
      return null;
    }
  }

  async createReport(createReportDto: CreateReportDto, userId: string, filenames?: string[]) {
    try {
      this.logger.log(`Creating report for ${userId ? userId : 'anonymous'}`);

      const randomInspectorId = await this.getRandomInspector();

      const reportData = {
        ...createReportDto,
        userId: userId ? new Types.ObjectId(userId) : undefined,
        ...(filenames && { images: filenames }),
        inspectorId: randomInspectorId,
        status: randomInspectorId ? ReportStatus.REVIEWED : ReportStatus.PENDING
      };

      const report = await this.reportModel.create(reportData);

      if (randomInspectorId) {
        this.logger.debug(`Created report with id: ${report._id} and assigned random inspector: ${randomInspectorId}`);
      } else {
        this.logger.debug(`Created report with id: ${report._id} without inspector assignment`);
      }

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

  async assignInspector(reportId: string, assignInspectorDto: AssignInspectorDto) {
    try {
      this.logger.log(`Attempting to assign inspector ${assignInspectorDto.inspectorId} to report ${reportId}`);

      // First check if the inspector exists and has the correct role
      const inspector = await this.userModel.findOne({
        _id: new Types.ObjectId(assignInspectorDto.inspectorId),
        role: { $in: [Role.Inspector] }
      });

      if (!inspector) {
        this.logger.warn(`Inspector ${assignInspectorDto.inspectorId} not found or is not an inspector`);
        throw new NotFoundException('Inspector not found or is not an inspector');
      }

      const updatedReport = await this.reportModel.findByIdAndUpdate(
        reportId,
        {
          inspectorId: new Types.ObjectId(assignInspectorDto.inspectorId),
          status: ReportStatus.REVIEWED
        },
        { new: true }
      ).exec();

      if (!updatedReport) {
        this.logger.warn(`Report ${reportId} not found for inspector assignment`);
        throw new NotFoundException('Report not found');
      }

      this.logger.debug(`Successfully assigned inspector ${assignInspectorDto.inspectorId} to report ${reportId}`);
      return updatedReport;
    } catch (error) {
      this.logger.error(`Failed to assign inspector: ${error.message}`);
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to assign inspector');
    }
  }

  async getReportsByInspectorId(inspectorId: string) {
    try {
      this.logger.log(`Fetching reports for inspector ${inspectorId}`);
      const objectId = new Types.ObjectId(inspectorId);
      const reports = await this.reportModel.find({ inspectorId: objectId });
      this.logger.debug(`Found ${reports.length} reports for inspector ${inspectorId}`);
      return reports || [];
    } catch (error) {
      this.logger.error(`Failed to fetch reports for inspector: ${error.message}`);
      throw new InternalServerErrorException('Failed to fetch reports for inspector');
    }
  }

  async reassignInspectorReports(oldInspectorId: string) {
    try {
      this.logger.log(`Reassigning reports from inspector ${oldInspectorId}`);

      // Get all reports assigned to the old inspector
      const reports = await this.reportModel.find({
        inspectorId: new Types.ObjectId(oldInspectorId)
      });

      if (reports.length === 0) {
        this.logger.debug(`No reports found for inspector ${oldInspectorId}`);
        return;
      }

      // Get a random inspector (excluding the old inspector)
      const newInspectorId = await this.getRandomInspector();

      // Update all reports
      const updatePromises = reports.map(report =>
        this.reportModel.findByIdAndUpdate(
          report._id,
          {
            inspectorId: newInspectorId ? new Types.ObjectId(newInspectorId) : null,
            status: newInspectorId ? ReportStatus.REVIEWED : ReportStatus.PENDING
          },
          { new: true }
        )
      );

      await Promise.all(updatePromises);

      this.logger.debug(`Successfully reassigned ${reports.length} reports from inspector ${oldInspectorId} to ${newInspectorId || 'no inspector'}`);
    } catch (error) {
      this.logger.error(`Failed to reassign inspector reports: ${error.message}`);
      throw new InternalServerErrorException('Failed to reassign inspector reports');
    }
  }
  
  getImage(filePath: string) {
    return fs.readFileSync(filePath);
  }
}

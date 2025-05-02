import { Controller, Post, Body, Get, Param, Req, Patch } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiBody, ApiParam } from '@nestjs/swagger';

import { ReportsService } from './reports.service';
import { CreateReportDto } from './dto/create-report.dto';
import { Report } from './report.schema';
import { ReportStatus } from 'src/common/enums/report-status.enum';

@ApiTags('reports')
@Controller('reports')
export class ReportsController {
    constructor(private readonly reportsService: ReportsService) { }

    @Post()
    @ApiOperation({ summary: 'Create a new report (can be anonymous)' })
    @ApiResponse({ status: 201, description: 'Report created successfully', type: Report })
    @ApiResponse({ status: 400, description: 'Invalid input' })
    async createReport(@Body() createReportDto: CreateReportDto, @Req() req) {
        const user = req.user || null;
        return this.reportsService.createReport(createReportDto, user.id);
    }

    @Get(':id')
    @ApiOperation({ summary: 'Get a report by ID' })
    @ApiResponse({ status: 200, description: 'Report found', type: Report })
    @ApiResponse({ status: 404, description: 'Report not found' })
    async getReport(@Param('id') userId: string) {
        return this.reportsService.getReportsByUserId(userId);
    }

    @Get()
    @ApiOperation({ summary: 'Get all reports' })
    @ApiResponse({ status: 200, description: 'List of all reports', type: [Report] })
    getAll() {
        return this.reportsService.getAllReports();
    }

    @Patch(':id/status')
    @ApiOperation({ summary: 'Update the status of a report' })
    @ApiParam({ name: 'id', description: 'ID of the report to update' })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                status: {
                    type: 'string',
                    enum: Object.values(ReportStatus),
                    description: 'New status for the report',
                },
            },
            required: ['status'],
        },
    })
    @ApiResponse({ status: 200, description: 'Report status updated', type: Report })
    @ApiResponse({ status: 404, description: 'Report not found' })
    updateStatus(@Param('id') id: string, @Body() body: { status: ReportStatus }) {
        return this.reportsService.updateReportStatus(id, body.status);
    }
}

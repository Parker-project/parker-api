import { Controller, Post, Body, Get, Param, Req, Patch, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiBody, ApiParam } from '@nestjs/swagger';

import { ReportsService } from './reports.service';
import { CreateReportDto } from './dto/create-report.dto';
import { Report } from './report.schema';
import { ReportStatus } from 'src/common/enums/report-status.enum';
import { Request } from 'express';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UpdateReportStatusDto } from './dto/update-report-status.dto';

@ApiTags('reports')
@Controller('reports')
export class ReportsController {
    constructor(private readonly reportsService: ReportsService) { }

    @Post()
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Create a new report (can be anonymous)' })
    @ApiResponse({ status: 201, description: 'Report created successfully', type: Report })
    @ApiResponse({ status: 400, description: 'Invalid input' })
    async createReport(@Body() createReportDto: CreateReportDto, @Req() req: any) {
        const userId = req.user?.id
        return this.reportsService.createReport(createReportDto, userId);
    }

    @Get(':id')
    @ApiOperation({ summary: 'Get a report by user ID' })
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


    @ApiResponse({ status: 200, description: 'Report status updated', type: Report })
    @ApiResponse({ status: 404, description: 'Report not found' })
    @Patch(':id/status')
    updateStatus(
        @Param('id') id: string,
        @Body() updateReportStatusDto: UpdateReportStatusDto,
    ) {
        return this.reportsService.updateReportStatus(id, updateReportStatusDto.status);
    }
}

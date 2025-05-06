import { Controller, Post, Body, Get, Param, Req, Patch, UseGuards, Query } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiBody, ApiParam, ApiQuery } from '@nestjs/swagger';

import { ReportsService } from './reports.service';
import { CreateReportDto } from './dto/create-report.dto';
import { Report } from './report.schema';
import { ReportStatus } from 'src/common/enums/report-state.enum';
import { Request } from 'express';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UpdateReportStatusDto } from './dto/update-report-status.dto';
import { RolesGuard } from 'src/auth/guards/role.guard';
import { Roles } from 'src/common/decorators/role.decorator';
import { Role } from 'src/common/enums/role.enum';

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
    @ApiOperation({ summary: 'Returns details for a single report' })
    @ApiResponse({ status: 200, description: 'Report found', type: Report })
    @ApiResponse({ status: 404, description: 'Report not found' })
    async getReport(@Param('id') reportId: string) {
        return this.reportsService.getReport(reportId);
    }

    @Get()
    @ApiOperation({ summary: 'Get all reports' })
    @ApiQuery({ name: 'sort', required: false, description: 'Sort by field, e.g., "createdAt" or "-createdAt"' })
    @ApiResponse({ status: 200, description: 'List of all reports', type: [Report] })
    findAll(@Query('sort') sort?: string) {
        return this.reportsService.getAllReports(sort);
    }

    @UseGuards(RolesGuard)
    @Roles(Role.Admin, Role.Inspector, Role.SuperInspector)
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

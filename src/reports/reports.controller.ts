import { Controller, Post, Body, Get, Param, Req, Patch, UseGuards, Query, Delete } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiParam, ApiQuery } from '@nestjs/swagger';

import { ReportsService } from './reports.service';
import { CreateReportDto } from './dto/create-report.dto';
import { Report } from './report.schema';
import { ReportStatus } from 'src/common/enums/report-state.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UpdateReportStatusDto } from './dto/update-report-status.dto';
import { RolesGuard } from 'src/auth/guards/role.guard';
import { Roles } from 'src/common/decorators/role.decorator';
import { Role } from 'src/common/enums/role.enum';

@ApiTags('reports')
@Controller('reports')
@UseGuards(JwtAuthGuard)
export class ReportsController {
    constructor(private readonly reportsService: ReportsService) { }

    @Post()
    @ApiOperation({ summary: 'Create a new report (can be anonymous)' })
    @ApiResponse({ status: 201, description: 'Report created successfully', type: Report })
    @ApiResponse({ status: 400, description: 'Invalid input' })
    async createReport(@Body() createReportDto: CreateReportDto, @Req() req: any) {
        const userId = req.user?.id
        return this.reportsService.createReport(createReportDto, userId);
    }

    @Get(':id')
    @UseGuards(RolesGuard)
    @Roles(Role.Admin, Role.Inspector, Role.SuperInspector)
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Returns user reports' })
    @ApiResponse({ status: 200, description: 'Reports found', type: Report })
    @ApiResponse({ status: 404, description: 'Reports was not found' })
    async getReportByUserId(@Param('id') reportId: string) {
        return this.reportsService.getReportsByUserId(reportId);
    }

    @Get()
    @UseGuards(RolesGuard)
    @Roles(Role.Admin, Role.Inspector, Role.SuperInspector)
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Get all reports' })
    @ApiQuery({ name: 'sort', required: false, description: 'Sort by field, e.g., "createdAt" or "-createdAt"' })
    @ApiResponse({ status: 200, description: 'List of all reports', type: [Report] })
    findAll(@Query('sort') sort?: string) {
        return this.reportsService.getAllReports(sort);
    }

    @UseGuards(RolesGuard)
    @Roles(Role.Admin, Role.Inspector, Role.SuperInspector)
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Update the status of a report' })
    @ApiResponse({ status: 200, description: 'Report status updated', type: Report })
    @ApiResponse({ status: 404, description: 'Report not found' })
    @Patch(':id/status')
    updateStatus(
        @Param('id') id: string,
        @Body() updateReportStatusDto: UpdateReportStatusDto,
    ) {
        return this.reportsService.updateReportStatus(id, updateReportStatusDto.status);
    }

    @Get('status/:status')
    @UseGuards(RolesGuard)
    @Roles(Role.Admin, Role.Inspector, Role.SuperInspector)
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Get reports by status' })
    @ApiParam({ name: 'status', enum: ReportStatus, description: 'Status of the reports to fetch' })
    @ApiResponse({ status: 200, description: 'List of reports with specified status' })
    getReportsByStatus(@Param('status') status: ReportStatus) {
        return this.reportsService.getReportsByStatus(status);
    }

    @Delete(':id')
    @UseGuards(RolesGuard)
    @Roles(Role.Admin, Role.SuperInspector)
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Delete a report' })
    @ApiParam({ name: 'id', description: 'Report ID to delete' })
    @ApiResponse({ status: 200, description: 'Report deleted successfully' })
    @ApiResponse({ status: 404, description: 'Report not found' })
    deleteReport(@Param('id') id: string) {
        return this.reportsService.deleteReport(id);
    }

    @Get('sort/date')
    @UseGuards(RolesGuard)
    @Roles(Role.Inspector, Role.SuperInspector)
    @UseGuards(JwtAuthGuard)
    @ApiOperation({ summary: 'Get reports sorted by date' })
    @ApiQuery({ name: 'order', enum: ['asc', 'desc'], required: false, description: 'Sort order (asc/desc)' })
    @ApiResponse({ status: 200, description: 'List of reports sorted by date' })
    getReportsByDate(@Query('order') order: 'asc' | 'desc' = 'desc') {
        return this.reportsService.getReportsByDate(order);
    }
}

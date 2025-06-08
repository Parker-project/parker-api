import {
  Controller,
  Post,
  Body,
  Get,
  Param,
  Req,
  Patch,
  UseGuards,
  Query,
  Delete,
  UseInterceptors,
  Res,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { Inject, Logger } from '@nestjs/common';

import { ReportsService } from './reports.service';
import { CreateReportDto } from './dto/create-report.dto';
import { Report } from './report.schema';
import { ReportStatus } from 'src/common/enums/report-state.enum';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { UpdateReportStatusDto } from './dto/update-report-status.dto';
import { RolesGuard } from 'src/auth/guards/role.guard';
import { Roles } from 'src/common/decorators/role.decorator';
import { Role } from 'src/common/enums/role.enum';
import { AssignInspectorDto } from './dto/assign-inspector.dto';
import { diskStorage } from 'multer';
import { FilesInterceptor } from '@nestjs/platform-express';
import { v4 as uuidv4 } from 'uuid';
import { BadRequestException, UploadedFiles } from '@nestjs/common';
import { Response } from 'express';
import * as path from 'path';

@ApiTags('reports')
@Controller('reports')
// @UseGuards(JwtAuthGuard)
export class ReportsController {
  constructor(
    private readonly reportsService: ReportsService,
    @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger,
  ) {}

  @Post()
  @UseInterceptors(
    FilesInterceptor('images', 5, {
      storage: diskStorage({
        destination: './uploads',
        filename: (req, file, cb) => {
          // Create a unique filename with original extension
          const filename = `${uuidv4()}${path.extname(file.originalname)}`;
          cb(null, filename);
        },
      }),
      fileFilter: (req, file, cb) => {
        // Accept only image files
        if (!file.mimetype.match(/\/(jpg|jpeg|png)$/)) {
          return cb(
            new BadRequestException('Only image files are allowed!'),
            false,
          );
        }
        cb(null, true);
      },
      limits: {
        fileSize: 5 * 1024 * 1024, // 5MB max file size
      },
    }),
  )
  @ApiOperation({ summary: 'Create a new report (can be anonymous)' })
  @ApiResponse({
    status: 201,
    description: 'Report created successfully',
    type: Report,
  })
  @ApiResponse({ status: 400, description: 'Invalid input' })
  async createReport(
    @Body() createReportDto: Partial<CreateReportDto>,
    @Req() req: any,
    @UploadedFiles() files?: Express.Multer.File[],
  ) {
    const userId = req.user?.id;
    const filenames = files?.map((file) => file.filename);
    return this.reportsService.createReport(createReportDto, userId, filenames);
  }

  @Get(':id')
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
  @ApiQuery({
    name: 'sort',
    required: false,
    description: 'Sort by field, e.g., "createdAt" or "-createdAt"',
  })
  @ApiResponse({
    status: 200,
    description: 'List of all reports',
    type: [Report],
  })
  findAll(@Query('sort') sort?: string) {
    return this.reportsService.getAllReports(sort);
  }

  @UseGuards(RolesGuard)
  @Roles(Role.Admin, Role.Inspector, Role.SuperInspector)
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Update the status of a report' })
  @ApiResponse({
    status: 200,
    description: 'Report status updated',
    type: Report,
  })
  @ApiResponse({ status: 404, description: 'Report not found' })
  @Patch(':id/status')
  updateStatus(
    @Param('id') id: string,
    @Body() updateReportStatusDto: UpdateReportStatusDto,
  ) {
    return this.reportsService.updateReportStatus(
      id,
      updateReportStatusDto.status,
    );
  }

  @Get('status/:status')
  @UseGuards(RolesGuard)
  @Roles(Role.Admin, Role.Inspector, Role.SuperInspector)
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get reports by status' })
  @ApiParam({
    name: 'status',
    enum: ReportStatus,
    description: 'Status of the reports to fetch',
  })
  @ApiResponse({
    status: 200,
    description: 'List of reports with specified status',
  })
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
  @ApiQuery({
    name: 'order',
    enum: ['asc', 'desc'],
    required: false,
    description: 'Sort order (asc/desc)',
  })
  @ApiResponse({ status: 200, description: 'List of reports sorted by date' })
  getReportsByDate(@Query('order') order: 'asc' | 'desc' = 'desc') {
    return this.reportsService.getReportsByDate(order);
  }

  @Patch(':id/assign-inspector')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.SuperInspector)
  @ApiOperation({ summary: 'Assign an inspector to a report' })
  @ApiResponse({ status: 200, description: 'Inspector assigned successfully' })
  @ApiResponse({ status: 404, description: 'Report not found' })
  async assignInspector(
    @Param('id') id: string,
    @Body() assignInspectorDto: AssignInspectorDto,
  ) {
    this.logger.log(`Assigning inspector to report ${id}`, 'ReportsController');
    return this.reportsService.assignInspector(id, assignInspectorDto);
  }

  @Get('inspector/:inspectorId')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.Admin, Role.Inspector, Role.SuperInspector)
  @ApiOperation({ summary: 'Get reports assigned to a specific inspector' })
  @ApiParam({ name: 'inspectorId', description: 'ID of the inspector' })
  @ApiResponse({
    status: 200,
    description: 'List of reports assigned to the inspector',
    type: [Report],
  })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  async getReportsByInspectorId(@Param('inspectorId') inspectorId: string) {
    this.logger.log(
      `Fetching reports for inspector ${inspectorId}`,
      'ReportsController',
    );
    return this.reportsService.getReportsByInspectorId(inspectorId);
  }

  @Get('images/:filename')
  @ApiOperation({ summary: 'Get an image by filename' })
  @ApiParam({ name: 'filename', description: 'Filename of the image' })
  getImage(@Param('filename') filename: string, @Res() res: Response) {
    const filePath = path.join(__dirname, '..', '..', 'uploads', filename);
    const imageBuffer = this.reportsService.getImage(filePath);

    res.setHeader('Content-Type', 'image/png');
    res.send(imageBuffer);
  }
}

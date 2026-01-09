import { ApiProperty } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';
import { ReportStatus } from '../enums/report-state.enum';

export class UpdateReportStatusDto {
    @ApiProperty({ enum: ReportStatus, example: ReportStatus.RESOLVED, })
    @IsEnum(ReportStatus, { message: 'Status must be a valid ReportStatus value' })
    status: ReportStatus;
}

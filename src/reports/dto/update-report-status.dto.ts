import { ApiProperty } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';
import { ReportStatus } from 'src/common/enums/report-status.enum';

export class UpdateReportStatusDto {
    @ApiProperty({ enum: ReportStatus, enumName: 'ReportStatus' })
    @IsEnum(ReportStatus)
    status: ReportStatus;
}

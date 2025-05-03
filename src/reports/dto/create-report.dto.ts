import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, MaxLength, maxLength } from 'class-validator';

export class CreateReportDto {
  @ApiPropertyOptional({ description: 'User ID if provided, else anonymous', example: '68121a6264ffc188db6891d1' })
  @IsOptional()
  @MaxLength(8)
  userId?: string;

  @ApiProperty({ description: 'Report description', example: "Car parked on the side walk" })
  @IsOptional()
  description: string;

  @ApiProperty({ description: 'Liscense Plate Number', example: '11223132' })
  liscensePlateNumber: string

}

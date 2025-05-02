import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional } from 'class-validator';

export class CreateReportDto {
  @ApiPropertyOptional({ description: 'User ID if provided, else anonymous' })
  @IsOptional()
  userId?: string;

  @ApiProperty({ description: 'Report description' })
  @IsOptional()
  description: string;

  @ApiProperty({description: 'Liscense Plate Number'})
  liscensePlateNumber: string
  
}

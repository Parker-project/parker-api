import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { Type } from 'class-transformer';
import { IsOptional, ValidateNested } from 'class-validator';

class LocationDto {
  @ApiProperty({ description: 'Latitude', example: 31.7683 })
  latitude: number;

  @ApiProperty({ description: 'Longitude', example: 35.2137 })
  longitude: number;

  @ApiProperty({ description: 'Address', example: 'Tel Aviv, Israel' })
  address: string;
}

export class CreateReportDto {
  @ApiPropertyOptional({ description: 'User ID if provided, else anonymous', example: '68121a6264ffc188db6891d1' })
  @IsOptional()
  userId?: string;

  @ApiPropertyOptional({ description: 'Inspector ID if assigned', example: '68121a6264ffc188db6891d1' })
  @IsOptional()
  inspectorId?: string;

  @ApiProperty({ description: 'Report description', example: "Car parked on the side walk" })
  @IsOptional()
  description: string;

  @ApiProperty({ description: 'Liscense Plate Number', example: '11223132' })
  liscensePlateNumber: string

  @ApiPropertyOptional({ description: 'Location information', type: LocationDto })
  @IsOptional()
  @Transform(({ value }) => {
    if (typeof value === 'string') {
      try {
        return JSON.parse(value) as LocationDto;
      } catch {
        return undefined;
      }
    }
    return value as LocationDto;
  })
  @ValidateNested()
  @Type(() => LocationDto)
  location?: LocationDto;

  @ApiPropertyOptional({ description: 'Images', type: [String] })
  @IsOptional()
  images?: string[];
}

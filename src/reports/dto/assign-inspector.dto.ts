import { ApiProperty } from '@nestjs/swagger';
import { IsMongoId } from 'class-validator';

export class AssignInspectorDto {
    @ApiProperty({ description: 'Inspector ID', example: '68121a6264ffc188db6891d1' })
    inspectorId: string;
} 
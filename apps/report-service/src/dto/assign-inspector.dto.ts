import { ApiProperty } from '@nestjs/swagger';

export class AssignInspectorDto {
    @ApiProperty({ description: 'Inspector ID', example: '68121a6264ffc188db6891d1' })
    inspectorId: string;
} 
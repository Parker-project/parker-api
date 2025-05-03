import { Test, TestingModule } from '@nestjs/testing';
import { ReportsclearnestService } from './reportsclearnest.service';

describe('ReportsclearnestService', () => {
  let service: ReportsclearnestService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ReportsclearnestService],
    }).compile();

    service = module.get<ReportsclearnestService>(ReportsclearnestService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

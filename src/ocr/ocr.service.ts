import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as FormData from 'form-data';
import axios, { AxiosInstance } from 'axios';

interface PlateRecognizerResponse {
  results: Array<{
    plate: string;
    score: number;
    box: {
      xmin: number;
      ymin: number;
      xmax: number;
      ymax: number;
    };
    region: {
      code: string;
      score: number;
    };
    candidates: Array<{
      score: number;
      plate: string;
    }>;
    dscore: number;
    vehicle: {
      score: number;
      type: string;
      box: {
        xmin: number;
        ymin: number;
        xmax: number;
        ymax: number;
      };
    };
  }>;
}

@Injectable()
export class OcrService {
  private readonly logger = new Logger(OcrService.name);
  private readonly axiosInstance: AxiosInstance;
  private readonly apiUrl: string;
  private readonly apiKey: string;

  constructor(private configService: ConfigService) {
    this.apiUrl = this.configService.get<string>('OCR_API_URL') ?? '';
    this.apiKey = this.configService.get<string>('OCR_API_KEY') ?? '';

    if (!this.apiKey || !this.apiUrl) {
      throw new Error('OCR_API_KEY or OCR_API_URL is not configured');
    }
  }

  /**
   * Process an image file to recognize license plate text using PlateRecognizer
   * @param imagePath Path to the image file
   * @returns Recognized text from the image
   */
  async recognizeLicensePlate(
    imagePath: string,
  ): Promise<PlateRecognizerResponse> {
    this.logger.log(`Processing image for license plate OCR: ${imagePath}`);

    try {
      const formData = new FormData();
      formData.append('upload', fs.createReadStream(imagePath));

      const { data } = await axios.post<PlateRecognizerResponse>(
        this.apiUrl,
        formData,
        {
          headers: {
            ...formData.getHeaders(),
            Authorization: `Token ${this.apiKey}`,
          },
        },
      );

      const results = data.results;
      if (!results || results.length === 0) {
        this.logger.warn('No license plates detected in the image');
        return {
          results: [],
        };
      }

      const bestResult = results.reduce((best, current) => {
        return current.score > best.score ? current : best;
      }, results[0]);

      return bestResult as unknown as PlateRecognizerResponse;
    } catch (error) {
      this.logger.error(
        `Error recognizing license plate: ${
          error instanceof Error ? error.message : String(error)
        }`,
        error instanceof Error ? error.stack : undefined,
      );
      return {
        results: [],
      };
    }
  }
}

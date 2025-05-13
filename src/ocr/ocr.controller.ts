import {
  Controller,
  Post,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { OcrService } from './ocr.service';
import * as fs from 'fs';
import * as path from 'path';
import { diskStorage } from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { LicensePlateResponse } from './interfaces/license-plate.interface';

@Controller('ocr')
export class OcrController {
  private readonly logger = new Logger(OcrController.name);

  constructor(private readonly ocrService: OcrService) {}

  @Post('license-plate')
  @UseInterceptors(
    FileInterceptor('image', {
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
        if (!file.mimetype.match(/\/(jpg|jpeg|png|gif)$/)) {
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
  async recognizeLicensePlate(
    @UploadedFile() file: Express.Multer.File,
  ): Promise<LicensePlateResponse> {
    if (!file) {
      throw new BadRequestException('No image file uploaded');
    }

    try {
      this.logger.log(`Processing license plate image: ${file.originalname}`);

      // Process the uploaded image
      const licensePlate = await this.ocrService.recognizeLicensePlate(
        file.path,
      );

      // Return the recognized text with enhanced response
      return {
        success: true,
        licensePlate: {
          text: licensePlate.results[0].plate,
          isConfident: licensePlate.results[0].score > 0.8,
        },
        originalFile: file.originalname,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error(
        `Error in license plate recognition: ${error instanceof Error ? error.message : String(error)}`,
        error instanceof Error ? error.stack : undefined,
      );

      // Clean up the uploaded file in case of error
      if (file.path && fs.existsSync(file.path)) {
        try {
          fs.unlinkSync(file.path);
        } catch (error) {
          this.logger.warn(
            `Failed to delete uploaded file: ${file.path}`,
            error,
          );
        }
      }

      // Return appropriate error response
      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new InternalServerErrorException(
        'An error occurred during license plate recognition',
      );
    }
  }
}

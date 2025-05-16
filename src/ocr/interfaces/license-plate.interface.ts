import { PlateRecognizerResponse } from '../ocr.service';

/**
 * License plate recognition result interface
 */
export interface LicensePlateResult {
  /**
   * The recognized license plate text
   */
  text: string;

  /**
   * Whether the recognition is confident (not UNRECOGNIZED)
   */
  isConfident: boolean;
}

/**
 * License plate recognition response interface
 */
export interface LicensePlateResponse {
  /**
   * Whether the operation was successful
   */
  success: boolean;

  /**
   * The recognized license plate information
   */
  licensePlate: PlateRecognizerResponse;

  /**
   * The original file name that was processed
   */
  originalFile: string;

  /**
   * Timestamp when the recognition was performed
   */
  timestamp: string;
} 
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { ReportStatus } from 'src/common/enums/report-state.enum';

@Schema({ timestamps: true })
export class Report extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: false })
  userId: Types.ObjectId;

  @Prop({ type: Types.ObjectId, ref: 'User', required: false })
  inspectorId: Types.ObjectId;

  @Prop({ required: true })
  description: string;

  @Prop({ required: true })
  liscensePlateNumber: string

  @Prop({
    type: String,
    enum: ReportStatus,
    default: ReportStatus.PENDING
  })
  status: ReportStatus;

  @Prop({
    type: Object,
    required: false,
    default: null
  })
  location: {
    latitude: number;
    longitude: number;
    address: string;
  };

  @Prop({ type: [String], required: false })
  images: string[];
}

export const ReportSchema = SchemaFactory.createForClass(Report);

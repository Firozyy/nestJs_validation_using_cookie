import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
enum Role {
  user="user",
  admin="admin", 
}
@Schema({
  timestamps: true,
})
export class User extends Document {
  @Prop()
  name: string;

  @Prop({ unique: [true, 'Duplicate email entered'] })
  email: string;

  @Prop()
  password: string;
  @Prop({ type: String, enum: Role, default: Role.user })
  role: Role;
}

export const UserSchema = SchemaFactory.createForClass(User);

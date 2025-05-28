import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './users/users.module';
// import { EmailModule } from './email/email.module';
import * as dotenv from 'dotenv';

dotenv.config();

@Module({
  imports: [
    MongooseModule.forRoot(process.env.MONGODB_URI),
    UsersModule,
    // EmailModule,
  ],
})
export class AppModule {}

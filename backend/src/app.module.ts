import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { NftContractModule } from './nft-contract/nft-contract.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes .env globally available
    }),
    MongooseModule.forRoot(process.env.MONGO_URI),
    AuthModule,
    NftContractModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}


// contract.module.ts
import { Module } from '@nestjs/common';
import { NftContractService } from './nft-contract.service';
import { NftContractController } from './nft-contract.controller';
import { User, UserSchema } from '../auth/schema/user.schema';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from 'src/auth/auth.module';
import { JwtService } from '@nestjs/jwt';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    AuthModule
  ],
  providers: [NftContractService],
  controllers: [NftContractController],
exports: [NftContractModule], // Export the service if other modules need it
})
export class NftContractModule {}

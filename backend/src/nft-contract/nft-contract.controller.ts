import { Controller, Post, Body, UseGuards, Request } from '@nestjs/common';
import { NftContractService } from './nft-contract.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard'; // Ensure this path is correct

@Controller('nft-contract')
export class NftContractController {
  constructor(private readonly nftContractService: NftContractService) {}

  @Post('mint')
  @UseGuards(JwtAuthGuard) // Protect the route with JWT guard
  async mintNFT(@Body('identifier') userIdentifier: string, @Body('tokenURI') tokenURI: string) {
    return this.nftContractService.mintNFT(userIdentifier, tokenURI);
  }
}

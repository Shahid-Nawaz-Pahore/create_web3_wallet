import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { NftContractService } from './nft-contract.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard'; 
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('NFT Contract') // Tag for grouping in Swagger
@Controller('nft-contract')
export class NftContractController {
  constructor(private readonly nftContractService: NftContractService) {}

  @Post('mint')
  @UseGuards(JwtAuthGuard) // Protect the route with JWT guard
  @ApiBearerAuth() // Indicate that this endpoint requires Bearer token
  @ApiOperation({ summary: 'Mint an NFT' }) // Brief description of the endpoint
  @ApiResponse({ status: 200, description: 'NFT minted successfully.' }) // Successful response
  @ApiResponse({ status: 401, description: 'Unauthorized. Invalid token.' }) // Unauthorized response
  @ApiResponse({ status: 404, description: 'User not found.' }) // User not found response
  @ApiResponse({ status: 500, description: 'Failed to mint NFT.' }) // General error response
  async mintNFT(
    @Body('identifier') userIdentifier: string, 
    @Body('tokenURI') tokenURI: string
  ) {
    return this.nftContractService.mintNFT(userIdentifier, tokenURI);
  }
}

import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ethers } from 'ethers';
import { User } from '../auth/schema/user.schema'; // Adjust the import path based on your structure
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as CryptoJS from 'crypto-js';
import * as bcrypt from 'bcrypt'; // Import bcrypt
import { CONTRACT_ABI, CONTRACT_ADDRESS } from './contract';

@Injectable()
export class NftContractService {
  private provider: ethers.providers.JsonRpcProvider;
  private contract: ethers.Contract;

  constructor(
    @InjectModel(User.name) private userModel: Model<User>, // Inject the User model
  ) {
    // Initialize provider
    this.provider = new ethers.providers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
    this.contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, this.provider);
  }

  async mintNFT(userIdentifier: string, tokenURI: string) {
    try {
      // Find the user by wallet address or ID
      const user = await this.userModel.findOne({
        $or: [{ walletAddress: userIdentifier }, { _id: userIdentifier }],
      });

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      // Here, you'd typically get the plaintext password from the user input
      // For example, you may pass it as a parameter to this method.
      const plaintextPassword ="abc123";

      // Verify the password against the hashed password
      const passwordMatch = await bcrypt.compare(plaintextPassword, user.password);
      if (!passwordMatch) {
        throw new HttpException('Invalid password', HttpStatus.UNAUTHORIZED);
      }

      // Now you can decrypt the private key
      const decryptedPrivateKey = CryptoJS.AES.decrypt(user.encryptedPrivateKey, plaintextPassword).toString(CryptoJS.enc.Utf8);

      if (!decryptedPrivateKey) {
        throw new HttpException('Failed to decrypt private key. Please check the encrypted key and password.', HttpStatus.INTERNAL_SERVER_ERROR);
      }

      // Create a wallet instance from the decrypted private key
      const wallet = new ethers.Wallet(decryptedPrivateKey, this.provider);
     console.log("I on the top of safemint function");
      // Mint the NFT using the wallet instance
      const tx = await this.contract.connect(wallet).safeMint(tokenURI);
      await tx.wait(); // Wait for the transaction to be mined

      return { message: 'NFT minted successfully', transactionHash: tx.hash };
    } catch (error) {
      throw new HttpException(`Failed to mint NFT: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}

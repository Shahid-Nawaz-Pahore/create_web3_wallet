import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ethers } from 'ethers';
import { User } from '../auth/schema/user.schema'; // Adjust the import path based on your structure
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as CryptoJS from 'crypto-js';
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


  async whitelistUser(userAddress: string, ownerId: string) {
    try {
      // Find the owner by their ID (assuming the owner is stored as a user in your database)
      const owner = await this.userModel.findOne({ _id: ownerId });

      if (!owner) {
        throw new HttpException('Owner not found', HttpStatus.NOT_FOUND);
      }

      // Decrypt the owner's private key from the stored encrypted private key
      const decryptedPrivateKey = CryptoJS.AES.decrypt(owner.encryptedPrivateKey, owner.password).toString(CryptoJS.enc.Utf8);

      if (!decryptedPrivateKey) {
        throw new HttpException('Failed to decrypt owner private key', HttpStatus.INTERNAL_SERVER_ERROR);
      }

      // Create an ethers wallet instance for the owner using the decrypted private key
      const ownerWallet = new ethers.Wallet(decryptedPrivateKey, this.provider);

      // Interact with the contract to whitelist the user
      const tx = await this.contract.connect(ownerWallet).whitelistUser(userAddress);
      await tx.wait(); // Wait for the transaction to be mined

      return { message: 'User whitelisted successfully', transactionHash: tx.hash };
    } catch (error) {
      throw new HttpException(`Failed to whitelist user: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }


  async mintNFT(userId: string, tokenURI: string) {
    try {
      // Find the user by wallet address or ID
      const user = await this.userModel.findOne(
       { _id: userId }
      );

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      // Here, you'd typically get the plaintext password from the user input
      // For example, you may pass it as a parameter to this method.
      // const plaintextPassword ="abc123";

      // // Verify the password against the hashed password
      // const passwordMatch = await bcrypt.compare(plaintextPassword, user.password);
      // if (!passwordMatch) {
      //   throw new HttpException('Invalid password', HttpStatus.UNAUTHORIZED);
      // }

      // Now you can decrypt the private key
      const decryptedPrivateKey = CryptoJS.AES.decrypt(user.encryptedPrivateKey, user.password).toString(CryptoJS.enc.Utf8);
      // console.log(decryptedPrivateKey)
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
    }//0x691EC8f12d195e9C4e189FE17b4F04ba278d9CFB
  }
}

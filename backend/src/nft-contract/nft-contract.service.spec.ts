import { Test, TestingModule } from '@nestjs/testing';
import { NftContractService } from './nft-contract.service';
import { getModelToken } from '@nestjs/mongoose';
import { User } from '../auth/schema/user.schema';
import * as CryptoJS from 'crypto-js';

describe('NftContractService', () => {
  let service: NftContractService;
  let userModel: any;

  const mockUser = {
    _id: 'mockUserId',
    encryptedPrivateKey: CryptoJS.AES.encrypt('mockPrivateKey', 'mockPassword').toString(),
    password: 'mockPassword',
  };

  const mockOwner = {
    _id: 'mockOwnerId',
    encryptedPrivateKey: CryptoJS.AES.encrypt('mockOwnerPrivateKey', 'mockOwnerPassword').toString(),
    password: 'mockOwnerPassword',
  };

  const mockContract = {
    whitelistUser: jest.fn().mockResolvedValue({ hash: 'mockTxHash' }),
    safeMint: jest.fn().mockResolvedValue({ hash: 'mockTxHash' }),
    connect: jest.fn().mockReturnThis(), // Mock connect to return the same object
  };

  const mockProvider = {
    getSigner: jest.fn().mockReturnValue({ getAddress: jest.fn().mockReturnValue('mockOwnerAddress') }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NftContractService,
        {
          provide: getModelToken(User.name),
          useValue: {
            findOne: jest.fn().mockImplementation((query) => {
              if (query._id === 'mockOwnerId') return mockOwner;
              if (query._id === 'mockUserId') return mockUser;
              return null;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<NftContractService>(NftContractService);
    userModel = module.get(getModelToken(User.name));

    // Mock ethers provider and contract
    service['provider'] = mockProvider as any;
    service['contract'] = mockContract as any;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('whitelistUser', () => {
    it('should whitelist a user successfully', async () => {
      const result = await service.whitelistUser('mockUserAddress', 'mockOwnerId');
      expect(result).toEqual({ message: 'User whitelisted successfully', transactionHash: 'mockTxHash' });
      expect(mockContract.whitelistUser).toHaveBeenCalledWith('mockUserAddress');
    });

    it('should throw an error if owner is not found', async () => {
      await expect(service.whitelistUser('mockUserAddress', 'invalidOwnerId')).rejects.toThrow('Owner not found');
    });

    it('should throw an error if private key decryption fails', async () => {
      jest.spyOn(CryptoJS.AES, 'decrypt').mockReturnValueOnce(CryptoJS.enc.Utf8.parse(''));
      await expect(service.whitelistUser('mockUserAddress', 'mockOwnerId')).rejects.toThrow('Failed to decrypt owner private key');
    });
  });

  describe('mintNFT', () => {
    it('should mint an NFT successfully', async () => {
      const result = await service.mintNFT('mockUserId', 'mockTokenURI');
      expect(result).toEqual({ message: 'NFT minted successfully', transactionHash: 'mockTxHash' });
      expect(mockContract.safeMint).toHaveBeenCalledWith('mockTokenURI');
    });

    it('should throw an error if user is not found', async () => {
      await expect(service.mintNFT('invalidUserId', 'mockTokenURI')).rejects.toThrow('User not found');
    });

    it('should throw an error if private key decryption fails', async () => {
      jest.spyOn(CryptoJS.AES, 'decrypt').mockReturnValueOnce(CryptoJS.enc.Utf8.parse(''));
      await expect(service.mintNFT('mockUserId', 'mockTokenURI')).rejects.toThrow('Failed to decrypt private key. Please check the encrypted key and password.');
    });
  });
});

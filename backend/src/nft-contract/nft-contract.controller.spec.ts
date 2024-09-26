import { Test, TestingModule } from '@nestjs/testing';
import { NftContractController } from './nft-contract.controller';

describe('NftContractController', () => {
  let controller: NftContractController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [NftContractController],
    }).compile();

    controller = module.get<NftContractController>(NftContractController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});

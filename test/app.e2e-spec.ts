import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';

describe('App E2E', () => {
  beforeAll(async () => {
    const moduleRef =
      await Test.createTestingModule({
        imports: [AppModule],
      }).compile();
  });
  it.todo('should pass');
});

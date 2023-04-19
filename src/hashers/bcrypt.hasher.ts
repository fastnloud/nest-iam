import { Injectable } from '@nestjs/common';
import { compare, genSalt, hash } from 'bcrypt';
import { IHasher } from '../interfaces/hasher.interface';

@Injectable()
export class BcryptHasher implements IHasher {
  async hash(data: string | Buffer): Promise<string> {
    const salt = await genSalt();

    return hash(data, salt);
  }

  async compare(data: string | Buffer, encrypted: string): Promise<boolean> {
    return compare(data, encrypted);
  }
}

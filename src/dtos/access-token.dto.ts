import { ApiProperty } from '@nestjs/swagger';

export class AccessTokenDto {
  @ApiProperty()
  public readonly accessToken: string;

  constructor(accessToken: string) {
    this.accessToken = accessToken;
  }
}

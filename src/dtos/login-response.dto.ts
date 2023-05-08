import { ApiProperty } from '@nestjs/swagger';

export class LoginResponseDto {
  @ApiProperty()
  public readonly accessToken: string;

  @ApiProperty()
  public readonly refreshToken: string;
}

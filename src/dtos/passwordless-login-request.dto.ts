import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class PasswordlessLoginRequestDto {
  @IsString()
  @ApiProperty()
  username: string;
}

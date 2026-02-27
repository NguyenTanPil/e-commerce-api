import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";

export class SignUpDto {
    @IsString()
    @IsEmail()
    email: string

    @IsString()
    @IsNotEmpty()
    @MinLength(8)
    password: string

    @IsString()
    @IsNotEmpty()
    name: string
}
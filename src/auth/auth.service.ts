import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { SignInDto } from './dto/sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { UserToken } from './user-token.entity';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { StringValue } from 'ms';
import * as bcrypt from 'bcrypt';
import { addDays, sub } from 'date-fns';
import { SignUpDto } from './dto/sign-up.dto';
import { AuthMapper } from './dto/AuthMapper';

interface JwtPayload {
    sub: number
    email: string
}

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        @InjectRepository(UserToken) private readonly userTokenRepo: Repository<UserToken>
    ) {}

    async generateToken(payload: JwtPayload, secretKey: string, expiresInKey: string) {
        const token = await this.jwtService.signAsync(payload, {
            secret: this.configService.get<string>(secretKey)!,
            expiresIn:this.configService.get<string>(expiresInKey) as StringValue,
        });
        return token;
    }

    async generateRefreshToken(payload: JwtPayload) {
        const refreshToken = await this.generateToken(payload, 'JWT_REFRESH_SECRET', 'JWT_REFRESH_EXPIRES_IN');

        const hashToken = await bcrypt.hash(refreshToken, 10);
        await this.userTokenRepo.save({
            userId: payload.sub,
            email: payload.email,
            refreshTokenHash: hashToken,
            expiresAt: addDays(new Date(), 1),
        });
        return refreshToken;
    }

    async generateAccessToken(payload: JwtPayload) {
        try {
            const accessToken = await this.generateToken(payload, 'JWT_ACCESS_SECRET', 'JWT_ACCESS_EXPIRES_IN');
            return accessToken;
        } catch {
            console.log('Error due gernerate access token');
        }
    }

    async refresh(refreshToken: string) {
        let payload: any;

        try {
            payload = this.jwtService.verify(refreshToken, {
                secret: this.configService.getOrThrow('JWT_REFRESH_SECRET')
            });
        } catch {
            throw new UnauthorizedException('Invalid refresh token');
        }

        const token = await this.userTokenRepo.findOne({
            where: {
                userId: payload.sub,
                revoked: false,
            }
        });

        const validToken = await bcrypt.compare(refreshToken, token?.refreshTokenHash);
        if(!validToken) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        if(validToken.expiresAt < new Date()) {
            throw new UnauthorizedException('Refresh token expired');
        }

        await this.userTokenRepo.update(
            { id: validToken.id },
            { revoked: true }
        );

        const newRefreshToken = await this.generateRefreshToken(payload);
        const newAccessToken = await this.generateAccessToken(payload);
        return {
            refreshToken: newRefreshToken,
            accessToken: newAccessToken,
        };
    }

    async signUp(payload: SignUpDto) {
        const userCreated = await this.userService.create(payload);
        return AuthMapper.toResponse(userCreated);
    }

    async signIn(payload: SignInDto) {
        const user = await this.userService.findByEmail(payload.email);

        if(!user) {
            throw new UnauthorizedException('Not found user with email');
        }

        const isMatch = await bcrypt.compare(payload.password, user.passwordHash);
        if(!isMatch) {
            throw new UnauthorizedException('Password is incorrect');
        }

        const jwtPayload = {
            sub: user.id,
            email: user.email,
        };

        const refreshToken = await this.generateRefreshToken(jwtPayload);
        const accessToken = await this.generateAccessToken(jwtPayload);
        return {
            refreshToken,
            accessToken,
        };
    }

    async signOut(refreshToken: string) {
        try {
            const payload = this.jwtService.verify(refreshToken, {
                secret: this.configService.getOrThrow('JWT_REFRESH_SECRET')
            });
            const token = await this.userTokenRepo.findOne({
                where: {
                    userId: payload.sub,
                    revoked: false
                }
            });

            const isMatch = await bcrypt.compare(refreshToken, token?.refreshTokenHash);
            if(isMatch) {
                await this.userTokenRepo.update(
                    { id: token?.id },
                    { revoked: true }
                );
            } else {
                throw new UnauthorizedException('Invalid refresh token');
            }
        } catch {
            // ignore
        }
    }
}

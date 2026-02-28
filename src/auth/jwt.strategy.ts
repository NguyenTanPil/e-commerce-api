import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";

export interface JwtPayload {
    sub: string
    email: string;
    iat?: number;
    exp?: number;
};

export interface JwtUser {
    userId: string;
    email: string;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        private readonly configService: ConfigService
    ) {
        const secret = configService.get<string>('JWT_ACCESS_SECRET');

        if(!secret) {
            throw new Error('Not found jwt');
        }
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: secret,
            ignoreExpiration: false,
        });
    }

    async validate(payload: JwtPayload): Promise<JwtUser> {
        if(!payload?.sub || !payload?.email) {
            throw new UnauthorizedException('Invalid token payload');
        }
        return {
            userId: payload.sub,
            email: payload.email,
        };
    }
}
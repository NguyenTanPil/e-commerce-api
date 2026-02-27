import { Body, Controller, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import type { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService
    ) { }

    @Post('sign-up')
    signUp(@Body() payload: SignUpDto) {
        return this.authService.signUp(payload);
    }

    @Post('sign-in')
    async signIn(
        @Body() payload: SignInDto, 
        @Res({ passthrough: true }) res: Response
    ) {
        const { accessToken, refreshToken } = await this.authService.signIn(payload);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            path: '/auth/refresh',
            maxAge: 1000 * 60 * 60 * 24,
        });
        return { accessToken };
    }

    @Post('refresh')
    async refresh(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response
    ) {
        const refreshToken = req.cookies?.refreshToken;

        if(!refreshToken) {
            throw new UnauthorizedException('No refresh token');
        }

        const { accessToken, refreshToken: newRefreshToken } = await this.authService.refresh(refreshToken);
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            path: '/auth/refresh',
            maxAge: 1000 * 60 * 60 * 24,
        });
        return { accessToken };
    }

    @Post('sign-out')
    async signOut(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response
    ) {
        const refreshToken = req.cookies?.refreshToken;
        if(refreshToken) {
            await this.authService.signOut(refreshToken);
        }

        res.clearCookie('refreshToken', {
            path: '/auth/refresh'
        });

        return { message: 'Signout successfully' };
    }

}

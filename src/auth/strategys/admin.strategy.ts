import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { PassportStrategy } from '@nestjs/passport';
import { Model } from 'mongoose';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { User } from '../schemas/user.schema';
import { Request } from 'express'
@Injectable()
export class AdminStrategy extends PassportStrategy(Strategy,"admin") {
    constructor(
        @InjectModel(User.name)
        private userModel: Model<User>,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                AdminStrategy.ExtractJwt,
              ]),
              ignoreExpiration: false,
            secretOrKey: process.env.JWT_SECRET,
        });
    }
    private static ExtractJwt(req: Request): string | null {
       
        
        if (req.cookies && req.cookies.access_token) {
            return req.cookies.access_token;
        }
        return null;
    }
    async validate(payload) {
        

        const { id } = payload;

        const user = await this.userModel.findById(id);


        
        if (user.role !=="admin") {
            throw new UnauthorizedException('Admin only access');
        }
        return user;
    }
}

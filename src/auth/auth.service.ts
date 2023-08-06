import { Injectable,UnauthorizedException } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import * as bcrypt from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import { LoginDto } from './dto/LoginDto';
@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}
    async signUp(CreateAuthDto: CreateAuthDto): Promise< any > {
      const { name, email, password } = CreateAuthDto;
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
      const user = await this.userModel.create({
        name,
        email,
        password: hashedPassword,
      });
  
      const token = this.jwtService.sign({ id: user._id });
  
      return user;
    }
  
    async login(loginDto: LoginDto,req,res): Promise<{ token: string }> {
      const { email, password } = loginDto;
  
      const user = await this.userModel.findOne({ email });
  
      if (!user) {
        throw new UnauthorizedException('Invalid email or password');
      }
  
      const isPasswordMatched = await bcrypt.compare(password, user.password);
  
      if (!isPasswordMatched) {
        throw new UnauthorizedException('Invalid email or password');
      }
  
      const token = this.jwtService.sign({ id: user._id });
      res.cookie('access_token', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            expires: new Date(Date.now() + 1 * 24 * 60 * 1000),
        })
      return { token };
    }

 
  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}

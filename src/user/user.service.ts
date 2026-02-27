import { ConflictException, Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { User } from "./user.entity";
import { Repository } from "typeorm";
import { CreateUserDto } from "./dto/create-user.dto";
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User) private readonly userRepo: Repository<User>
    ) {}

    async create(payload: CreateUserDto) {
        const existingUser = await this.userRepo.findOne({
            where: { email: payload.email },
        });

        if(existingUser) {
            throw new ConflictException('Email already exits');
        }

        const passwordHash = await bcrypt.hash(payload.password, 10);
        const user = this.userRepo.create({
            name: payload.name,
            email: payload.email,
            passwordHash: passwordHash,
        });

        const savedUser = await this.userRepo.save(user);
        return savedUser;
    }

    findByEmail(email: string) {
        return this.userRepo.findOneBy({ email });
    }
}
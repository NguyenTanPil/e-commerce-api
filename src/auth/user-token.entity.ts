import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity('user_token')
export class UserToken  {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column()
    userId: number;

    @Column()
    email: string;

    @Column({ default: false })
    revoked: boolean;

    @Column()
    refreshTokenHash: string;

    @Column()
    expiresAt: Date;

    @CreateDateColumn()
    createdAt: Date;
}
import { User } from "src/user/user.entity";

export class AuthMapper {
    static toResponse(user: User) {
        return {
            name: user.name,
            email: user.email,
        };
    }
}
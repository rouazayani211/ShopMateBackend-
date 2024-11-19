// src/user/dto/update-user.dto.ts
export class UpdateUserDto {
    readonly nom?: string;
    readonly prenom?: string;
    readonly email?: string;
    readonly historiqueAchat?: string[];
    readonly preferences?: string[];
  }
  
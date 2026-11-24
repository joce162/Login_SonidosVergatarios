package com.ms_SonidosVergatarios.login.dto;

import jakarta.validation.constraints.*;

public record RegistroRequest(
        @NotBlank(message = "Ingresa un nombre de usuario.")
        @Pattern(regexp = "^[a-zA-Z0-9._-]{3,20}$",
                message = "Usa de 3 a 20 caracteres: letras, números, punto, guion o guion bajo.")
        String usuario,

        @NotBlank(message = "Ingresa un correo electrónico.")
        @Email(message = "Ingresa un correo electrónico válido.")
        @Size(max = 120, message = "El correo es demasiado largo.")
        String email,

        @NotBlank(message = "Ingresa una contraseña.")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).{8,64}$",
                message = "Usa de 8 a 64 caracteres, con al menos una letra y un número.")
        String contrasena) {
}

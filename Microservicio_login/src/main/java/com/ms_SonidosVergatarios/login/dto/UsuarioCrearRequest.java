package com.ms_SonidosVergatarios.login.dto;

import com.ms_SonidosVergatarios.login.model.Rol;
import jakarta.validation.constraints.*;

public record UsuarioCrearRequest(
        @NotBlank(message = "Ingresa un nombre de usuario.")
        @Pattern(regexp = "^[a-zA-Z0-9._-]{3,20}$", message = "Nombre de usuario no válido.")
        String usuario,

        @NotBlank(message = "Ingresa un correo electrónico.")
        @Email(message = "Ingresa un correo electrónico válido.")
        @Size(max = 120)
        String email,

        @NotBlank(message = "Ingresa una contraseña.")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).{8,64}$",
                message = "Usa de 8 a 64 caracteres, con al menos una letra y un número.")
        String contrasena,

        @NotNull(message = "Indica el rol.") Rol rol) {
}

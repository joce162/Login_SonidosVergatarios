package com.ms_SonidosVergatarios.login.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "Ingresa tu correo o nombre de usuario.") String identificador,
        @NotBlank(message = "Ingresa tu contraseña.") String contrasena) {
}

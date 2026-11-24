package com.ms_SonidosVergatarios.login.dto;

import com.ms_SonidosVergatarios.login.model.Rol;
import jakarta.validation.constraints.*;

/** Todos los campos son opcionales: solo se modifican los que vienen informados. */
public record UsuarioActualizarRequest(
        @Email(message = "Ingresa un correo electrónico válido.") @Size(max = 120) String email,
        Rol rol,
        Boolean activo,
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).{8,64}$",
                message = "Usa de 8 a 64 caracteres, con al menos una letra y un número.")
        String contrasena) {
}

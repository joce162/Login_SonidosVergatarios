package com.ms_SonidosVergatarios.login.dto;

import com.ms_SonidosVergatarios.login.model.Rol;
import com.ms_SonidosVergatarios.login.model.Usuario;

/** Lo que ve el cliente de un usuario. Nunca incluye el hash de la contraseña. */
public record UsuarioResponse(Long id, String usuario, String email, Rol rol, boolean activo) {

    public static UsuarioResponse desde(Usuario u) {
        return new UsuarioResponse(u.getId(), u.getUsuario(), u.getEmail(), u.getRol(), u.isActivo());
    }
}

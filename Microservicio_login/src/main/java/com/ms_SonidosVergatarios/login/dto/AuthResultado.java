package com.ms_SonidosVergatarios.login.dto;

/** Resultado interno: la sesión va en el cuerpo y el refresh token en una cookie HttpOnly. */
public record AuthResultado(SesionResponse sesion, String refreshToken) {
}

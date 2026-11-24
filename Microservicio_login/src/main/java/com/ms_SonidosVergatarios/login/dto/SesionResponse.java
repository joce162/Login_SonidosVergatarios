package com.ms_SonidosVergatarios.login.dto;

public record SesionResponse(String accessToken, String tipo, long expiraEnSegundos, UsuarioResponse usuario) {
}

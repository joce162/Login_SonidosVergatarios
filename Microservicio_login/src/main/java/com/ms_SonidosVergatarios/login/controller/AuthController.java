package com.ms_SonidosVergatarios.login.controller;

import com.ms_SonidosVergatarios.login.dto.*;
import com.ms_SonidosVergatarios.login.exception.ApiException;
import com.ms_SonidosVergatarios.login.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Autenticación")
public class AuthController {

    private static final String COOKIE = "refresh_token";

    private final AuthService auth;
    private final boolean cookieSegura;
    private final long diasRefresh;
    private final String valorCabecera;

    public AuthController(AuthService auth,
                          @Value("${app.cookie.secure}") boolean cookieSegura,
                          @Value("${app.jwt.refresh-days}") long diasRefresh,
                          @Value("${app.csrf-header}") String valorCabecera) {
        this.auth = auth;
        this.cookieSegura = cookieSegura;
        this.diasRefresh = diasRefresh;
        this.valorCabecera = valorCabecera;
    }

    @Operation(summary = "Registra un cliente nuevo (siempre con rol CLIENTE)")
    @PostMapping("/registro")
    @ResponseStatus(HttpStatus.CREATED)
    public UsuarioResponse registro(@Valid @RequestBody RegistroRequest r) {
        return auth.registrar(r);
    }

    @Operation(summary = "Inicia sesión con usuario o correo. Devuelve el JWT y deja la cookie de renovación")
    @PostMapping("/login")
    public ResponseEntity<SesionResponse> login(@Valid @RequestBody LoginRequest r) {
        return conCookie(auth.login(r));
    }

    @Operation(summary = "Renueva el JWT usando la cookie HttpOnly (exige X-Requested-With)")
    @PostMapping("/refresh")
    public ResponseEntity<SesionResponse> refresh(
            @RequestHeader(value = "X-Requested-With", required = false) String cabecera,
            @CookieValue(name = COOKIE, required = false) String token) {
        exigirCabecera(cabecera);
        if (token == null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "No hay una sesión activa.");
        }
        return conCookie(auth.refrescar(token));
    }

    @Operation(summary = "Cierra la sesión: revoca la renovación y borra la cookie")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(value = "X-Requested-With", required = false) String cabecera,
            @CookieValue(name = COOKIE, required = false) String token) {
        exigirCabecera(cabecera);
        if (token != null) {
            auth.cerrarSesion(token);
        }
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookie("", Duration.ZERO).toString()).build();
    }

    @Operation(summary = "Datos de la cuenta autenticada")
    @GetMapping("/me")
    public UsuarioResponse me(@AuthenticationPrincipal Jwt jwt) {
        return auth.perfil(Long.valueOf(jwt.getSubject()));
    }

    private ResponseEntity<SesionResponse> conCookie(AuthResultado r) {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie(r.refreshToken(), Duration.ofDays(diasRefresh)).toString())
                .body(r.sesion());
    }

    /** HttpOnly: JavaScript no puede leerla. SameSite=Strict + cabecera propia frenan CSRF. */
    private ResponseCookie cookie(String valor, Duration duracion) {
        return ResponseCookie.from(COOKIE, valor)
                .httpOnly(true)
                .secure(cookieSegura)
                .sameSite("Strict")
                .path("/api/auth")
                .maxAge(duracion)
                .build();
    }

    private void exigirCabecera(String cabecera) {
        if (!valorCabecera.equals(cabecera)) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Falta la cabecera de seguridad X-Requested-With.");
        }
    }
}

package com.ms_SonidosVergatarios.login.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.ms_SonidosVergatarios.login.dto.AuthResultado;
import com.ms_SonidosVergatarios.login.dto.LoginRequest;
import com.ms_SonidosVergatarios.login.dto.RegistroRequest;
import com.ms_SonidosVergatarios.login.exception.ApiException;
import com.ms_SonidosVergatarios.login.model.Rol;
import com.ms_SonidosVergatarios.login.model.Usuario;
import com.ms_SonidosVergatarios.login.repository.SesionRefreshRepository;
import com.ms_SonidosVergatarios.login.repository.UsuarioRepository;
import com.ms_SonidosVergatarios.login.security.JwtService;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class AuthServiceTest {

    private UsuarioRepository usuarios;
    private SesionRefreshRepository sesiones;
    private JwtService jwt;
    private PasswordEncoder encoder;
    private AuthService servicio;

    @BeforeEach
    void preparar() {
        usuarios = mock(UsuarioRepository.class);
        sesiones = mock(SesionRefreshRepository.class);
        jwt = mock(JwtService.class);
        encoder = new BCryptPasswordEncoder(4);
        servicio = new AuthService(usuarios, sesiones, encoder, jwt, 7);
    }

    private Usuario cuenta(String usuario, String clave, Rol rol) {
        Usuario u = new Usuario();
        u.setUsuario(usuario);
        u.setEmail(usuario + "@correo.cl");
        u.setPasswordHash(encoder.encode(clave));
        u.setRol(rol);
        return u;
    }

    @Test
    void registroRechazaNombresReservados() {
        ApiException e = assertThrows(ApiException.class,
                () -> servicio.registrar(new RegistroRequest("admin", "x@correo.cl", "Clave1234")));
        assertEquals(HttpStatus.CONFLICT, e.getEstado());
        verify(usuarios, never()).save(any());
    }

    @Test
    void registroCreaSiempreUnCliente() {
        when(usuarios.existsByUsuarioIgnoreCase("ana")).thenReturn(false);
        when(usuarios.existsByEmailIgnoreCase("ana@correo.cl")).thenReturn(false);
        when(usuarios.save(any(Usuario.class))).thenAnswer(inv -> inv.getArgument(0));

        var respuesta = servicio.registrar(new RegistroRequest("ana", "Ana@correo.cl", "Clave1234"));

        assertEquals(Rol.CLIENTE, respuesta.rol());
        assertEquals("ana@correo.cl", respuesta.email());
    }

    @Test
    void loginConClaveIncorrectaDevuelve401() {
        when(usuarios.findByUsuarioIgnoreCaseOrEmailIgnoreCase("ana", "ana"))
                .thenReturn(Optional.of(cuenta("ana", "Clave1234", Rol.CLIENTE)));

        ApiException e = assertThrows(ApiException.class,
                () -> servicio.login(new LoginRequest("ana", "otra-clave")));
        assertEquals(HttpStatus.UNAUTHORIZED, e.getEstado());
    }

    @Test
    void loginCorrectoEntregaTokenYRefresh() {
        when(usuarios.findByUsuarioIgnoreCaseOrEmailIgnoreCase("ana", "ana"))
                .thenReturn(Optional.of(cuenta("ana", "Clave1234", Rol.CLIENTE)));
        when(jwt.generarAccessToken(any(Usuario.class))).thenReturn("jwt-de-prueba");
        when(jwt.segundosAcceso()).thenReturn(900L);

        AuthResultado r = servicio.login(new LoginRequest("ana", "Clave1234"));

        assertEquals("jwt-de-prueba", r.sesion().accessToken());
        assertNotNull(r.refreshToken());
        verify(sesiones).save(any());
    }
}

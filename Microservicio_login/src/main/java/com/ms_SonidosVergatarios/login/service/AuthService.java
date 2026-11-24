package com.ms_SonidosVergatarios.login.service;

import com.ms_SonidosVergatarios.login.dto.*;
import com.ms_SonidosVergatarios.login.exception.ApiException;
import com.ms_SonidosVergatarios.login.model.Rol;
import com.ms_SonidosVergatarios.login.model.SesionRefresh;
import com.ms_SonidosVergatarios.login.model.Usuario;
import com.ms_SonidosVergatarios.login.repository.SesionRefreshRepository;
import com.ms_SonidosVergatarios.login.repository.UsuarioRepository;
import com.ms_SonidosVergatarios.login.security.JwtService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final Set<String> RESERVADOS = Set.of("admin", "administrador", "root");
    private static final SecureRandom ALEATORIO = new SecureRandom();

    private final UsuarioRepository usuarios;
    private final SesionRefreshRepository sesiones;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final long diasRefresh;

    public AuthService(UsuarioRepository usuarios, SesionRefreshRepository sesiones, PasswordEncoder encoder,
                       JwtService jwt, @Value("${app.jwt.refresh-days}") long diasRefresh) {
        this.usuarios = usuarios;
        this.sesiones = sesiones;
        this.encoder = encoder;
        this.jwt = jwt;
        this.diasRefresh = diasRefresh;
    }

    /** El registro público siempre crea un CLIENTE: el rol nunca lo elige quien se registra. */
    @Transactional
    public UsuarioResponse registrar(RegistroRequest r) {
        String usuario = r.usuario().trim();
        String email = r.email().trim().toLowerCase(Locale.ROOT);
        if (RESERVADOS.contains(usuario.toLowerCase(Locale.ROOT)) || usuarios.existsByUsuarioIgnoreCase(usuario)) {
            throw new ApiException(HttpStatus.CONFLICT, "Ese nombre de usuario no está disponible.", "usuario");
        }
        if (usuarios.existsByEmailIgnoreCase(email)) {
            throw new ApiException(HttpStatus.CONFLICT, "Ya existe una cuenta con ese correo.", "email");
        }
        Usuario u = new Usuario();
        u.setUsuario(usuario);
        u.setEmail(email);
        u.setPasswordHash(encoder.encode(r.contrasena()));
        u.setRol(Rol.CLIENTE);
        return UsuarioResponse.desde(usuarios.save(u));
    }

    @Transactional
    public AuthResultado login(LoginRequest r) {
        String identificador = r.identificador().trim();
        Usuario u = usuarios.findByUsuarioIgnoreCaseOrEmailIgnoreCase(identificador, identificador).orElse(null);
        if (u == null || !u.isActivo() || !encoder.matches(r.contrasena(), u.getPasswordHash())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Usuario o contraseña incorrectos.");
        }
        return abrirSesion(u);
    }

    /**
     * Renueva la sesión rotando el refresh token. Si llega uno ya revocado se asume robo
     * y se cierran todas las sesiones del usuario (por eso noRollbackFor).
     */
    @Transactional(noRollbackFor = ApiException.class)
    public AuthResultado refrescar(String tokenCrudo) {
        SesionRefresh s = sesiones.findByTokenHash(hash(tokenCrudo))
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Sesión no válida."));
        if (s.isRevocada()) {
            sesiones.revocarTodas(s.getUsuario().getId());
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Sesión no válida.");
        }
        if (s.getExpiraEn().isBefore(Instant.now()) || !s.getUsuario().isActivo()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "La sesión expiró. Inicia sesión nuevamente.");
        }
        s.setRevocada(true);
        return abrirSesion(s.getUsuario());
    }

    @Transactional
    public void cerrarSesion(String tokenCrudo) {
        sesiones.findByTokenHash(hash(tokenCrudo)).ifPresent(s -> s.setRevocada(true));
    }

    @Transactional(readOnly = true)
    public UsuarioResponse perfil(Long id) {
        return usuarios.findById(id).map(UsuarioResponse::desde)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado."));
    }

    private AuthResultado abrirSesion(Usuario u) {
        byte[] bytes = new byte[32];
        ALEATORIO.nextBytes(bytes);
        String crudo = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        SesionRefresh s = new SesionRefresh();
        s.setUsuario(u);
        s.setTokenHash(hash(crudo));
        s.setExpiraEn(Instant.now().plus(diasRefresh, ChronoUnit.DAYS));
        sesiones.save(s);

        SesionResponse cuerpo = new SesionResponse(jwt.generarAccessToken(u), "Bearer",
                jwt.segundosAcceso(), UsuarioResponse.desde(u));
        return new AuthResultado(cuerpo, crudo);
    }

    static String hash(String valor) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(valor.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

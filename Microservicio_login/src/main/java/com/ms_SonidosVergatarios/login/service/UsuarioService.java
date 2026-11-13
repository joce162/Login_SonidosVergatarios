package com.ms_SonidosVergatarios.login.service;

import com.ms_SonidosVergatarios.login.dto.UsuarioActualizarRequest;
import com.ms_SonidosVergatarios.login.dto.UsuarioCrearRequest;
import com.ms_SonidosVergatarios.login.dto.UsuarioResponse;
import com.ms_SonidosVergatarios.login.exception.ApiException;
import com.ms_SonidosVergatarios.login.model.Rol;
import com.ms_SonidosVergatarios.login.model.Usuario;
import com.ms_SonidosVergatarios.login.repository.SesionRefreshRepository;
import com.ms_SonidosVergatarios.login.repository.UsuarioRepository;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** CRUD de usuarios para el administrador. */
@Service
public class UsuarioService {

    private static final Set<String> RESERVADOS = Set.of("admin", "administrador", "root");

    private final UsuarioRepository usuarios;
    private final SesionRefreshRepository sesiones;
    private final PasswordEncoder encoder;

    public UsuarioService(UsuarioRepository usuarios, SesionRefreshRepository sesiones, PasswordEncoder encoder) {
        this.usuarios = usuarios;
        this.sesiones = sesiones;
        this.encoder = encoder;
    }

    @Transactional(readOnly = true)
    public List<UsuarioResponse> listar() {
        return usuarios.findAll().stream().map(UsuarioResponse::desde).toList();
    }

    @Transactional(readOnly = true)
    public UsuarioResponse obtener(Long id) {
        return UsuarioResponse.desde(buscar(id));
    }

    @Transactional
    public UsuarioResponse crear(UsuarioCrearRequest r) {
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
        u.setRol(r.rol());
        return UsuarioResponse.desde(usuarios.save(u));
    }

    @Transactional
    public UsuarioResponse actualizar(Long id, UsuarioActualizarRequest r, Long idActual) {
        Usuario u = buscar(id);
        boolean perdeAcceso = false;

        if (r.email() != null) {
            String email = r.email().trim().toLowerCase(Locale.ROOT);
            if (usuarios.existsByEmailIgnoreCaseAndIdNot(email, id)) {
                throw new ApiException(HttpStatus.CONFLICT, "Ya existe una cuenta con ese correo.", "email");
            }
            u.setEmail(email);
        }
        if (r.rol() != null && r.rol() != u.getRol()) {
            if (u.getRol() == Rol.ADMIN) {
                exigirOtroAdmin(u);
            }
            u.setRol(r.rol());
            perdeAcceso = true; // el JWT vigente conserva el rol anterior hasta vencer; se revocan las renovaciones
        }
        if (r.activo() != null && r.activo() != u.isActivo()) {
            if (!r.activo()) {
                if (id.equals(idActual)) {
                    throw new ApiException(HttpStatus.CONFLICT, "No puedes desactivar tu propia cuenta.");
                }
                if (u.getRol() == Rol.ADMIN) {
                    exigirOtroAdmin(u);
                }
                perdeAcceso = true;
            }
            u.setActivo(r.activo());
        }
        if (r.contrasena() != null) {
            u.setPasswordHash(encoder.encode(r.contrasena()));
            perdeAcceso = true;
        }
        if (perdeAcceso) {
            sesiones.revocarTodas(id);
        }
        return UsuarioResponse.desde(usuarios.save(u));
    }

    /** Baja lógica: la cuenta queda inactiva y se revocan sus sesiones. */
    @Transactional
    public void eliminar(Long id, Long idActual) {
        Usuario u = buscar(id);
        if (id.equals(idActual)) {
            throw new ApiException(HttpStatus.CONFLICT, "No puedes eliminar tu propia cuenta.");
        }
        if (u.getRol() == Rol.ADMIN && u.isActivo()) {
            exigirOtroAdmin(u);
        }
        u.setActivo(false);
        sesiones.revocarTodas(id);
        usuarios.save(u);
    }

    private void exigirOtroAdmin(Usuario u) {
        if (u.isActivo() && usuarios.countByRolAndActivoTrue(Rol.ADMIN) <= 1) {
            throw new ApiException(HttpStatus.CONFLICT, "Debe existir al menos un administrador activo.");
        }
    }

    private Usuario buscar(Long id) {
        return usuarios.findById(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Usuario no encontrado."));
    }
}

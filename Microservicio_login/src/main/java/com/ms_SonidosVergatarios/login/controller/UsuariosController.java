package com.ms_SonidosVergatarios.login.controller;

import com.ms_SonidosVergatarios.login.dto.UsuarioActualizarRequest;
import com.ms_SonidosVergatarios.login.dto.UsuarioCrearRequest;
import com.ms_SonidosVergatarios.login.dto.UsuarioResponse;
import com.ms_SonidosVergatarios.login.service.UsuarioService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

/** Solo ADMIN (regla definida en SecurityConfig). */
@RestController
@RequestMapping("/api/usuarios")
@Tag(name = "Usuarios (ADMIN)")
public class UsuariosController {

    private final UsuarioService servicio;

    public UsuariosController(UsuarioService servicio) {
        this.servicio = servicio;
    }

    @Operation(summary = "Lista todos los usuarios")
    @GetMapping
    public List<UsuarioResponse> listar() {
        return servicio.listar();
    }

    @Operation(summary = "Obtiene un usuario por id")
    @GetMapping("/{id}")
    public UsuarioResponse obtener(@PathVariable Long id) {
        return servicio.obtener(id);
    }

    @Operation(summary = "Crea un usuario indicando su rol")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public UsuarioResponse crear(@Valid @RequestBody UsuarioCrearRequest r) {
        return servicio.crear(r);
    }

    @Operation(summary = "Modifica correo, rol, estado o contraseña")
    @PutMapping("/{id}")
    public UsuarioResponse actualizar(@PathVariable Long id, @Valid @RequestBody UsuarioActualizarRequest r,
                                      @AuthenticationPrincipal Jwt jwt) {
        return servicio.actualizar(id, r, Long.valueOf(jwt.getSubject()));
    }

    @Operation(summary = "Da de baja (desactiva) una cuenta")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void eliminar(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        servicio.eliminar(id, Long.valueOf(jwt.getSubject()));
    }
}

package com.ms_SonidosVergatarios.login.config;

import com.ms_SonidosVergatarios.login.model.Rol;
import com.ms_SonidosVergatarios.login.model.Usuario;
import com.ms_SonidosVergatarios.login.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Cuentas iniciales de desarrollo: se crean solo si no existen. */
@Configuration
public class Seed {

    @Bean
    ApplicationRunner cuentasIniciales(UsuarioRepository repo, PasswordEncoder encoder,
                                       @Value("${app.seed.admin-password}") String claveAdmin,
                                       @Value("${app.seed.demo}") boolean demo) {
        return args -> {
            if (!repo.existsByUsuarioIgnoreCase("admin")) {
                crear(repo, encoder, "admin", "admin@sonidosvergatarios.cl", claveAdmin, Rol.ADMIN);
            }
            if (demo && !repo.existsByUsuarioIgnoreCase("cliente")) {
                crear(repo, encoder, "cliente", "cliente@sonidosvergatarios.cl", "Cliente1234", Rol.CLIENTE);
            }
        };
    }

    private void crear(UsuarioRepository repo, PasswordEncoder encoder, String usuario, String email,
                       String clave, Rol rol) {
        Usuario u = new Usuario();
        u.setUsuario(usuario);
        u.setEmail(email);
        u.setPasswordHash(encoder.encode(clave));
        u.setRol(rol);
        repo.save(u);
    }
}

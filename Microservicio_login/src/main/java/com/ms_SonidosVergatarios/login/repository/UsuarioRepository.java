package com.ms_SonidosVergatarios.login.repository;

import com.ms_SonidosVergatarios.login.model.Rol;
import com.ms_SonidosVergatarios.login.model.Usuario;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {

    Optional<Usuario> findByUsuarioIgnoreCaseOrEmailIgnoreCase(String usuario, String email);

    boolean existsByUsuarioIgnoreCase(String usuario);

    boolean existsByEmailIgnoreCase(String email);

    boolean existsByEmailIgnoreCaseAndIdNot(String email, Long id);

    long countByRolAndActivoTrue(Rol rol);
}

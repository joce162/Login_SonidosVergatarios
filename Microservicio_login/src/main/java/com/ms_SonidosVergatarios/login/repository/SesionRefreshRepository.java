package com.ms_SonidosVergatarios.login.repository;

import com.ms_SonidosVergatarios.login.model.SesionRefresh;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SesionRefreshRepository extends JpaRepository<SesionRefresh, Long> {

    Optional<SesionRefresh> findByTokenHash(String tokenHash);

    @Modifying
    @Query("update SesionRefresh s set s.revocada = true where s.usuario.id = :usuarioId and s.revocada = false")
    int revocarTodas(@Param("usuarioId") Long usuarioId);
}

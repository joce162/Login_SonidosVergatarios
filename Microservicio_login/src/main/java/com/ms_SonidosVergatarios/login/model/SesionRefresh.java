package com.ms_SonidosVergatarios.login.model;

import jakarta.persistence.*;
import java.time.Instant;

/** Sesión de renovación: solo se guarda el hash del token, nunca el token. */
@Entity
@Table(name = "sesiones_refresh")
public class SesionRefresh {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "usuario_id")
    private Usuario usuario;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "expira_en", nullable = false)
    private Instant expiraEn;

    @Column(nullable = false)
    private boolean revocada = false;

    @Column(name = "creada_en", nullable = false)
    private Instant creadaEn = Instant.now();

    public Long getId() { return id; }
    public Usuario getUsuario() { return usuario; }
    public void setUsuario(Usuario usuario) { this.usuario = usuario; }
    public String getTokenHash() { return tokenHash; }
    public void setTokenHash(String tokenHash) { this.tokenHash = tokenHash; }
    public Instant getExpiraEn() { return expiraEn; }
    public void setExpiraEn(Instant expiraEn) { this.expiraEn = expiraEn; }
    public boolean isRevocada() { return revocada; }
    public void setRevocada(boolean revocada) { this.revocada = revocada; }
    public Instant getCreadaEn() { return creadaEn; }
}

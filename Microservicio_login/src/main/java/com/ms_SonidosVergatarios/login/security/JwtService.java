package com.ms_SonidosVergatarios.login.security;

import com.ms_SonidosVergatarios.login.model.Usuario;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

@Component
public class JwtService {

    private final JwtEncoder encoder;
    private final String emisor;
    private final long minutosAcceso;

    public JwtService(JwtEncoder encoder,
                      @Value("${app.jwt.issuer}") String emisor,
                      @Value("${app.jwt.access-minutes}") long minutosAcceso) {
        this.encoder = encoder;
        this.emisor = emisor;
        this.minutosAcceso = minutosAcceso;
    }

    /** subject = id del usuario; roles = lista con el rol (ADMIN o CLIENTE). */
    public String generarAccessToken(Usuario u) {
        Instant ahora = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(emisor)
                .issuedAt(ahora)
                .expiresAt(ahora.plus(minutosAcceso, ChronoUnit.MINUTES))
                .subject(String.valueOf(u.getId()))
                .claim("usuario", u.getUsuario())
                .claim("roles", List.of(u.getRol().name()))
                .build();
        JwsHeader cabecera = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(cabecera, claims)).getTokenValue();
    }

    public long segundosAcceso() {
        return minutosAcceso * 60;
    }
}

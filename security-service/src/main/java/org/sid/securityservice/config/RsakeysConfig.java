package org.sid.securityservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/* Grace au Camel case (publicKey == public-key) et a configurationProperties(vient set le prefixe "rsa." ), */
/* on vient faire le liens entre la valeur dans l'application properties et celle indique dans les parametres de class */
@ConfigurationProperties(prefix = "rsa")
/* Est utilise en tant que class de configuration pour recup la clé public et private */
public record RsakeysConfig(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
}

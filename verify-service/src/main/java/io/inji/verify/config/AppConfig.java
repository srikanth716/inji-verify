package io.inji.verify.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nimbusds.jose.shaded.gson.Gson;

import io.mosip.vercred.vcverifier.CredentialsVerifier;

@Configuration
public class AppConfig {
    @Bean
    public CredentialsVerifier credentialsVerifier() {
        return new CredentialsVerifier();
    }

    @Bean
    public Gson Gson() {
        return new Gson();
    }
}

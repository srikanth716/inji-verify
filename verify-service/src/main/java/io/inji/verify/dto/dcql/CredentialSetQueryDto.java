package io.inji.verify.dto.dcql;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialSetQueryDto {

    @NotBlank
    private String id;

    /**
     * Each inner list contains credential ids.
     */
    private List<List<String>> options;

    private boolean required = true;
}

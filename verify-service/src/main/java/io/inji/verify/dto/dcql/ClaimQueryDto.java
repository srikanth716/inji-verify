package io.inji.verify.dto.dcql;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ClaimQueryDto {

    private String id;

    @NotNull(message = "DCQL_CLAIM_PATH_REQUIRED")
    @NotEmpty(message = "DCQL_CLAIM_PATH_INVALID")
    private List<@NotBlank(message = "DCQL_CLAIM_PATH_INVALID") String> path;

    private boolean values;
}

package io.inji.verify.dto.dcql;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ClaimQueryDto {

    private String id;

    @NotEmpty
    private List<String> path;

    private boolean optional;
}

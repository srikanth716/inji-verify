package io.inji.verify.dto.submission;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import java.util.List;

@AllArgsConstructor
@Getter
@Valid
public class  PresentationSubmissionDto {
    @NotNull(message = "Presentation Submission ID cannot be null")
    @Size(min = 1, message = "Presentation Submission ID cannot be empty")
    private final String id;

    @NotNull(message = "Definition ID cannot be null")
    @Size(min = 1, message = "Definition ID cannot be empty")
    @JsonProperty("definition_id")
    @SerializedName("definition_id")
    private final String definitionId;

    @NotNull(message = "Descriptor Map cannot be null")
    @JsonProperty("descriptor_map")
    @SerializedName("descriptor_map")
    @Valid
    private final List<DescriptorMapDto> descriptorMap;
}

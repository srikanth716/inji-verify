package io.inji.verify.dto.submission;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.inji.verify.enums.ErrorCode;
import io.inji.verify.enums.VPResultStatus;
import io.inji.verify.models.VCResult;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VPTokenResultDto {
    String transactionId;
    VPResultStatus VPResultStatus;
    List<VCResult> VCResults;
    ErrorCode errorCode;
    String errorMessage;
}

package io.inji.verify.dto.authorizationrequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import io.inji.verify.dto.presentation.VPDefinitionResponseDto;
import io.inji.verify.dto.presentation.InputDescriptorDto;
import io.inji.verify.dto.presentation.FormatDto;
import io.inji.verify.dto.presentation.SubmissionRequirementDto;
import io.inji.verify.shared.Constants;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

public class AuthorizationRequestResponseDtoTest {

    @Test
    public void ShouldTestConstructorSetsFieldsCorrectly() {
        String clientId = "testClientId";
        String nonce = "testNonce";
        String responseUri = "testUri";
        List<InputDescriptorDto> mockInputDescriptors = mock();
        List<SubmissionRequirementDto> mockSubmissionRequirements = mock();
        FormatDto mockFormatDto = mock();
        VPDefinitionResponseDto vpDefinitionResponseDto = new VPDefinitionResponseDto("pd123", mockInputDescriptors, "name", "purpose", mockFormatDto, mockSubmissionRequirements);

        AuthorizationRequestResponseDto responseDto =
                new AuthorizationRequestResponseDto(clientId,
                        vpDefinitionResponseDto, nonce, responseUri, true, false);

        assertEquals(Constants.RESPONSE_TYPE, responseDto.getResponseType());
        assertEquals(clientId, responseDto.getClientId());
        assertEquals(vpDefinitionResponseDto, responseDto.getPresentationDefinition());
        assertEquals(responseUri, responseDto.getResponseUri());
        assertEquals(nonce, responseDto.getNonce());
        assertTrue(Instant.now().toEpochMilli() >= responseDto.getIssuedAt());
        assertTrue(responseDto.isAcceptVPWithoutHolderProof());
    }
}
package io.inji.verify.dto.dcql;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClaimQueryDtoTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void deserializesValuesAsMixedPrimitiveArray() throws Exception {
        ClaimQueryDto claim = MAPPER.readValue(
                "{\"path\":[\"given_name\"],\"values\":[\"Ada\",42,true]}",
                ClaimQueryDto.class);

        assertEquals(List.of("given_name"), claim.getPath());
        assertEquals(List.of("Ada", 42, true), claim.getValues());
    }

    @Test
    void omitsValuesWhenAbsent() throws Exception {
        ClaimQueryDto claim = MAPPER.readValue(
                "{\"path\":[\"email\"]}",
                ClaimQueryDto.class);

        assertNull(claim.getValues());
    }

    @Test
    void roundTripsIntentToRetainAndOmitsItWhenAbsent() throws Exception {
        ClaimQueryDto retained = MAPPER.readValue(
                "{\"path\":[\"org.iso.18013.5.1\",\"portrait\"],\"intent_to_retain\":true}",
                ClaimQueryDto.class);

        assertEquals(Boolean.TRUE, retained.getIntentToRetain());
        assertTrue(MAPPER.writeValueAsString(retained).contains("\"intent_to_retain\":true"));

        ClaimQueryDto plain = MAPPER.readValue(
                "{\"path\":[\"org.iso.18013.5.1\",\"family_name\"]}",
                ClaimQueryDto.class);
        assertNull(plain.getIntentToRetain());
        assertFalse(MAPPER.writeValueAsString(plain).contains("intent_to_retain"));
    }
}

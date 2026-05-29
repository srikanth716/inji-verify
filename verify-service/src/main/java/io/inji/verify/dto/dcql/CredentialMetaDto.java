package io.inji.verify.dto.dcql;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialMetaDto {

    /**
     * SD-JWT VC vct values
     */
    private List<String> vctValues;

    /**
     * mdoc doctype values
     */
    private List<String> doctypeValues;
}

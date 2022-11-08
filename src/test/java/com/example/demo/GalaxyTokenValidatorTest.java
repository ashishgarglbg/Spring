package com.lbg.iau.securetokenservice.api.validator;

import static com.lbg.iau.securetokenservice.api.TestUtils.getHappyPathToken;
import static com.lbg.iau.securetokenservice.api.service.CryptoServiceFactory.FACTORY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.lbg.iau.securetokenservice.api.TestUtils;
import com.lbg.iau.securetokenservice.api.constant.JsonTags;
import com.lbg.iau.securetokenservice.api.exception.Error;
import com.lbg.iau.securetokenservice.api.service.CryptoServiceKMS;
import lombok.SneakyThrows;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.openam.sts.TokenValidationException;
import org.forgerock.openam.sts.rest.token.validator.RestTokenTransformValidatorResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@Tag("unittest")
@ExtendWith(MockitoExtension.class)
class GalaxyTokenValidatorTest {
  String signedEncryptedJwt = "signedEncryptedJwt";

  @AfterEach
  public void clearMocks() {
    Mockito.reset(FACTORY.getCryptoService());
  }

  @Test
  @SneakyThrows
  void testValidateTokenHappyPath() throws ResourceException {
    try (MockedConstruction<CryptoServiceKMS> ignored =
        Mockito.mockConstruction(CryptoServiceKMS.class)) {
      GalaxyTokenValidator galaxyTokenValidator = new GalaxyTokenValidator();
      when(FACTORY
              .getCryptoService()
              .decryptAndVerify("sessionId", "correlationId", signedEncryptedJwt))
          .thenReturn(getHappyPathToken());
      RestTokenTransformValidatorResult result =
          galaxyTokenValidator.validateToken(
              TestUtils.getValidatorParameters(
                  JsonTags.TOKEN.getJsonTag(), signedEncryptedJwt, "sessionId", "correlationId"));
      assertEquals(
          "https://dp-domain/path/to/jwks",
          ((JwtClaimsSet) result.getAdditionalState().get("decryptedToken").getObject())
              .toJsonValue()
              .get("jwks")
              .getObject()
              .toString());
    }
  }

  @Test
  @SneakyThrows
  void testValidateTokenWithExpiredToken() throws ResourceException {
    try (MockedConstruction<CryptoServiceKMS> ignored =
        Mockito.mockConstruction(CryptoServiceKMS.class)) {
      GalaxyTokenValidator galaxyTokenValidator = new GalaxyTokenValidator();
      when(FACTORY
              .getCryptoService()
              .decryptAndVerify("sessionId", "correlationId", signedEncryptedJwt))
          .thenReturn(TestUtils.getExpiredToken());
      TokenValidationException exception =
          assertThrows(
              TokenValidationException.class,
              () ->
                  galaxyTokenValidator.validateToken(
                      TestUtils.getValidatorParameters(
                          JsonTags.TOKEN.getJsonTag(),
                          signedEncryptedJwt,
                          "sessionId",
                          "correlationId")));
      assertEquals("Forbidden", exception.getReason());
      assertEquals(403, exception.getCode());
      assertEquals("Provided token is expired and will not be processed", exception.getMessage());
      Error error = (Error) exception.getDetail().getObject();
      assertEquals("PROVIDED_TOKEN_ERROR", error.getAuthStatus());
      assertEquals("SECURE_TOKEN_SERVICE_ERR_001", error.getCode());
      assertEquals(0, error.getStatusCode());
      assertEquals("Expired Token", error.getReasonCode());
      assertEquals("Provided token is expired and will not be processed", error.getMessage());
    }
  }

  @Test
  @SneakyThrows
  void testValidateTokenWhenCryptoFailure() throws ResourceException {
    try (MockedConstruction<CryptoServiceKMS> ignored =
        Mockito.mockConstruction(CryptoServiceKMS.class)) {
      GalaxyTokenValidator galaxyTokenValidator = new GalaxyTokenValidator();
      ResourceException cryptoException = Mockito.mock((ResourceException.class));
      when(cryptoException.getMessage()).thenReturn("Can not reach to crypto service");
      when(FACTORY
              .getCryptoService()
              .decryptAndVerify("sessionId", "correlationId", signedEncryptedJwt))
          .thenThrow(cryptoException);
      TokenValidationException exception =
          assertThrows(
              TokenValidationException.class,
              () ->
                  galaxyTokenValidator.validateToken(
                      TestUtils.getValidatorParameters(
                          JsonTags.TOKEN.getJsonTag(),
                          signedEncryptedJwt,
                          "sessionId",
                          "correlationId")));
      assertEquals("Resource Exception", exception.getReason());
      assertEquals(0, exception.getCode());
      assertEquals("Internal Server Error", exception.getMessage());
    }
  }

  @ParameterizedTest
  @SneakyThrows
  @CsvSource(
      value = {
        "null, null, x-lbg-session-id",
        "null, correlationId, x-lbg-session-id",
        "sessionId, null, x-lbg-txn-correlation-id"
      },
      nullValues = {"null"})
  void testValidateTokenForSessionIdAndCorrelationId(
      String sessionId, String correlationId, String expected) throws ResourceException {
    try (MockedConstruction<CryptoServiceKMS> ignored =
        Mockito.mockConstruction(CryptoServiceKMS.class)) {
      GalaxyTokenValidator galaxyTokenValidator = new GalaxyTokenValidator();
      when(FACTORY
              .getCryptoService()
              .decryptAndVerify("sessionId", "correlationId", signedEncryptedJwt))
          .thenReturn(getHappyPathToken());

      TokenValidationException exception =
          assertThrows(
              TokenValidationException.class,
              () ->
                  galaxyTokenValidator.validateToken(
                      TestUtils.getValidatorParameters(
                          JsonTags.TOKEN.getJsonTag(),
                          signedEncryptedJwt,
                          sessionId,
                          correlationId)));
      assertEquals("Resource Exception", exception.getReason());
      assertEquals(0, exception.getCode());
      assertEquals("Missing mandatory header " + expected, exception.getMessage());
    }
  }
}

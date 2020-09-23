package org.sral.keycloak.mappers.mapper;

import org.junit.Test;
import org.keycloak.models.UserSessionModel;
import org.mockito.Mockito;
import org.sral.keycloak.mappers.GWTFixture;

public class WhenUsingPatternAndGroupNumber extends GWTFixture<UserSessionModel> {

    @Override
    protected void Given() {
        super.sut = Mockito.mock(UserSessionModel.class);
    }

    @Override
    protected void When() {
    }

    @Test
    public void ThenXxx() {

    }
}

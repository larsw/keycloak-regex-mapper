package org.sral.keycloak.mappers;

public abstract class GWTFixture<T> {

    protected T sut;

    protected abstract void Given();
    protected abstract void When();


    protected GWTFixture() {
        Given();
        When();
    }
}

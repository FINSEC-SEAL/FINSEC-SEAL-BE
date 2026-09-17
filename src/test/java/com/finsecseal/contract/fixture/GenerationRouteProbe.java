package com.finsecseal.contract.fixture;

/** Unannotated test probe: registered explicitly, never discovered as a controller or invoked. */
public final class GenerationRouteProbe {
    public void generate() {
        throw new AssertionError("Ownership probes must not invoke handlers");
    }
}

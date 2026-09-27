package com.finsecseal.sandbox.tool;

/**
 * Opt-in contract for adapters whose execution always has one server-defined operation.
 * The value describes the adapter's behavior, not a catalog declaration or caller assertion.
 */
public interface FixedOperationToolAdapter extends ToolAdapter {

    String fixedOperation();
}

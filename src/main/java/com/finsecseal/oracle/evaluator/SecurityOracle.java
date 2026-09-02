package com.finsecseal.oracle.evaluator;

import com.finsecseal.oracle.domain.OracleResult;

/** A deterministic, side-effect-free security evidence evaluator. */
@FunctionalInterface
public interface SecurityOracle<E> {
    OracleResult evaluate(E evidence);
}

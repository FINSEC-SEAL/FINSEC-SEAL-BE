package com.finsec.seal.oracle.evaluator;

import com.finsec.seal.oracle.domain.OracleResult;

/** A deterministic, side-effect-free security evidence evaluator. */
@FunctionalInterface
public interface SecurityOracle<E> {
    OracleResult evaluate(E evidence);
}

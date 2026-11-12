/*
 * Copyright 2026 Maalshekto
 * SPDX-License-Identifier: Apache-2.0
 */
package com.pqcops.javacard;

import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Étape 2.1 — tests EXHAUSTIFS de l'arithmétique modulo q.
 *
 * <p>Avec q = 3329, on peut se permettre de tester toutes les entrées possibles :
 * 6 658 valeurs pour csub, 3329² ≈ 11 millions de couples pour add, sub et mul.
 * Aucun cas limite ne peut échapper.
 *
 * <p>Exercice terminé : ces tests font partie de la CI et protègent ModQ pour la suite.
 */
class ModQTest {

    static final int Q = 3329;

    @Test
    @DisplayName("Trou A — csub : [0, 2q) → [0, q)")
    void csub() {
        for (int x = 0; x < 2 * Q; x++) {
            int got = ModQ.csub((short) x);
            int expected = x % Q;
            if (got != expected) {
                fail("csub(" + x + ") = " + got + ", attendu " + expected + " — voir carnet § Trou A");
            }
        }
    }

    @Test
    @DisplayName("add : tous les couples")
    void add() {
        for (int a = 0; a < Q; a++) {
            for (int b = 0; b < Q; b++) {
                int got = ModQ.add((short) a, (short) b);
                if (got != (a + b) % Q) {
                    fail("add(" + a + ", " + b + ") = " + got + ", attendu " + (a + b) % Q
                            + " — add repose sur csub : commencer par le Trou A");
                }
            }
        }
    }

    @Test
    @DisplayName("Trou B — sub : tous les couples")
    void sub() {
        for (int a = 0; a < Q; a++) {
            for (int b = 0; b < Q; b++) {
                int got = ModQ.sub((short) a, (short) b);
                int expected = Math.floorMod(a - b, Q);
                if (got != expected) {
                    fail("sub(" + a + ", " + b + ") = " + got + ", attendu " + expected + " — voir carnet § Trou B");
                }
            }
        }
    }

    @Test
    @DisplayName("Trou C — mul : les 11 millions de couples")
    void mul() {
        for (int a = 0; a < Q; a++) {
            for (int b = 0; b < Q; b++) {
                int got = ModQ.mul((short) a, (short) b);
                int expected = (a * b) % Q;
                if (got != expected) {
                    fail("mul(" + a + ", " + b + ") = " + got + ", attendu " + expected + " — voir carnet § Trou C");
                }
            }
        }
    }
}

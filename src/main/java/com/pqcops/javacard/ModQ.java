/*
 * Copyright 2026 Maalshekto
 * SPDX-License-Identifier: Apache-2.0
 */
package com.pqcops.javacard;

/**
 * Arithmétique modulo q = 3329 (ML-KEM, FIPS 203) avec uniquement des {@code short}.
 *
 * <p>Étape 2.1 du jalon 2 — exercice. Cours, indices et expériences :
 * {@code docs/carnet/etape-2.1-arithmetique-modulaire.md}.
 *
 * <h2>Le problème</h2>
 * Un coefficient de ML-KEM est dans [0, q), donc tient sur 12 bits. Mais le produit de deux
 * coefficients peut atteindre 3328² = 11 075 584, soit 24 bits : il ne tient pas dans un
 * {@code short} (max 32 767), et une carte Java Card classique n'a pas de type {@code int}.
 *
 * <h2>L'idée</h2>
 * Ne jamais calculer le produit complet. On le construit bit par bit (« doubler puis
 * ajouter », comme l'exponentiation rapide de RSA, mais avec des additions), en réduisant
 * modulo q à chaque pas. Invariant : toute valeur intermédiaire reste dans [0, 2q),
 * et 2q = 6 658 tient largement dans un {@code short}.
 *
 * <h2>Contrainte de sécurité</h2>
 * Pas de {@code if} dépendant des données : sur une carte, la durée et la consommation
 * électrique d'un branchement trahissent la valeur testée (attaques par canaux auxiliaires).
 * On utilise des masques à la place.
 *
 * <p>Toutes les méthodes supposent des entrées dans [0, q), sauf mention contraire.
 */
public final class ModQ {

    /** Le module de ML-KEM. */
    public static final short Q = (short) 3329;

    /** Nombre de bits d'un coefficient : q < 2^12. */
    static final short COEFF_BITS = (short) 12;

    private ModQ() {
    }

    /**
     * Réduction conditionnelle : ramène x de [0, 2q) à [0, q), en temps constant.
     *
     * <p>Équivalent mathématique : {@code x >= Q ? x - Q : x}, mais sans branchement.
     *
     * <p>Outils utiles :
     * <ul>
     *   <li>{@code (short) (t >> 15)} vaut 0x0000 si t ≥ 0 et 0xFFFF (= -1) si t &lt; 0 :
     *       le décalage arithmétique recopie le bit de signe dans les 16 bits ;</li>
     *   <li>{@code Q & 0xFFFF} vaut Q, {@code Q & 0x0000} vaut 0.</li>
     * </ul>
     */
    public static short csub(short x) {
        // ===================== TROU A (carnet § Trou A) =====================
        // 1. Soustraire Q à x.
        // 2. Fabriquer un masque à partir du signe du résultat.
        // 3. Rajouter Q seulement si la soustraction a fait passer sous zéro.
        // Trois lignes suffisent. Aucun if, aucun opérateur ternaire.
        short t = (short) (x - Q);
        short mask = (short) (t >> 15);
        return (short) (t + (short) (Q & mask));
        // =====================================================================
    }

    /** Addition modulaire : (a + b) mod q. a + b est dans [0, 2q). */
    public static short add(short a, short b) {
        return csub((short) (a + b));
    }

    /** Soustraction modulaire : (a - b) mod q, en temps constant. */
    public static short sub(short a, short b) {
        // ===================== TROU B (carnet § Trou B) =====================
        // a - b est dans (-q, q) : il peut être négatif, et csub n'accepte que [0, 2q).
        // Une seule ligne, en réutilisant csub.
        return csub((short) (a - b  + Q));
        // =====================================================================
    }

    /**
     * Multiplication modulaire : (a × b) mod q, sans jamais former le produit sur 24 bits.
     *
     * <p>Méthode « doubler puis ajouter », bit de poids fort d'abord. Pour b = 1011 en binaire :
     * <pre>
     *   acc = 0
     *   bit 1 : acc = 2·acc + a        → a
     *   bit 0 : acc = 2·acc            → 2a
     *   bit 1 : acc = 2·acc + a        → 5a
     *   bit 1 : acc = 2·acc + a        → 11a   (= a × 1011₂)
     * </pre>
     * chaque opération étant faite modulo q.
     */

    public static short mul(short a, short b) {
        short acc = 0;
        for (short i = (short) (COEFF_BITS - 1); i >= 0; i--) {
            acc = csub((short) (acc << 1));
            short mask = (short) (-((short) ((short) (b >> i) & 1)));
            acc = add(acc, (short) (a & mask));
            // ===================== TROU C (carnet § Trou C) =====================
            // À chaque tour :
            //   1. doubler acc modulo q ;
            //   2. extraire le bit i de b (0 ou 1) ;
            //   3. ajouter a à acc modulo q SI ce bit vaut 1 — sans if :
            //      transformer le bit en masque 0x0000 / 0xFFFF, puis appliquer le masque à a.
            // Rappel : (short) (-1) = 0xFFFF.
            // =====================================================================
        }
        return acc;
    }
}

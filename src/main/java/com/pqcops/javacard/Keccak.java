/*
 * Copyright 2026 Maalshekto
 * SPDX-License-Identifier: Apache-2.0
 */
package com.pqcops.javacard;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/**
 * Keccak-f[1600] et ses déclinaisons FIPS 202 (SHA3-256, SHA3-512, SHAKE128, SHAKE256),
 * en arithmétique 16 bits uniquement.
 *
 * <h2>Représentation</h2>
 * L'état de 1 600 bits = 25 « lanes » de 64 bits. Java Card classique n'ayant ni {@code long}
 * ni (souvent) {@code int}, chaque lane est stockée sur 4 {@code short}, poids faible d'abord :
 * la lane {@code i} occupe {@code st[4i] .. st[4i+3]}, et {@code st[4i]} contient les bits 0 à 15.
 * L'ordre des octets suit FIPS 202 (petit-boutiste dans chaque lane).
 *
 * <h2>Mémoire</h2>
 * Tout est alloué une fois, en RAM (transient) : état 200 octets, temporaires 56 octets,
 * variables de contexte 8 octets. Total : 264 octets de RAM, aucune écriture en EEPROM
 * pendant le calcul.
 *
 * <h2>Utilisation</h2>
 * {@code init(alg)}, puis {@code absorb(...)} autant de fois que nécessaire, puis
 * {@code squeeze(...)} (plusieurs appels possibles pour SHAKE : sortie de longueur arbitraire).
 */
public final class Keccak {

    public static final byte SHA3_256 = (byte) 0;
    public static final byte SHA3_512 = (byte) 1;
    public static final byte SHAKE128 = (byte) 2;
    public static final byte SHAKE256 = (byte) 3;

    /** Taille des sorties SHA3. */
    public static final short SHA3_256_LENGTH = (short) 32;
    public static final short SHA3_512_LENGTH = (short) 64;

    // Index dans vars[]
    private static final short V_RATE = (short) 0;      // taux en octets (r/8)
    private static final short V_POS = (short) 1;       // position dans le bloc courant
    private static final short V_DOMAIN = (short) 2;    // octet de séparation de domaine
    private static final short V_SQUEEZING = (short) 3; // 0 = absorption, 1 = extraction

    /** Constantes de tour (ι), 4 short par tour, poids faible d'abord. */
    private static final short[] RC = {
        (short) 0x0001, (short) 0x0000, (short) 0x0000, (short) 0x0000,
        (short) 0x8082, (short) 0x0000, (short) 0x0000, (short) 0x0000,
        (short) 0x808A, (short) 0x0000, (short) 0x0000, (short) 0x8000,
        (short) 0x8000, (short) 0x8000, (short) 0x0000, (short) 0x8000,
        (short) 0x808B, (short) 0x0000, (short) 0x0000, (short) 0x0000,
        (short) 0x0001, (short) 0x8000, (short) 0x0000, (short) 0x0000,
        (short) 0x8081, (short) 0x8000, (short) 0x0000, (short) 0x8000,
        (short) 0x8009, (short) 0x0000, (short) 0x0000, (short) 0x8000,
        (short) 0x008A, (short) 0x0000, (short) 0x0000, (short) 0x0000,
        (short) 0x0088, (short) 0x0000, (short) 0x0000, (short) 0x0000,
        (short) 0x8009, (short) 0x8000, (short) 0x0000, (short) 0x0000,
        (short) 0x000A, (short) 0x8000, (short) 0x0000, (short) 0x0000,
        (short) 0x808B, (short) 0x8000, (short) 0x0000, (short) 0x0000,
        (short) 0x008B, (short) 0x0000, (short) 0x0000, (short) 0x8000,
        (short) 0x8089, (short) 0x0000, (short) 0x0000, (short) 0x8000,
        (short) 0x8003, (short) 0x0000, (short) 0x0000, (short) 0x8000,
        (short) 0x8002, (short) 0x0000, (short) 0x0000, (short) 0x8000,
        (short) 0x0080, (short) 0x0000, (short) 0x0000, (short) 0x8000,
        (short) 0x800A, (short) 0x0000, (short) 0x0000, (short) 0x0000,
        (short) 0x000A, (short) 0x8000, (short) 0x0000, (short) 0x8000,
        (short) 0x8081, (short) 0x8000, (short) 0x0000, (short) 0x8000,
        (short) 0x8080, (short) 0x0000, (short) 0x0000, (short) 0x8000,
        (short) 0x0001, (short) 0x8000, (short) 0x0000, (short) 0x0000,
        (short) 0x8008, (short) 0x8000, (short) 0x0000, (short) 0x8000,
    };

    /** ρ et π combinés, parcours en place (formulation « compacte » de Keccak). */
    private static final byte[] ROT = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    };
    private static final byte[] PI_LANE = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    };

    /**
     * Masques pour un décalage logique à droite sur 16 bits : LOW_MASK[n] = 0xFFFF >>> n.
     * Le JCVM et la JVM ne traitent pas {@code >>>} sur un short négatif de la même façon ;
     * {@code (x >> n) & LOW_MASK[n]} donne le même résultat partout.
     */
    private static final short[] LOW_MASK = {
        (short) 0xFFFF, (short) 0x7FFF, (short) 0x3FFF, (short) 0x1FFF,
        (short) 0x0FFF, (short) 0x07FF, (short) 0x03FF, (short) 0x01FF,
        (short) 0x00FF, (short) 0x007F, (short) 0x003F, (short) 0x001F,
        (short) 0x000F, (short) 0x0007, (short) 0x0003, (short) 0x0001,
    };

    private final short[] st;    // 100 short : l'état
    private final short[] tmp;   // 28 short : 5 lanes (θ, χ) + 2 lanes (ρπ)
    private final short[] vars;  // 4 short : contexte

    public Keccak() {
        st = JCSystem.makeTransientShortArray((short) 100, JCSystem.CLEAR_ON_DESELECT);
        tmp = JCSystem.makeTransientShortArray((short) 28, JCSystem.CLEAR_ON_DESELECT);
        vars = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
    }

    // --- API -------------------------------------------------------------------------------

    /** Réinitialise l'état pour l'algorithme indiqué. */
    public void init(byte alg) {
        short rate;
        byte domain;
        switch (alg) {
            case SHA3_256: rate = (short) 136; domain = (byte) 0x06; break;
            case SHA3_512: rate = (short) 72;  domain = (byte) 0x06; break;
            case SHAKE128: rate = (short) 168; domain = (byte) 0x1F; break;
            case SHAKE256: rate = (short) 136; domain = (byte) 0x1F; break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                return;
        }
        clear(st);
        vars[V_RATE] = rate;
        vars[V_POS] = 0;
        vars[V_DOMAIN] = domain;
        vars[V_SQUEEZING] = 0;
    }

    /** Absorbe len octets. Interdit après le début de l'extraction. */
    public void absorb(byte[] in, short off, short len) {
        if (vars[V_SQUEEZING] != 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short rate = vars[V_RATE];
        short pos = vars[V_POS];
        short end = (short) (off + len);
        for (short i = off; i < end; i++) {
            xorByte(pos, in[i]);
            pos++;
            if (pos == rate) {
                permute();
                pos = 0;
            }
        }
        vars[V_POS] = pos;
    }

    /** Produit len octets de sortie. Le premier appel applique le bourrage (pad10*1). */
    public void squeeze(byte[] out, short off, short len) {
        short rate = vars[V_RATE];
        if (vars[V_SQUEEZING] == 0) {
            xorByte(vars[V_POS], (byte) vars[V_DOMAIN]);
            xorByte((short) (rate - 1), (byte) 0x80);
            permute();
            vars[V_POS] = 0;
            vars[V_SQUEEZING] = 1;
        }
        short pos = vars[V_POS];
        short end = (short) (off + len);
        for (short i = off; i < end; i++) {
            if (pos == rate) {
                permute();
                pos = 0;
            }
            out[i] = getByte(pos);
            pos++;
        }
        vars[V_POS] = pos;
    }

    /** Raccourci : init + absorb + squeeze. Renvoie la longueur produite. */
    public short digest(byte alg, byte[] in, short inOff, short inLen, byte[] out, short outOff, short outLen) {
        init(alg);
        absorb(in, inOff, inLen);
        squeeze(out, outOff, outLen);
        return outLen;
    }

    // --- Accès octet par octet à l'état ------------------------------------------------------

    /** XOR d'un octet à la position p (0 ≤ p < 200) : lane p/8, octet p%8 de la lane. */
    private void xorByte(short p, byte b) {
        short idx = (short) (((short) (p >> 3) << 2) + (short) ((p & 7) >> 1));
        short v = (short) (b & 0x00FF);
        if ((p & 1) != 0) {
            v = (short) (v << 8);
        }
        st[idx] ^= v;
    }

    private byte getByte(short p) {
        short w = st[(short) (((short) (p >> 3) << 2) + (short) ((p & 7) >> 1))];
        return (p & 1) == 0 ? (byte) w : (byte) (w >> 8);
    }

    // --- Permutation Keccak-f[1600] ----------------------------------------------------------

    private void permute() {
        short[] a = st;
        short[] t = tmp;
        for (short round = 0; round < 24; round++) {
            // θ : C[x] = XOR des 5 lanes de la colonne x ; A[x,y] ^= C[x-1] ^ rot(C[x+1], 1)
            for (short x = 0; x < 5; x++) {
                for (short w = 0; w < 4; w++) {
                    short i = (short) ((x << 2) + w);
                    t[i] = (short) (a[i] ^ a[(short) (i + 20)] ^ a[(short) (i + 40)]
                            ^ a[(short) (i + 60)] ^ a[(short) (i + 80)]);
                }
            }
            for (short x = 0; x < 5; x++) {
                short prev = (short) (((short) ((short) (x + 4) % 5)) << 2);  // C[x-1]
                short next = (short) (((short) ((short) (x + 1) % 5)) << 2);  // C[x+1]
                for (short w = 0; w < 4; w++) {
                    // rot(C[x+1], 1) mot w = (C[w] << 1) | (C[w-1] >>> 15)
                    short rot = (short) ((short) (t[(short) (next + w)] << 1)
                            | ushr(t[(short) (next + ((short) ((w + 3) & 3)))], (short) 15));
                    short d = (short) (t[(short) (prev + w)] ^ rot);
                    for (short y = 0; y < 100; y += 20) {
                        short i = (short) (y + (x << 2) + w);
                        a[i] ^= d;
                    }
                }
            }

            // ρ et π : on suit le cycle de la permutation π en partant de la lane 1
            copyLane(a, (short) 4, t, (short) 20);              // courant = lane 1
            for (short k = 0; k < 24; k++) {
                short j = (short) (PI_LANE[k] << 2);
                copyLane(a, j, t, (short) 24);                  // sauvegarde de la lane j
                rotl(t, (short) 20, ROT[k], a, j);              // lane j = rot(courant)
                copyLane(t, (short) 24, t, (short) 20);         // courant = ancienne lane j
            }

            // χ : A[x,y] = B[x,y] ^ (~B[x+1,y] & B[x+2,y]), ligne par ligne
            for (short y = 0; y < 100; y += 20) {
                for (short i = 0; i < 20; i++) {
                    t[i] = a[(short) (y + i)];
                }
                for (short x = 0; x < 5; x++) {
                    short x1 = (short) (((short) ((short) (x + 1) % 5)) << 2);
                    short x2 = (short) (((short) ((short) (x + 2) % 5)) << 2);
                    for (short w = 0; w < 4; w++) {
                        a[(short) (y + (x << 2) + w)] = (short) (t[(short) ((x << 2) + w)]
                                ^ (short) (~t[(short) (x1 + w)] & t[(short) (x2 + w)]));
                    }
                }
            }

            // ι
            short rc = (short) (round << 2);
            a[0] ^= RC[rc];
            a[1] ^= RC[(short) (rc + 1)];
            a[2] ^= RC[(short) (rc + 2)];
            a[3] ^= RC[(short) (rc + 3)];
        }
    }

    /** Rotation à gauche d'une lane de 64 bits (4 short) de r bits : dst = src <<< r. */
    private static void rotl(short[] src, short srcOff, byte r, short[] dst, short dstOff) {
        short q = (short) (r >> 4);   // rotation de mots entiers
        short s = (short) (r & 15);   // rotation résiduelle en bits
        for (short w = 0; w < 4; w++) {
            short hi = src[(short) (srcOff + ((short) ((w - q) & 3)))];
            if (s == 0) {
                dst[(short) (dstOff + w)] = hi;
            } else {
                short lo = src[(short) (srcOff + ((short) ((w - q - 1) & 3)))];
                dst[(short) (dstOff + w)] = (short) ((short) (hi << s) | ushr(lo, (short) (16 - s)));
            }
        }
    }

    /** Décalage logique à droite d'un short (identique sur JVM et JCVM). */
    private static short ushr(short x, short n) {
        return (short) ((short) (x >> n) & LOW_MASK[n]);
    }

    private static void copyLane(short[] src, short srcOff, short[] dst, short dstOff) {
        dst[dstOff] = src[srcOff];
        dst[(short) (dstOff + 1)] = src[(short) (srcOff + 1)];
        dst[(short) (dstOff + 2)] = src[(short) (srcOff + 2)];
        dst[(short) (dstOff + 3)] = src[(short) (srcOff + 3)];
    }

    private static void clear(short[] a) {
        for (short i = 0; i < (short) a.length; i++) {
            a[i] = 0;
        }
    }
}

/*
 * Copyright 2026 Maalshekto
 * SPDX-License-Identifier: Apache-2.0
 */
package com.pqcops.javacard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Validation de Keccak exécuté dans l'applet (commande HASH), contre les valeurs de FIPS 202
 * et contre les implémentations de référence du JDK (SHA3) et de BouncyCastle (SHAKE).
 */
class KeccakTest {

    static final AID APPLET_AID = AIDUtil.create("F05051434F505301");

    /** Longueurs de message encadrant les tailles de bloc : 72 (SHA3-512), 136 (SHA3-256, SHAKE256), 168 (SHAKE128). */
    static final int[] MESSAGE_LENGTHS = {
        0, 1, 2, 7, 8, 9, 71, 72, 73, 135, 136, 137, 143, 144, 145, 167, 168, 169,
        271, 272, 273, 335, 336, 337, 503, 504, 505, 1000, 1400, 1534,
    };

    CardSimulator card;

    @BeforeEach
    void setUp() {
        card = new CardSimulator();
        card.installApplet(APPLET_AID, PqcApplet.class);
        card.selectApplet(APPLET_AID);
    }

    // --- Accès à la carte ----------------------------------------------------------------

    byte[] cardHash(int alg, byte[] message, int shakeOutLen) {
        byte[] data = message;
        if (alg >= Keccak.SHAKE128) {
            data = new byte[message.length + 2];
            data[0] = (byte) (shakeOutLen >> 8);
            data[1] = (byte) shakeOutLen;
            System.arraycopy(message, 0, data, 2, message.length);
        }
        ResponseAPDU r = transmit(alg, data);
        assertEquals(0x9000, r.getSW(), "SW pour alg=" + alg + ", longueur=" + message.length);
        return r.getData();
    }

    ResponseAPDU transmit(int p1, byte[] data) {
        return card.transmitCommand(data.length == 0
                ? new CommandAPDU(0x80, 0x10, p1, 0x00, 65536)
                : new CommandAPDU(0x80, 0x10, p1, 0x00, data, 65536));
    }

    // --- Références ----------------------------------------------------------------------

    static byte[] refSha3(String name, byte[] m) throws Exception {
        return MessageDigest.getInstance(name).digest(m);
    }

    static byte[] refShake(int bits, byte[] m, int outLen) {
        SHAKEDigest d = new SHAKEDigest(bits);
        d.update(m, 0, m.length);
        byte[] out = new byte[outLen];
        d.doFinal(out, 0, outLen);
        return out;
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static byte[] random(int len, long seed) {
        byte[] b = new byte[len];
        new Random(seed).nextBytes(b);
        return b;
    }

    // --- Valeurs connues (FIPS 202 / exemples NIST) ------------------------------------------

    @Test
    @DisplayName("Valeurs connues : message vide et « abc »")
    void valeursConnues() {
        byte[] empty = new byte[0];
        byte[] abc = "abc".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
                cardHash(Keccak.SHA3_256, empty, 0));
        assertArrayEquals(hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
                cardHash(Keccak.SHA3_256, abc, 0));
        assertArrayEquals(hex("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                        + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
                cardHash(Keccak.SHA3_512, empty, 0));
        assertArrayEquals(hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
                cardHash(Keccak.SHAKE128, empty, 32));
        assertArrayEquals(hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                        + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"),
                cardHash(Keccak.SHAKE256, empty, 64));
    }

    // --- Tests différentiels ---------------------------------------------------------------

    @Test
    void sha3_256Differentiel() throws Exception {
        for (int len : MESSAGE_LENGTHS) {
            byte[] m = random(len, len);
            assertArrayEquals(refSha3("SHA3-256", m), cardHash(Keccak.SHA3_256, m, 0), "longueur " + len);
        }
    }

    @Test
    void sha3_512Differentiel() throws Exception {
        for (int len : MESSAGE_LENGTHS) {
            byte[] m = random(len, 1000 + len);
            assertArrayEquals(refSha3("SHA3-512", m), cardHash(Keccak.SHA3_512, m, 0), "longueur " + len);
        }
    }

    @ParameterizedTest(name = "SHAKE128, sortie de {0} octets")
    @ValueSource(ints = {1, 16, 32, 167, 168, 169, 336, 337, 504, 1000, 1536})
    void shake128Differentiel(int outLen) {
        for (int len : MESSAGE_LENGTHS) {
            if (len + 2 > PqcApplet.IO_BUFFER_SIZE) {
                continue;
            }
            byte[] m = random(len, 2000 + len);
            assertArrayEquals(refShake(128, m, outLen), cardHash(Keccak.SHAKE128, m, outLen),
                    "message " + len + ", sortie " + outLen);
        }
    }

    @ParameterizedTest(name = "SHAKE256, sortie de {0} octets")
    @ValueSource(ints = {1, 32, 64, 135, 136, 137, 272, 1000, 1536})
    void shake256Differentiel(int outLen) {
        for (int len : MESSAGE_LENGTHS) {
            if (len + 2 > PqcApplet.IO_BUFFER_SIZE) {
                continue;
            }
            byte[] m = random(len, 3000 + len);
            assertArrayEquals(refShake(256, m, outLen), cardHash(Keccak.SHAKE256, m, outLen),
                    "message " + len + ", sortie " + outLen);
        }
    }

    @Test
    @DisplayName("Messages aléatoires : 200 tirages par algorithme")
    void tiragesAleatoires() throws Exception {
        Random rnd = new Random(20261111);
        for (int i = 0; i < 200; i++) {
            byte[] m = random(rnd.nextInt(1200), rnd.nextLong());
            int out = 1 + rnd.nextInt(600);
            assertArrayEquals(refSha3("SHA3-256", m), cardHash(Keccak.SHA3_256, m, 0));
            assertArrayEquals(refSha3("SHA3-512", m), cardHash(Keccak.SHA3_512, m, 0));
            assertArrayEquals(refShake(128, m, out), cardHash(Keccak.SHAKE128, m, out));
            assertArrayEquals(refShake(256, m, out), cardHash(Keccak.SHAKE256, m, out));
        }
    }

    // --- Erreurs ---------------------------------------------------------------------------

    @Test
    void erreurs() {
        assertEquals(0x6A86, transmit(4, new byte[] {1}).getSW(), "algorithme inconnu");
        assertEquals(0x6A86, card.transmitCommand(new CommandAPDU(0x80, 0x10, 0, 1, new byte[] {1}, 256)).getSW(), "P2 ≠ 0");
        assertEquals(0x6700, transmit(Keccak.SHAKE128, new byte[] {0}).getSW(), "longueur de sortie absente");
        assertEquals(0x6A80, transmit(Keccak.SHAKE128, new byte[] {0, 0}).getSW(), "sortie de 0 octet");
        assertEquals(0x6A80, transmit(Keccak.SHAKE256, new byte[] {0x06, 0x01}).getSW(), "sortie > tampon");
    }

    @Test
    void getInfoAnnonceKeccak() {
        ResponseAPDU r = card.transmitCommand(new CommandAPDU(0x80, 0x01, 0, 0, 256));
        assertEquals(PqcApplet.ALGO_KECCAK, r.getData()[6]);
        assertEquals(2, r.getData()[1], "version 0.2");
    }
}

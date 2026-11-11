/*
 * Copyright 2026 Maalshekto
 * SPDX-License-Identifier: Apache-2.0
 */
package com.pqcops.javacard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class PqcAppletTest {

    static final AID APPLET_AID = AIDUtil.create("F05051434F505301");
    static final int EXTENDED_LE = 65536;

    CardSimulator card;

    /** Paramètres d'installation au format GlobalPlatform avec un PIN initial. */
    static byte[] installParams(String pin) {
        byte[] aid = {(byte) 0xF0, 0x50, 0x51, 0x43, 0x4F, 0x50, 0x53, 0x01};
        byte[] p = pin.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(aid.length);
        out.write(aid, 0, aid.length);
        out.write(0);              // pas d'informations de contrôle
        out.write(p.length);
        out.write(p, 0, p.length);
        return out.toByteArray();
    }

    void install(byte[] params) {
        card = new CardSimulator();
        if (params == null) {
            card.installApplet(APPLET_AID, PqcApplet.class);
        } else {
            card.installApplet(APPLET_AID, PqcApplet.class, params, (short) 0, (byte) params.length);
        }
        card.selectApplet(APPLET_AID);
    }

    ResponseAPDU send(int cla, int ins, int p1, int p2, byte[] data) {
        return card.transmitCommand(data == null
                ? new CommandAPDU(cla, ins, p1, p2, 256)
                : new CommandAPDU(cla, ins, p1, p2, data));
    }

    ResponseAPDU verify(String pin) {
        return send(0x00, 0x20, 0x00, 0x80, pin.getBytes(StandardCharsets.US_ASCII));
    }

    ResponseAPDU getInfo() {
        return send(0x80, 0x01, 0x00, 0x00, null);
    }

    @Nested
    @DisplayName("Installation avec PIN fourni")
    class AvecPin {

        @BeforeEach
        void setUp() {
            install(installParams("246810"));
        }

        @Test
        void getInfoRenvoieVersionEtEtat() {
            ResponseAPDU r = getInfo();
            assertEquals(0x9000, r.getSW());
            byte[] d = r.getData();
            assertEquals(7, d.length);
            assertEquals(PqcApplet.VERSION_MAJOR, d[0]);
            assertEquals(PqcApplet.VERSION_MINOR, d[1]);
            assertEquals(0, d[2] & PqcApplet.FLAG_DEFAULT_PIN, "le PIN ne doit pas être celui par défaut");
            assertEquals(3, d[3]);
            assertEquals(PqcApplet.IO_BUFFER_SIZE, ((d[4] & 0xFF) << 8) | (d[5] & 0xFF));
        }

        @Test
        void pinCorrect() {
            assertEquals(0x9000, verify("246810").getSW());
            assertEquals(PqcApplet.FLAG_PIN_VALIDATED, getInfo().getData()[2] & PqcApplet.FLAG_PIN_VALIDATED);
        }

        @Test
        void pinIncorrectDecrementeLesEssais() {
            assertEquals(0x63C2, verify("000000").getSW());
            assertEquals(0x63C2, send(0x00, 0x20, 0x00, 0x80, null).getSW(), "VERIFY sans données");
            assertEquals(0x9000, verify("246810").getSW());
            assertEquals(3, getInfo().getData()[3], "compteur réinitialisé après succès");
        }

        @Test
        void pinBloqueApresTroisEchecs() {
            verify("000000");
            verify("000000");
            assertEquals(0x6983, verify("000000").getSW());
            assertEquals(0x6983, verify("246810").getSW(), "même le bon PIN est refusé");
        }

        @Test
        void changementDePinExigeLaVerification() {
            assertEquals(0x6982, send(0x00, 0x24, 0x00, 0x80, "13579".getBytes(StandardCharsets.US_ASCII)).getSW());
            assertEquals(0x9000, verify("246810").getSW());
            assertEquals(0x9000, send(0x00, 0x24, 0x00, 0x80, "13579".getBytes(StandardCharsets.US_ASCII)).getSW());
            card.selectApplet(APPLET_AID); // la resélection invalide le PIN
            assertEquals(0x63C2, verify("246810").getSW());
            assertEquals(0x9000, verify("13579").getSW());
        }

        @Test
        void longueurDePinInvalideRefusee() {
            verify("246810");
            assertEquals(0x6A80, send(0x00, 0x24, 0x00, 0x80, "123".getBytes(StandardCharsets.US_ASCII)).getSW());
            assertEquals(0x6A80, send(0x00, 0x24, 0x00, 0x80, "123456789".getBytes(StandardCharsets.US_ASCII)).getSW());
        }

        @Test
        void mauvaiseReferenceDePin() {
            assertEquals(0x6A86, send(0x00, 0x20, 0x00, 0x81, "246810".getBytes(StandardCharsets.US_ASCII)).getSW());
        }
    }

    @Nested
    @DisplayName("Installation sans paramètre (laboratoire)")
    class SansPin {

        @BeforeEach
        void setUp() {
            install(null);
        }

        @Test
        void pinParDefautSignale() {
            ResponseAPDU r = getInfo();
            assertEquals(0x9000, r.getSW());
            assertEquals(PqcApplet.FLAG_DEFAULT_PIN, r.getData()[2] & PqcApplet.FLAG_DEFAULT_PIN);
            assertEquals(0x9000, verify("1234").getSW());
        }

        @Test
        void changerLePinRetireLeDrapeau() {
            verify("1234");
            assertEquals(0x9000, send(0x00, 0x24, 0x00, 0x80, "975310".getBytes(StandardCharsets.US_ASCII)).getSW());
            assertEquals(0, getInfo().getData()[2] & PqcApplet.FLAG_DEFAULT_PIN);
        }
    }

    @Nested
    @DisplayName("Protocole et APDU étendus")
    class Protocole {

        @BeforeEach
        void setUp() {
            install(null);
        }

        @Test
        void echoCourt() {
            byte[] data = {1, 2, 3, 4, 5};
            ResponseAPDU r = card.transmitCommand(new CommandAPDU(0x80, 0x02, 0, 0, data, 256));
            assertEquals(0x9000, r.getSW());
            assertArrayEquals(data, r.getData());
        }

        @Test
        @DisplayName("ECHO de 1 184 octets (taille d'une clé ML-KEM-768)")
        void echoEtenduTailleMlKem() {
            byte[] data = new byte[1184];
            new Random(42).nextBytes(data);
            ResponseAPDU r = card.transmitCommand(new CommandAPDU(0x80, 0x02, 0, 0, data, EXTENDED_LE));
            assertEquals(0x9000, r.getSW());
            assertArrayEquals(data, r.getData());
        }

        @Test
        void echoTropLongRefuse() {
            byte[] data = new byte[PqcApplet.IO_BUFFER_SIZE + 1];
            ResponseAPDU r = card.transmitCommand(new CommandAPDU(0x80, 0x02, 0, 0, data, EXTENDED_LE));
            assertEquals(0x6700, r.getSW());
        }

        @Test
        void instructionInconnue() {
            assertEquals(0x6D00, send(0x80, 0x7E, 0, 0, null).getSW());
            assertEquals(0x6D00, send(0x00, 0x7E, 0, 0, null).getSW());
        }

        @Test
        void classeInconnue() {
            assertEquals(0x6E00, send(0x90, 0x01, 0, 0, null).getSW());
        }
    }
}

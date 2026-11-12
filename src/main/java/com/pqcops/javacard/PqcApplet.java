/*
 * Copyright 2026 Maalshekto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.pqcops.javacard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

/**
 * Applet PQC.
 * <ul>
 *   <li>Jalon 0 : socle (PIN, APDU étendus, protocole).</li>
 *   <li>Jalon 1 : Keccak / SHA-3 / SHAKE en 16 bits, exposé par la commande de test HASH.</li>
 * </ul>
 *
 * <p>Contraintes Java Card 3.0.5 respectées volontairement : pas de {@code int}, pas de
 * {@code long}, pas de {@code String}, aucune allocation après l'installation.
 *
 * <p>Protocole : voir le README.
 */
public final class PqcApplet extends Applet implements ExtendedLength {

    // --- Version de l'applet -------------------------------------------------------------
    static final byte VERSION_MAJOR = (byte) 0x00;
    static final byte VERSION_MINOR = (byte) 0x02;

    // --- Classes et instructions -----------------------------------------------------------
    static final byte CLA_ISO = (byte) 0x00;
    static final byte CLA_PROPRIETARY = (byte) 0x80;

    static final byte INS_VERIFY_PIN = (byte) 0x20;   // ISO 7816-4
    static final byte INS_CHANGE_PIN = (byte) 0x24;   // ISO 7816-4 (données = nouveau PIN)
    static final byte INS_GET_INFO = (byte) 0x01;     // propriétaire
    static final byte INS_ECHO = (byte) 0x02;         // propriétaire, test des APDU étendus
    static final byte INS_HASH = (byte) 0x10;         // propriétaire, test de SHA-3 / SHAKE (P1 = algorithme)

    static final byte PIN_REFERENCE = (byte) 0x80;    // P2 des commandes PIN

    // --- PIN -------------------------------------------------------------------------------
    static final byte PIN_TRY_LIMIT = (byte) 3;
    static final byte PIN_MIN_LENGTH = (byte) 4;
    static final byte PIN_MAX_LENGTH = (byte) 8;
    /** PIN de laboratoire, utilisé seulement si aucun PIN n'est fourni à l'installation. */
    private static final byte[] DEFAULT_PIN = {(byte) '1', (byte) '2', (byte) '3', (byte) '4'};

    // --- Champ « flags » de GET INFO ---------------------------------------------------------
    static final byte FLAG_DEFAULT_PIN = (byte) 0x01;
    static final byte FLAG_PIN_VALIDATED = (byte) 0x02;

    // --- Champ « algorithmes » de GET INFO ---------------------------------------------------
    static final byte ALGO_ML_KEM_768 = (byte) 0x01;
    static final byte ALGO_ML_DSA_44 = (byte) 0x02;
    static final byte ALGO_KECCAK = (byte) 0x10;      // SHA3-256, SHA3-512, SHAKE128, SHAKE256

    // --- Tampon d'échange --------------------------------------------------------------------
    /**
     * Taille du tampon d'échange en RAM. Dimensionné pour ML-KEM-768 : clé d'encapsulation
     * de 1 184 octets, chiffré de 1 088 octets. La RAM disponible varie beaucoup d'une carte
     * à l'autre : à réévaluer sur la cible réelle.
     */
    static final short IO_BUFFER_SIZE = (short) 1536;

    static final short SW_PIN_TRIES_REMAINING = (short) 0x63C0;

    private final OwnerPIN pin;
    private final byte[] ioBuffer;
    private final Keccak keccak;
    private boolean defaultPin;

    private PqcApplet(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_LENGTH);
        ioBuffer = JCSystem.makeTransientByteArray(IO_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        keccak = new Keccak();
        initPin(bArray, bOffset, bLength);
    }

    /**
     * Installation. Les paramètres suivent le format GlobalPlatform :
     * [Li AID][AID][Li contrôle][contrôle][Li applet][données applet].
     * Données applet = PIN initial (4 à 8 octets). Absent : PIN de laboratoire « 1234 ».
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new PqcApplet(bArray, bOffset, bLength).register();
    }

    private void initPin(byte[] bArray, short bOffset, byte bLength) {
        short end = (short) (bOffset + (short) (bLength & 0xFF));
        short off = bOffset;
        if (off < end) {
            off = (short) (off + 1 + (short) (bArray[off] & 0xFF));         // AID de l'instance
            if (off < end) {
                off = (short) (off + 1 + (short) (bArray[off] & 0xFF));     // informations de contrôle
                if (off < end) {
                    short len = (short) (bArray[off] & 0xFF);
                    off++;
                    if (len != 0) {
                        if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH || (short) (off + len) > end) {
                            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        }
                        pin.update(bArray, off, (byte) len);
                        defaultPin = false;
                        return;
                    }
                }
            }
        }
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
        defaultPin = true;
    }

    @Override
    public void deselect() {
        pin.reset();
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        byte cla = (byte) (buf[ISO7816.OFFSET_CLA] & (byte) 0xFC); // ignore le canal logique
        byte ins = buf[ISO7816.OFFSET_INS];

        if (cla == CLA_ISO) {
            switch (ins) {
                case INS_VERIFY_PIN:
                    verifyPin(apdu);
                    return;
                case INS_CHANGE_PIN:
                    changePin(apdu);
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else if (cla == CLA_PROPRIETARY) {
            switch (ins) {
                case INS_GET_INFO:
                    getInfo(apdu);
                    return;
                case INS_ECHO:
                    echo(apdu);
                    return;
                case INS_HASH:
                    hash(apdu);
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    // --- Commandes -------------------------------------------------------------------------

    /** GET INFO : version, état du PIN, taille du tampon, algorithmes disponibles. */
    private void getInfo(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte flags = 0;
        if (defaultPin) {
            flags |= FLAG_DEFAULT_PIN;
        }
        if (pin.isValidated()) {
            flags |= FLAG_PIN_VALIDATED;
        }
        buf[0] = VERSION_MAJOR;
        buf[1] = VERSION_MINOR;
        buf[2] = flags;
        buf[3] = pin.getTriesRemaining();
        Util.setShort(buf, (short) 4, IO_BUFFER_SIZE);
        buf[6] = ALGO_KECCAK;
        apdu.setOutgoingAndSend((short) 0, (short) 7);
    }

    /** VERIFY (00 20 00 80). Sans données : renvoie le nombre d'essais restants (63Cx). */
    private void verifyPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        checkPinReference(buf);
        short len = apdu.setIncomingAndReceive();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(ISO7816.SW_FILE_INVALID); // 6983 : PIN bloqué
        }
        if (len == 0) {
            if (pin.isValidated()) {
                return;
            }
            ISOException.throwIt((short) (SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }
        if (len > PIN_MAX_LENGTH
                || !pin.check(buf, apdu.getOffsetCdata(), (byte) len)) {
            if (pin.getTriesRemaining() == 0) {
                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
            }
            ISOException.throwIt((short) (SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }
    }

    /** CHANGE REFERENCE DATA (00 24 00 80), données = nouveau PIN. PIN vérifié requis. */
    private void changePin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        checkPinReference(buf);
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        short len = apdu.setIncomingAndReceive();
        if (len < PIN_MIN_LENGTH || len > PIN_MAX_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        pin.update(buf, apdu.getOffsetCdata(), (byte) len);
        defaultPin = false;
        JCSystem.commitTransaction();
    }

    /** ECHO : renvoie les données reçues. Valide la chaîne APDU étendus de bout en bout. */
    private void echo(APDU apdu) {
        short len = receiveIntoIoBuffer(apdu);
        sendFromIoBuffer(apdu, len);
    }

    /**
     * HASH (80 10 P1 00) — commande de test, sans PIN : à retirer d'une applet de production.
     * P1 = algorithme (0 SHA3-256, 1 SHA3-512, 2 SHAKE128, 3 SHAKE256).
     * Données : message ; pour SHAKE, précédé de la longueur de sortie voulue sur 2 octets.
     */
    private void hash(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte alg = buf[ISO7816.OFFSET_P1];
        if (buf[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        short len = receiveIntoIoBuffer(apdu);
        short msgOff = 0;
        short outLen = 0;
        switch (alg) {
            case Keccak.SHA3_256:
                outLen = Keccak.SHA3_256_LENGTH;
                break;
            case Keccak.SHA3_512:
                outLen = Keccak.SHA3_512_LENGTH;
                break;
            case Keccak.SHAKE128:
            case Keccak.SHAKE256:
                if (len < 2) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                outLen = Util.getShort(ioBuffer, (short) 0);
                if (outLen <= 0 || outLen > IO_BUFFER_SIZE) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                msgOff = 2;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        keccak.init(alg);
        keccak.absorb(ioBuffer, msgOff, (short) (len - msgOff));
        keccak.squeeze(ioBuffer, (short) 0, outLen);  // le message n'est plus utile : on réutilise le tampon
        sendFromIoBuffer(apdu, outLen);
    }

    // --- Utilitaires d'E/S -----------------------------------------------------------------

    private static void checkPinReference(byte[] buf) {
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != PIN_REFERENCE) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /** Reçoit l'intégralité des données de commande (APDU court ou étendu) dans ioBuffer. */
    private short receiveIntoIoBuffer(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short chunk = apdu.setIncomingAndReceive();
        short total = apdu.getIncomingLength();
        if (total > IO_BUFFER_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short dataOffset = apdu.getOffsetCdata();
        short pos = 0;
        while (chunk > 0) {
            Util.arrayCopyNonAtomic(buf, dataOffset, ioBuffer, pos, chunk);
            pos += chunk;
            chunk = apdu.receiveBytes(dataOffset);
        }
        return pos;
    }

    /** Envoie len octets de ioBuffer (APDU étendu si nécessaire). */
    private void sendFromIoBuffer(APDU apdu, short len) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(ioBuffer, (short) 0, len);
    }
}

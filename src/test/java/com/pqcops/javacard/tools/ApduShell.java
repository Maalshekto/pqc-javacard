/*
 * Copyright 2026 Maalshekto
 * SPDX-License-Identifier: Apache-2.0
 */
package com.pqcops.javacard.tools;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.pqcops.javacard.PqcApplet;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Terminal interactif pour dialoguer avec l'applet, sur simulateur (par défaut) ou sur une
 * carte réelle via PC/SC (--pcsc). Lancer avec ./tools/shell.sh ; taper « aide ».
 */
public final class ApduShell {

    static final String APPLET_AID = "F05051434F505301";
    static final int MAX_DISPLAY = 32;

    private final CardTerminal terminal;
    private final boolean interactive;
    private Card card;
    private CardChannel channel;

    private ApduShell(CardTerminal terminal, boolean interactive) throws CardException {
        this.terminal = terminal;
        this.interactive = interactive;
        connect();
    }

    public static void main(String[] args) throws Exception {
        String pin = null;
        boolean pcsc = false;
        for (int i = 0; i < args.length; i++) {
            if ("--pin".equals(args[i]) && i + 1 < args.length) {
                pin = args[++i];
            } else if ("--pcsc".equals(args[i])) {
                pcsc = true;
            } else if (!args[i].isEmpty()) {
                System.err.println("Option inconnue : " + args[i]);
                System.err.println("Usage : shell.sh [--pin <PIN initial>] [--pcsc]");
                System.exit(2);
            }
        }

        CardTerminal terminal;
        if (pcsc) {
            terminal = firstReaderWithCard();
            System.out.println("Lecteur PC/SC : " + terminal.getName());
        } else {
            CardSimulator simulator = new CardSimulator();
            byte[] params = installParams(pin);
            simulator.installApplet(AIDUtil.create(APPLET_AID), PqcApplet.class,
                    params, (short) 0, (byte) params.length);
            terminal = CardTerminalSimulator.terminal(simulator);
            System.out.println("Simulateur jCardSim — applet installée (AID " + APPLET_AID + "), PIN initial : "
                    + (pin == null ? "1234 (par défaut)" : pin));
        }

        boolean interactive = System.console() != null;
        ApduShell shell = new ApduShell(terminal, interactive);
        System.out.println("Tapez « aide » pour la liste des commandes.\n");
        shell.loop();
    }

    // --- Boucle ----------------------------------------------------------------------------

    private void loop() throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        boolean previousWasComment = false;
        while (true) {
            if (interactive) {
                System.out.print("pqc> ");
                System.out.flush();
            }
            String line = in.readLine();
            if (line == null) {
                return;
            }
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            if (line.startsWith("#")) {
                // Commentaire : affiché en mode script pour servir de fil conducteur
                if (!interactive) {
                    System.out.println((previousWasComment ? "" : "\n") + line);
                }
                previousWasComment = true;
                continue;
            }
            previousWasComment = false;
            if (!interactive) {
                System.out.println("pqc> " + line);
            }
            try {
                if (!execute(line)) {
                    return;
                }
            } catch (IllegalArgumentException e) {
                System.out.println("   ! " + e.getMessage());
            } catch (CardException e) {
                System.out.println("   ! Erreur de communication : " + e.getMessage());
            }
        }
    }

    private boolean execute(String line) throws CardException {
        String[] parts = line.split("\\s+", 2);
        String cmd = parts[0].toLowerCase(Locale.ROOT);
        String arg = parts.length > 1 ? parts[1].trim() : "";

        switch (cmd) {
            case "aide":
            case "help":
            case "?":
                printHelp();
                return true;
            case "quitter":
            case "quit":
            case "exit":
                return false;
            case "select":
                send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hex(APPLET_AID), 256));
                return true;
            case "info":
                send(new CommandAPDU(0x80, 0x01, 0x00, 0x00, 256));
                return true;
            case "verify":
                send(arg.isEmpty()
                        ? new CommandAPDU(0x00, 0x20, 0x00, 0x80)
                        : new CommandAPDU(0x00, 0x20, 0x00, 0x80, ascii(arg)));
                return true;
            case "change":
                requireArg(arg, "change <nouveau PIN>");
                send(new CommandAPDU(0x00, 0x24, 0x00, 0x80, ascii(arg)));
                return true;
            case "echo":
                requireArg(arg, "echo <données en hexadécimal>");
                send(new CommandAPDU(0x80, 0x02, 0x00, 0x00, hex(arg), 65536));
                return true;
            case "echo-alea": {
                requireArg(arg, "echo-alea <nombre d'octets>");
                byte[] data = new byte[Integer.parseInt(arg)];
                new SecureRandom().nextBytes(data);
                ResponseAPDU r = send(new CommandAPDU(0x80, 0x02, 0x00, 0x00, data, 65536));
                if (r.getSW() == 0x9000) {
                    System.out.println("   Données renvoyées identiques : "
                            + (java.util.Arrays.equals(data, r.getData()) ? "oui" : "NON"));
                }
                return true;
            }
            case "sha3-256":
                hash(0, 0, arg);
                return true;
            case "sha3-512":
                hash(1, 0, arg);
                return true;
            case "shake128":
            case "shake256": {
                String[] p = arg.split("\\s+", 2);
                requireArg(arg, cmd + " <octets en sortie> <message>");
                int outLen = Integer.parseInt(p[0]);
                hash("shake128".equals(cmd) ? 2 : 3, outLen, p.length > 1 ? p[1] : "");
                return true;
            }
            case "reset":
                card.disconnect(true);
                connect();
                System.out.println("   Carte réinitialisée (mise hors tension puis sous tension). ATR : "
                        + toHex(card.getATR().getBytes(), Integer.MAX_VALUE));
                return true;
            case "apdu":
                requireArg(arg, "apdu <APDU complet en hexadécimal>");
                send(new CommandAPDU(hex(arg)));
                return true;
            default:
                if (line.matches("[0-9A-Fa-f\\s:]+")) {
                    send(new CommandAPDU(hex(line)));
                    return true;
                }
                throw new IllegalArgumentException("Commande inconnue : " + cmd + " (tapez « aide »)");
        }
    }

    /**
     * HASH sur la carte, puis comparaison avec une implémentation de référence.
     * Message : "texte entre guillemets" ou hexadécimal (vide autorisé).
     */
    private void hash(int alg, int shakeOutLen, String arg) throws CardException {
        byte[] message = parseMessage(arg);
        byte[] data = message;
        if (alg >= 2) {
            if (shakeOutLen <= 0 || shakeOutLen > 0xFFFF) {
                throw new IllegalArgumentException("Longueur de sortie invalide : " + shakeOutLen);
            }
            data = new byte[message.length + 2];
            data[0] = (byte) (shakeOutLen >> 8);
            data[1] = (byte) shakeOutLen;
            System.arraycopy(message, 0, data, 2, message.length);
        }
        System.out.println("   Message : " + message.length + " octet(s)");
        ResponseAPDU r = send(data.length == 0
                ? new CommandAPDU(0x80, 0x10, alg, 0x00, 65536)
                : new CommandAPDU(0x80, 0x10, alg, 0x00, data, 65536));
        if (r.getSW() != 0x9000) {
            return;
        }
        byte[] ref = reference(alg, message, shakeOutLen);
        System.out.println("   Empreinte : " + toHex(r.getData(), Integer.MAX_VALUE).replace(" ", "").toLowerCase(Locale.ROOT));
        System.out.println("   Référence (" + (alg < 2 ? "JDK" : "BouncyCastle") + ") : "
                + (java.util.Arrays.equals(ref, r.getData()) ? "identique ✔" : "DIFFÉRENTE ✘ "
                + toHex(ref, Integer.MAX_VALUE)));
    }

    private static byte[] reference(int alg, byte[] m, int outLen) {
        try {
            switch (alg) {
                case 0: return MessageDigest.getInstance("SHA3-256").digest(m);
                case 1: return MessageDigest.getInstance("SHA3-512").digest(m);
                default:
                    SHAKEDigest d = new SHAKEDigest(alg == 2 ? 128 : 256);
                    d.update(m, 0, m.length);
                    byte[] out = new byte[outLen];
                    d.doFinal(out, 0, outLen);
                    return out;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] parseMessage(String arg) {
        if (arg.length() >= 2 && arg.startsWith("\"") && arg.endsWith("\"")) {
            return arg.substring(1, arg.length() - 1).getBytes(StandardCharsets.UTF_8);
        }
        return hex(arg);
    }

    // --- Émission et affichage -----------------------------------------------------------

    private ResponseAPDU send(CommandAPDU command) throws CardException {
        System.out.println("   >> " + toHex(command.getBytes(), MAX_DISPLAY));
        System.out.println("      " + describeCommand(command));
        long start = System.nanoTime();
        ResponseAPDU response = channel.transmit(command);
        long micros = (System.nanoTime() - start) / 1000;
        byte[] data = response.getData();
        System.out.println("   << " + (data.length == 0 ? "" : toHex(data, MAX_DISPLAY) + "  ")
                + String.format("SW=%04X", response.getSW())
                + (data.length > 0 ? "  (" + data.length + " octets)" : "")
                + String.format("  [%d,%03d ms]", micros / 1000, micros % 1000));
        System.out.println("      " + describeStatus(response.getSW()));
        if (command.getCLA() == 0x80 && command.getINS() == 0x01 && response.getSW() == 0x9000) {
            describeInfo(data);
        }
        return response;
    }

    private static String describeCommand(CommandAPDU c) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("CLA=%02X INS=%02X P1=%02X P2=%02X", c.getCLA(), c.getINS(), c.getP1(), c.getP2()));
        if (c.getNc() > 0) {
            sb.append("  Lc=").append(c.getNc());
        }
        if (c.getNe() > 0) {
            sb.append("  Le=").append(c.getNe());
        }
        int shortLength = 4 + (c.getNc() > 0 ? 1 + c.getNc() : 0) + (c.getNe() > 0 ? 1 : 0);
        if (c.getBytes().length > shortLength) {
            sb.append("  [APDU étendu]");
        }
        String name = commandName(c);
        if (name != null) {
            sb.append("  → ").append(name);
        }
        return sb.toString();
    }

    private static String commandName(CommandAPDU c) {
        int cla = c.getCLA() & 0xFC;
        int ins = c.getINS();
        if (cla == 0x00 && ins == 0xA4) {
            return "SELECT (sélection d'applet par AID)";
        }
        if (cla == 0x00 && ins == 0x20) {
            return c.getNc() == 0 ? "VERIFY (interroger le compteur d'essais)" : "VERIFY (présenter le PIN)";
        }
        if (cla == 0x00 && ins == 0x24) {
            return "CHANGE REFERENCE DATA (changer le PIN)";
        }
        if (cla == 0x80 && ins == 0x01) {
            return "GET INFO";
        }
        if (cla == 0x80 && ins == 0x02) {
            return "ECHO";
        }
        if (cla == 0x80 && ins == 0x10) {
            String[] names = {"SHA3-256", "SHA3-512", "SHAKE128", "SHAKE256"};
            return "HASH " + (c.getP1() < names.length ? names[c.getP1()] : "(algorithme inconnu)");
        }
        return null;
    }

    static String describeStatus(int sw) {
        if ((sw & 0xFFF0) == 0x63C0) {
            return "PIN incorrect — " + (sw & 0x0F) + " essai(s) restant(s)";
        }
        switch (sw) {
            case 0x9000: return "Succès";
            case 0x6700: return "Longueur incorrecte (données trop longues pour le tampon ?)";
            case 0x6982: return "Conditions de sécurité non satisfaites (PIN non vérifié)";
            case 0x6983: return "PIN bloqué";
            case 0x6986: return "Commande non autorisée (aucune applet sélectionnée ?)";
            case 0x6999: return "Échec de la sélection";
            case 0x6A80: return "Données incorrectes (longueur de PIN invalide ?)";
            case 0x6A82: return "Applet ou fichier introuvable";
            case 0x6A86: return "P1/P2 incorrects";
            case 0x6D00: return "Instruction (INS) non prise en charge";
            case 0x6E00: return "Classe (CLA) non prise en charge";
            case 0x6F00: return "Erreur interne de l'applet";
            default: return "Code de statut non répertorié";
        }
    }

    private static void describeInfo(byte[] d) {
        if (d.length < 7) {
            return;
        }
        int flags = d[2] & 0xFF;
        int algos = d[6] & 0xFF;
        String algoNames = algos == 0 ? "aucun" : ((algos & 1) != 0 ? "ML-KEM-768 " : "")
                + ((algos & 2) != 0 ? "ML-DSA-44 " : "") + ((algos & 0x10) != 0 ? "SHA-3/SHAKE" : "");
        System.out.println("      Version " + (d[0] & 0xFF) + "." + (d[1] & 0xFF)
                + " | PIN par défaut : " + ((flags & 0x01) != 0 ? "OUI (à changer)" : "non")
                + " | PIN vérifié : " + ((flags & 0x02) != 0 ? "oui" : "non")
                + " | essais restants : " + (d[3] & 0xFF)
                + " | tampon : " + (((d[4] & 0xFF) << 8) | (d[5] & 0xFF)) + " octets"
                + " | algorithmes : " + algoNames.trim());
    }

    private static void printHelp() {
        System.out.println(String.join("\n",
                "  select              Sélectionner l'applet (obligatoire avant toute autre commande)",
                "  info                GET INFO : version, état du PIN, tampon, algorithmes",
                "  verify [PIN]        Présenter le PIN ; sans argument : nombre d'essais restants",
                "  change <PIN>        Changer le PIN (4 à 8 caractères, PIN vérifié requis)",
                "  echo <hex>          Envoyer des données et les recevoir en retour",
                "  echo-alea <n>       ECHO de n octets aléatoires (ex. 1184 = clé ML-KEM-768)",
                "  sha3-256 <msg>      Empreinte SHA3-256 calculée par la carte (msg : \"texte\" ou hexadécimal)",
                "  sha3-512 <msg>      Empreinte SHA3-512",
                "  shake128 <n> <msg>  SHAKE128, n octets en sortie",
                "  shake256 <n> <msg>  SHAKE256, n octets en sortie",
                "  reset               Réinitialiser la carte (coupure d'alimentation)",
                "  apdu <hex>          Envoyer un APDU brut (ou taper directement l'hexadécimal)",
                "  aide                Cette aide",
                "  quitter             Sortir",
                "",
                "  Exemple d'APDU brut : 80 01 00 00 00   (= info)"));
    }

    // --- Connexion -------------------------------------------------------------------------

    private void connect() throws CardException {
        card = terminal.connect("*");
        channel = card.getBasicChannel();
    }

    private static CardTerminal firstReaderWithCard() throws CardException {
        CardTerminals terminals = TerminalFactory.getDefault().terminals();
        List<CardTerminal> withCard = terminals.list(CardTerminals.State.CARD_PRESENT);
        if (withCard.isEmpty()) {
            throw new CardException("Aucun lecteur PC/SC avec une carte insérée.");
        }
        return withCard.get(0);
    }

    static byte[] installParams(String pin) {
        byte[] aid = hex(APPLET_AID);
        byte[] p = pin == null ? new byte[0] : ascii(pin);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(aid.length);
        out.write(aid, 0, aid.length);
        out.write(0);
        out.write(p.length);
        out.write(p, 0, p.length);
        return out.toByteArray();
    }

    // --- Utilitaires -----------------------------------------------------------------------

    private static void requireArg(String arg, String usage) {
        if (arg.isEmpty()) {
            throw new IllegalArgumentException("Usage : " + usage);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] hex(String s) {
        String clean = s.replaceAll("[\\s:]", "");
        if (clean.length() % 2 != 0 || !clean.matches("[0-9A-Fa-f]*")) {
            throw new IllegalArgumentException("Hexadécimal invalide : " + s);
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String toHex(byte[] b, int max) {
        StringBuilder sb = new StringBuilder();
        int n = Math.min(b.length, max);
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", b[i] & 0xFF));
        }
        if (b.length > max) {
            sb.append(" …");
        }
        return sb.toString();
    }
}

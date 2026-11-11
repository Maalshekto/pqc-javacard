# pqc-javacard

Applet **Java Card** de cryptographie post-quantique — prototype pédagogique du projet [PQC-Ops](https://pqc-ops.com/).

Objectif : montrer ce qu'implique ML-KEM et ML-DSA sur une carte à puce (RAM de quelques Ko, arithmétique 16 bits, APDU étendus, temps d'exécution) et construire une mini-PKI dont la clé privée reste dans la carte.

> [!WARNING]
> **Prototype de recherche et d'enseignement. Ne pas utiliser en production.**
> L'implémentation ne comporte aucune contre-mesure contre les attaques physiques (canaux auxiliaires, injection de fautes), indispensables sur une carte réelle. Elle n'est ni évaluée ni certifiée.

## Feuille de route

| Jalon | Contenu | État |
|---|---|---|
| 0 | Socle : protocole APDU, PIN, APDU étendus, tests jCardSim, conversion `.cap` | ✅ |
| 1 | Keccak-f[1600] en 16 bits : SHA3-256, SHA3-512, SHAKE128, SHAKE256 (vecteurs NIST) | ⏳ |
| 2 | ML-KEM-768 : NTT modulo 3329, génération de clés et décapsulation sur la carte ; encapsulation côté hôte | ⏳ |
| 3 | Interopérabilité : vecteurs ACVP du NIST, croisement avec BouncyCastle et OpenSSL 3.5 | ⏳ |
| 4 | ML-DSA-44 : arithmétique modulo 8 380 417 émulée en 16 bits, signature sur la carte | ⏳ |
| 5 | PKI : CSR signée par la carte, AC OpenSSL 3.5, certificat stocké sur la carte | ⏳ |
| 6 | Carte réelle : chargement GlobalPlatformPro, mesures de temps et de mémoire | ⏳ |

## Prérequis

- JDK 11 (`sudo apt install openjdk-11-jdk`)
- Maven 3.6+ (`sudo apt install maven`)
- git, curl

## Démarrage

```bash
./tools/bootstrap.sh   # une seule fois : kit Java Card 3.0.5u4, jCardSim, ant-javacard → .tools/
mvn verify             # tests sur simulateur + conversion en target/pqc-javacard.cap
```

`bootstrap.sh` compile jCardSim depuis ses sources (il n'est pas publié sur Maven Central) et l'installe dans le dépôt Maven local. Toutes les versions sont épinglées.

La **conversion `.cap`** n'est pas une formalité : jCardSim exécute l'applet sur une JVM normale et accepterait du code qu'aucune carte n'exécute (`int`, `long`, `String`, allocations dynamiques). Seul le convertisseur Java Card détecte ces erreurs. Elle est donc exécutée à chaque `mvn verify` et en CI.

## Protocole APDU

AID du paquetage : `F05051434F5053` — AID de l'applet : `F05051434F505301` (RID `F0` : catégorie propriétaire non enregistrée).

| Commande | CLA | INS | P1 | P2 | Données | Réponse |
|---|---|---|---|---|---|---|
| VERIFY | `00` | `20` | `00` | `80` | PIN (4 à 8 octets) ; vide = interroger le compteur | `9000`, `63Cx` (x essais restants), `6983` (bloqué) |
| CHANGE PIN | `00` | `24` | `00` | `80` | Nouveau PIN (PIN vérifié requis) | `9000`, `6982`, `6A80` |
| GET INFO | `80` | `01` | `00` | `00` | — | 7 octets : version (2), drapeaux (1), essais PIN (1), taille du tampon (2), algorithmes (1) |
| ECHO | `80` | `02` | `00` | `00` | 0 à 1 536 octets | Les mêmes données (test des APDU étendus) |

Drapeaux de GET INFO : bit 0 = PIN de laboratoire par défaut (`1234`) toujours actif, bit 1 = PIN vérifié.

**Installation** : les données d'applet (format GlobalPlatform) contiennent le PIN initial. Sans PIN fourni, le PIN de laboratoire `1234` est utilisé et signalé par GET INFO.

## Contraintes de codage (Java Card 3.0.5 classique)

- Types : `byte`, `short`, `boolean` et tableaux de ces types uniquement. Pas de `int` : de nombreuses cartes ne le prennent pas en charge.
- Aucune allocation hors du constructeur : tout est alloué à l'installation.
- Tampons temporaires en RAM via `JCSystem.makeTransientByteArray`.
- Écritures persistantes groupées et protégées par transaction.

## Licence

[Apache 2.0](LICENSE)

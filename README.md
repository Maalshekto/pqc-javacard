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
| 1 | Keccak-f[1600] en 16 bits : SHA3-256, SHA3-512, SHAKE128, SHAKE256 (vecteurs NIST) | ✅ |
| 2 | ML-KEM-768 : NTT modulo 3329, génération de clés et décapsulation sur la carte ; encapsulation côté hôte | ⏳ |
| 3 | Interopérabilité : vecteurs ACVP du NIST, croisement avec BouncyCastle et OpenSSL 3.5 | ⏳ |
| 4 | ML-DSA-44 : arithmétique modulo 8 380 417 émulée en 16 bits, signature sur la carte | ⏳ |
| 5 | PKI : CSR signée par la carte, AC OpenSSL 3.5, certificat stocké sur la carte | ⏳ |
| 6 | Carte réelle : chargement GlobalPlatformPro, mesures de temps et de mémoire | ⏳ |
| 7 | Signature de firmware LMS/HSS (NIST SP 800-208, variante SHAKE256) : état atomique, cérémonie à double contrôle, un sous-arbre par carte | ⏳ |

### Jalon 7 — signature de firmware LMS/HSS

La signature de firmware est la première priorité du CNSA 2.0 : un équipement déployé vérifiera encore des mises à jour dans 15 à 20 ans. Pour ce cas d'usage, on recommande des signatures **à base de hachage avec état** (LMS, XMSS), et non ML-DSA. Le jalon s'inspire d'une applet de signature de firmware RSA de 2010, avec double contrôle, que l'on refait en version post-quantique.

- **Ce qui est déjà là** : SHAKE256 (jalon 1). SP 800-208 définit des jeux de paramètres LMS et LM-OTS basés sur SHAKE256.
- **Signataire (la carte)** : l'indice de la prochaine clé à usage unique est mis à jour **avant** que la signature sorte de la carte, dans une transaction atomique (`JCSystem.beginTransaction`). Un indice ne doit jamais être réutilisé, même après un arrachement de la carte.
- **Pas de clonage de clé** : la sauvegarde ne passe pas par la copie de la clé privée. Avec HSS, l'arbre racine signe **un sous-arbre distinct par carte**, carte de secours comprise ; l'état est donc partitionné. *(À vérifier dans le texte de SP 800-208 : exigences sur la non-exportation de la clé privée.)*
- **Cérémonie d'initialisation** : double contrôle (deux dépositaires par rôle), séparation des rôles administrateur et signataire imposée par la carte. Les secrets de sauvegarde sont des composantes à pleine entropie, combinées par XOR ou par partage de Shamir, et jamais dérivées d'un PIN.
- **La carte signe une empreinte** calculée par l'hôte, après un contrôle strict de sa longueur.
- **Vérificateur** : côté hôte (Java ou OpenSSL), puis éventuellement sur un petit microcontrôleur. La vérification LMS ne demande que des hachages.
- **Mesures** : temps de génération de l'arbre (borne sur sa hauteur), nombre de signatures disponibles, comparaison avec RSA-2048 sur coprocesseur.

Ce jalon peut être traité dès la fin du jalon 2 : il ne dépend que de SHAKE256.

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

## Apprendre : exercices à trous

À partir du jalon 2, certaines lignes clés sont laissées **à écrire** : là où l'algorithme se comprend en le faisant. Chaque étape a :

- un **carnet** dans `docs/carnet/` : cours, trous, indices progressifs, expériences, questions ;
- des **tests d'exercice** (tagués `exercice`, exclus de la CI tant que les trous ne sont pas remplis) ;
- un **corrigé vérifié** dans `docs/corriges/`.

```bash
mvn -q test -Pexercices -Dtest=ModQTest   # étape 2.1 : arithmétique modulo q
```

| Étape | Carnet | État |
|---|---|---|
| 2.1 | [Arithmétique modulo q sans `int`](docs/carnet/etape-2.1-arithmetique-modulaire.md) | à faire |

## Utiliser l'applet

Un terminal APDU interactif dialogue avec l'applet sur le simulateur, via l'API standard `javax.smartcardio` :

```bash
./tools/shell.sh                     # PIN de laboratoire 1234
./tools/shell.sh --pin 246810        # PIN initial fourni à l'installation
./tools/shell.sh < tools/demo.apdu   # visite guidée commentée
./tools/shell.sh --pcsc              # carte réelle sur le premier lecteur PC/SC (applet déjà chargée)
```

Commandes : `select`, `info`, `verify [PIN]`, `change <PIN>`, `echo <hex>`, `echo-alea <n>`, `reset`, `aide`, `quitter`, ou un APDU brut tapé en hexadécimal (`80 01 00 00 00`). Chaque échange est affiché octet par octet, avec le découpage CLA/INS/P1/P2/Lc/Le et la signification du code de statut.

Les lignes « Trying to load an instance of com.licel.globalplatform… » viennent de jCardSim et sont sans conséquence.

## Protocole APDU

AID du paquetage : `F05051434F5053` — AID de l'applet : `F05051434F505301` (RID `F0` : catégorie propriétaire non enregistrée).

| Commande | CLA | INS | P1 | P2 | Données | Réponse |
|---|---|---|---|---|---|---|
| VERIFY | `00` | `20` | `00` | `80` | PIN (4 à 8 octets) ; vide = interroger le compteur | `9000`, `63Cx` (x essais restants), `6983` (bloqué) |
| CHANGE PIN | `00` | `24` | `00` | `80` | Nouveau PIN (PIN vérifié requis) | `9000`, `6982`, `6A80` |
| GET INFO | `80` | `01` | `00` | `00` | — | 7 octets : version (2), drapeaux (1), essais PIN (1), taille du tampon (2), algorithmes (1) |
| ECHO | `80` | `02` | `00` | `00` | 0 à 1 536 octets | Les mêmes données (test des APDU étendus) |
| HASH *(test)* | `80` | `10` | algo | `00` | SHA3 : message. SHAKE : longueur de sortie (2 octets) + message | Empreinte : 32 o (SHA3-256), 64 o (SHA3-512), longueur demandée (SHAKE) |

Algorithmes de HASH (P1) : `00` SHA3-256, `01` SHA3-512, `02` SHAKE128, `03` SHAKE256. Cette commande sert à valider Keccak ; elle n'exige pas de PIN et serait retirée d'une applet de production.

Drapeaux de GET INFO : bit 0 = PIN de laboratoire par défaut (`1234`) toujours actif, bit 1 = PIN vérifié.
Algorithmes de GET INFO : bit 0 = ML-KEM-768, bit 1 = ML-DSA-44, bit 4 = SHA-3/SHAKE.

**Installation** : les données d'applet (format GlobalPlatform) contiennent le PIN initial. Sans PIN fourni, le PIN de laboratoire `1234` est utilisé et signalé par GET INFO.

## Notes d'implémentation

### Keccak en 16 bits (`Keccak.java`)

- Chaque lane de 64 bits est stockée sur **4 `short`**, poids faible d'abord. Une rotation de *r* bits se décompose en une rotation de *r* / 16 mots entiers, puis un décalage de *r* mod 16 bits propagé d'un mot à l'autre.
- Le décalage logique à droite (`>>>`) n'a pas la même sémantique sur un `short` négatif en Java et sur la machine virtuelle Java Card : il est remplacé par `(x >> n) & masque`.
- ρ et π sont fusionnées et appliquées **en place** en suivant le cycle de la permutation, ce qui évite un second état de 200 octets.
- **RAM utilisée : 264 octets** (état 200 o, temporaires 56 o, contexte 8 o), sans aucune écriture en EEPROM pendant le calcul.
- Validation : valeurs connues de FIPS 202, puis comparaison différentielle avec le JDK (SHA3) et BouncyCastle (SHAKE) sur des messages de 0 à 1 534 octets encadrant chaque frontière de bloc (72, 136, 168 octets), plus 200 tirages aléatoires par algorithme.

## Contraintes de codage (Java Card 3.0.5 classique)

- Types : `byte`, `short`, `boolean` et tableaux de ces types uniquement. Pas de `int` : de nombreuses cartes ne le prennent pas en charge.
- Aucune allocation hors du constructeur : tout est alloué à l'installation.
- Tampons temporaires en RAM via `JCSystem.makeTransientByteArray`.
- Écritures persistantes groupées et protégées par transaction.
- Les calculs intermédiaires doivent pouvoir se faire sur 16 bits. Le convertisseur refuse par exemple `(x + 4) % 5`, car `x + 4` est un `int` en Java et le reste dépend des bits de poids fort. Il faut écrire `(short) (x + 4) % 5`.

## Licence

[Apache 2.0](LICENSE)

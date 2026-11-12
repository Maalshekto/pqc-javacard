# Étape 2.1 — Arithmétique modulo q sans `int`

> **Objectif** : savoir additionner, soustraire et multiplier des coefficients de ML-KEM modulo q = 3329 sur une carte qui ne connaît que des entiers 16 bits, **en temps constant**.
>
> **Fichiers** : `src/main/java/com/pqcops/javacard/ModQ.java` (3 trous) · `src/test/java/com/pqcops/javacard/ModQTest.java` (tests exhaustifs) · corrigé : `docs/corriges/etape-2.1.md` (à n'ouvrir qu'après avoir essayé).

## 1. Comprendre

### Pourquoi q = 3329 ?

ML-KEM manipule des polynômes de 256 coefficients, chacun pris modulo q = 3329. Ce nombre n'est pas choisi au hasard : c'est un nombre premier tel que **q − 1 = 3328 = 2⁸ × 13** soit divisible par 256. Cette propriété garantit l'existence de racines 256ᵉ de l'unité modulo q, condition nécessaire à la **NTT** (étape 2.2), qui rend la multiplication de polynômes rapide.

### Le problème sur carte

| Valeur | Taille | Tient dans un `short` (−32 768 … 32 767) ? |
|---|---|---|
| Un coefficient, dans [0, 3329) | 12 bits | ✔ |
| La somme de deux coefficients, < 6 658 | 13 bits | ✔ |
| Le produit de deux coefficients, jusqu'à 3328² = 11 075 584 | 24 bits | ✘ |

Sur un PC, on écrirait `(a * b) % q` en `int`. Sur une carte Java Card classique, `int` n'existe pas (ou en option).

### L'idée : doubler puis ajouter

C'est l'algorithme de l'exponentiation rapide utilisée par RSA (« élever au carré puis multiplier »), transposé à la multiplication : **on doublera et on ajoutera**.

Pour calculer a × b, on parcourt les bits de b du poids fort au poids faible :

```
b = 1011₂ = 11
acc = 0
bit 1 → acc = 2·0  + a = a
bit 0 → acc = 2·a      = 2a
bit 1 → acc = 2·2a + a = 5a
bit 1 → acc = 2·5a + a = 11a  ✔
```

Si **chaque** opération est réduite modulo q, `acc` reste toujours dans [0, q). Il ne dépasse jamais 2q = 6 658 avant réduction, et tout tient sur 16 bits. Comme b < 2¹², douze tours suffisent.

### La contrainte de temps constant

Sur une carte à puce, un attaquant peut **mesurer la consommation électrique** pendant le calcul. Un `if (bit == 1) acc += a;` exécute du code différent selon la valeur du bit : la trace de consommation révèle alors b, bit par bit. C'est une **analyse simple de consommation** (*Simple Power Analysis*, SPA), une attaque historique contre RSA sur carte, exactement sur ce schéma.

La parade : exécuter **toujours les mêmes instructions**, et faire disparaître la valeur indésirable avec un **masque** :

| Bit | Masque `(short) -bit` | `a & masque` |
|---|---|---|
| 0 | `0x0000` | 0 (on ajoute zéro) |
| 1 | `0xFFFF` | a (on ajoute a) |

Même idée pour la réduction conditionnelle (`csub`) : on soustrait q **toujours**, puis on rajoute q **masqué** selon le signe du résultat.

### Le décalage arithmétique, outil clé

`t >> 15` sur un `short` recopie le bit de signe dans tous les bits :

```
t =  1234  = 0000 0100 1101 0010   →  t >> 15 = 0000 0000 0000 0000 = 0
t = -1234  = 1111 1011 0010 1110   →  t >> 15 = 1111 1111 1111 1111 = -1 = 0xFFFF
```

C'est un masque « t est négatif » sans aucun branchement.

## 2. Les trous

Commence par lancer les tests pour voir l'état de départ :

```bash
mvn -q test -Pexercices -Dtest=ModQTest
```

Les quatre tests échouent, avec un message indiquant le trou concerné. Remplis-les **dans l'ordre** : `add` dépend de `csub`, et `mul` dépend des deux.

### Trou A — `csub` : réduction conditionnelle

Ramener x ∈ [0, 2q) dans [0, q), en trois lignes, sans `if`.

<details><summary>Indice 1</summary>

Calcule `t = x - Q`. Si x < q, t est négatif et il faut « annuler » la soustraction ; sinon t est déjà le bon résultat.
</details>

<details><summary>Indice 2</summary>

`(short) (t >> 15)` vaut 0 ou −1 selon le signe de t. Que vaut `Q & ce masque` dans chacun des deux cas ?
</details>

<details><summary>Indice 3 (presque la solution)</summary>

Le résultat est `t + (Q & masque)`. N'oublie pas les casts `(short)` : en Java, `t + (Q & masque)` est un `int`.
</details>

### Trou B — `sub` : soustraction modulaire

`a - b` est dans (−q, q). `csub` n'accepte que [0, 2q).

<details><summary>Indice</summary>

Que faut-il ajouter à `a - b` pour qu'il tombe toujours dans [0, 2q) sans changer sa valeur modulo q ?
</details>

### Trou C — `mul` : le corps de la boucle

Trois étapes à chaque tour : doubler `acc` modulo q, extraire le bit i de b, ajouter a si ce bit vaut 1, sans `if`.

<details><summary>Indice 1 — doubler</summary>

`acc << 1` vaut 2·acc, dans [0, 2q). Quelle fonction ramène ça dans [0, q) ?
</details>

<details><summary>Indice 2 — extraire le bit</summary>

`(b >> i) & 1` donne le bit i de b. Attention aux casts : chaque sous-expression doit être ramenée en `short`, sinon le convertisseur Java Card refusera le code (voir l'erreur `unsupported int type of intermediate value` du jalon 1).
</details>

<details><summary>Indice 3 — ajouter sans if</summary>

`(short) -bit` donne le masque. `a & masque` vaut a ou 0. Ensuite, `add`.
</details>

Quand les quatre tests passent, vérifie que le code est aussi **valide sur carte** :

```bash
mvn -q package -DskipTests      # doit produire target/pqc-javacard.cap sans erreur [convert]
```

## 3. Expériences

**3.1 — Manipuler en direct avec jshell.** `ModQ` ne dépend d'aucune classe Java Card : on peut l'appeler depuis le shell Java interactif.

```bash
mvn -q compile
jshell --class-path target/classes
jshell> import com.pqcops.javacard.ModQ;
jshell> ModQ.mul((short) 3328, (short) 3328)    // 3328 ≡ −1 mod q : que doit-on obtenir ?
jshell> ModQ.sub((short) 0, (short) 1)
jshell> (short) (-1234 >> 15)
jshell> Integer.toBinaryString(-1234 & 0xFFFF)
```

**3.2 — Casser l'invariant.** Dans `mul`, remplace temporairement `csub((short) (acc << 1))` par `(short) (acc << 1)`. **Avant** de relancer les tests, prédis : est-ce que ça casse ? Pour quels a et b, environ ? Puis vérifie. Le test exhaustif te donne le premier couple fautif.

**3.3 — Le simulateur ment, le convertisseur dit vrai.** Remplace tout le corps de `mul` par `return (short) ((a * b) % Q);`, puis :

```bash
mvn -q test -Pexercices -Dtest=ModQTest   # que se passe-t-il ?
mvn -q package -DskipTests                # et là ?
```

Explique la différence. C'est la leçon la plus importante de cette étape pour la suite du projet.

**3.4 — Compter.** Combien d'appels à `csub` coûte une multiplication ? La NTT de l'étape 2.2 fera 896 multiplications par polynôme, et la génération de clés environ une trentaine de NTT et de multiplications de polynômes. Estime l'ordre de grandeur du nombre d'opérations. On le comparera à une mesure réelle au jalon 6.

Remets le code dans son état correct après chaque expérience.

## 4. Questions

1. Pourquoi est-il essentiel que 2q < 32 768 ? Que se passerait-il avec un q de 20 000 ?
2. Le temps d'exécution de ta fonction `mul` dépend-il de a ? De b ? Vérifie en relisant ton code ligne par ligne.
3. Le convertisseur aurait-il accepté `if (x >= Q) x -= Q;` dans `csub` ? Si oui, pourquoi ne l'écrit-on pas quand même ?
4. Douze tours de boucle par multiplication, c'est lent. La réduction de Montgomery fait mieux sur processeur 32 bits. Pourquoi est-elle difficile à utiliser ici ? (Pense à ce dont elle a besoin : un produit complet.)
5. *Question ouverte, pour l'étape 2.6 :* pourquoi la décapsulation renvoie-t-elle une clé pseudo-aléatoire en cas d'échec, au lieu d'un code d'erreur ?

## 5. Une fois terminé

- Note ici tes réponses et ce qui t'a surpris (section ci-dessous).
- Retire `@Tag("exercice")` de `ModQTest` : les tests rejoignent alors la CI et protégeront ce code pour la suite.
- Compare avec `docs/corriges/etape-2.1.md` : il existe d'autres écritures correctes.

### Mes notes

Question 1 : si 2q > 32768 alors on peut avoir des dépassement de short signés dans les calculs impliquant des additions entre nombres allant de [0, q[ puisque   l'intervalle serait sur [0, 2q[ donc un dépassement de short signé pour certaine valuer . Ce que l'on observerai avec q = 20000.

Question 2: a priori, non, il y a 24 csub quoi qu'il arrive même avec des valeurs de bits à 0 pour b - j'imagine qu'il s'agit d'une précaution contre le SPA.

Question 3: Oui, il aurait accepté mais on n'aurait une différence du nombre d'opération effectué pouvant être exploité (SPA)

Question 4: Un produit complet avec q = 3329 engendrait un dépassement de short signé, nous sommes contraint en absence de int de passer par une approche plus lente mais engendrant des résultat intermédiaire pouvant être contenu dans un short 
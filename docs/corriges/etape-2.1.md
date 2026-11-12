# Corrigé — Étape 2.1 (arithmétique modulo q)

> ⚠️ **À n'ouvrir qu'après avoir essayé.** Le carnet propose des indices progressifs : `docs/carnet/etape-2.1-arithmetique-modulaire.md`.
>
> Corrigé vérifié : les 4 tests exhaustifs de `ModQTest` passent, et le code est accepté par le convertisseur Java Card 3.0.5.

## Trou A — `csub`

```java
short t = (short) (x - Q);
short mask = (short) (t >> 15);
return (short) (t + (short) (Q & mask));
```

| Cas | t | mask | Q & mask | Résultat |
|---|---|---|---|---|
| x = 3 400 (≥ q) | 71 | `0x0000` | 0 | 71 ✔ |
| x = 100 (< q) | −3 229 | `0xFFFF` | 3 329 | 100 ✔ |

Les deux branches exécutent exactement les mêmes instructions : seule la valeur du masque change.

**Pourquoi tous ces `(short)` ?** En Java, `x - Q`, `t >> 15` ou `Q & mask` sont calculés en `int`. Le convertisseur Java Card accepte un calcul intermédiaire `int` s'il peut prouver que le résultat ramené sur 16 bits est le même que si tout avait été fait sur 16 bits. Caster à chaque étape lève toute ambiguïté.

## Trou B — `sub`

```java
return csub((short) (a - b + Q));
```

a − b ∈ (−q, q), donc a − b + q ∈ (0, 2q) : c'est le domaine d'entrée de `csub`. Ajouter q ne change pas la valeur modulo q.

## Trou C — corps de `mul`

```java
acc = csub((short) (acc << 1));
short mask = (short) (-((short) ((short) (b >> i) & 1)));
acc = add(acc, (short) (a & mask));
```

- **Ligne 1** : acc ∈ [0, q), donc 2·acc ∈ [0, 2q) → `csub`.
- **Ligne 2** : `(b >> i) & 1` est le bit i ; sa négation vaut 0 ou −1 = `0xFFFF`.
- **Ligne 3** : on ajoute **toujours** quelque chose : a ou 0.

Variante équivalente pour la ligne 1 : `acc = add(acc, acc);`.

## Réponses aux expériences

**3.1** — `mul(3328, 3328)` = 1, puisque (−1)² = 1. `sub(0, 1)` = 3328.

**3.2** — Ça casse, et bien avant tout débordement 16 bits. Sans réduction au doublement, acc peut dépasser 2q. Or `csub`, appelé par `add`, ne soustrait q **qu'une seule fois** : son domaine d'entrée [0, 2q) n'est plus respecté et le résultat sort de [0, q). Premier couple fautif : `mul(4, 1665)` = 3331 au lieu de 2. 1665 = 011010000001₂ : les six zéros consécutifs laissent acc doubler jusqu'à 3328, le dernier doublement donne 6656, puis `add(6656, 4)` = `csub(6660)` = 3331. Le débordement au-delà de 32 767 n'arrive que plus tard, pour des valeurs plus grandes. Leçon : on casse le **contrat d'une fonction** (son domaine d'entrée) bien avant de casser le type.

**3.3** — **Les tests passent** : jCardSim tourne sur une JVM, où `a * b` est calculé en `int` 32 bits, donc le résultat est juste. **La conversion échoue** : `a * b` est un intermédiaire `int` dont les 16 bits de poids faible ne suffisent pas à calculer le reste. Sur une vraie carte, ce code n'existerait même pas. Le simulateur valide l'algorithme ; seul le convertisseur valide le code pour la carte.

**3.4** — Par multiplication : 12 tours × (1 `csub` pour doubler + 1 pour `add`) = 24 `csub`, plus les décalages et masques, soit environ 150 à 200 instructions de la machine virtuelle. Une NTT (896 multiplications) en coûte donc environ 150 000. Sur une carte qui exécute de l'ordre de quelques centaines de milliers d'instructions par seconde, c'est déjà presque une seconde par NTT. **La performance sera un vrai sujet**, et c'est exactement ce qu'on veut mesurer au jalon 6.

## Réponses aux questions

1. Toutes les valeurs intermédiaires sont < 2q. Si 2q dépassait 32 767, une addition de deux coefficients déborderait le `short` et deviendrait négative. Avec q = 20 000, `add` serait faux.
2. Ni l'un ni l'autre : le nombre de tours est fixe (12) et chaque tour exécute les mêmes instructions quelles que soient les valeurs. Nuance honnête : le temps constant au niveau du code source ne garantit pas le temps constant au niveau du matériel (cache, implémentation de la machine virtuelle). Sur une vraie carte, cela se vérifie par mesure.
3. Oui, le convertisseur l'accepte : c'est du Java Card valide. On ne l'écrit pas parce que le branchement dépend d'une valeur secrète et fuit par la consommation électrique (SPA).
4. Montgomery calcule `a·b·R⁻¹ mod q` à partir du produit complet `a·b` (24 bits) et de sa moitié haute. Sans multiplication 16 × 16 → 32 bits, il faut émuler ce produit, ce qui coûte à peu près autant que notre méthode. Une piste pour plus tard : découper en blocs de 6 bits, dont les produits partiels tiennent sur 12 bits.
5. Réponse à l'étape 2.6.

# 🔐 Attaque par fautes sur le DES

![Python](https://img.shields.io/badge/Python-3.x-blue)
![DES](https://img.shields.io/badge/Cryptographie-DES-red)
![Status](https://img.shields.io/badge/Status-Terminé-green)

## Description

Implémentation complète d'une **attaque par fautes** sur le **DES**
dans le cadre du cours de Calcul Sécurisé — M2 Cryptographie.

## Résultat

| Donnée | Valeur |
|--------|--------|
| Message clair | 86 67 A7 0B 08 E6 5B 61 |
| Chiffré juste | 61 D5 83 36 BF D4 83 B0 |
| **Clé trouvée** | **FE 76 5D 01 D0 54 9E 20** |

## Structure du projet

    calcul-securise-DES/
    ├── data/
    │   └── donnees.txt
    ├── notebooks/
    │   └── analyse_DES.ipynb
    ├── src/
    │   ├── des.py
    │   ├── attaque.py
    │   └── retrouver_cle.py
    └── README.md

## Utilisation

    python src/retrouver_cle.py

## Principe de l'attaque

    32 chiffrés faux (fautes sur R15)
             ↓
    Extraction R15 et R16
             ↓
    Attaque sur 8 boîtes S → K16 (48 bits)
             ↓
    Inversion PC-2 → 56 bits partiels
             ↓
    Force brute 256 essais
             ↓
    Clé : FE 76 5D 01 D0 54 9E 20 ✅

## Auteur

**Diaw Papa Amadou** — M2 Cryptographie et Algèbre Appliquée

Université de Versailles Saint-Quentin-en-Yvelines
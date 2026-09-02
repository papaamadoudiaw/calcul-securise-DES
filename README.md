# 🔐 Attaque par fautes sur le DES

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Cryptographie](https://img.shields.io/badge/Cryptographie-DES-red)
![Status](https://img.shields.io/badge/Status-Terminé-green)

## 📋 Description

Implémentation complète d'une **attaque par fautes** sur l'algorithme
**DES (Data Encryption Standard)** dans le cadre du cours de
Calcul Sécurisé — M2 Cryptographie et Algèbre Appliquée.

## 🎯 Résultat

| Donnée | Valeur |
|--------|--------|
| Message clair | `86 67 A7 0B 08 E6 5B 61` |
| Chiffré juste | `61 D5 83 36 BF D4 83 B0` |
| **Clé trouvée** | **`FE 76 5D 01 D0 54 9E 20`** |

## 📁 Structure

calcul-securise-DES/
├── data/
│ └── donnees.txt # Message clair + chiffrés
├── notebooks/
│ └── analyse_DES.ipynb # Notebook principal
├── src/
│ ├── des.py # Implémentation DES
│ ├── attaque.py # Attaque par fautes
│ └── retrouver_cle.py # Retrouver la clé complète
└── README.md


## 🚀 Utilisation

```bash
# Lancer l'attaque complète
python src/retrouver_cle.py

# Lancer le notebook
jupyter lab
```

## 📊 Principe de l'attaque

32 chiffrés faux (fautes sur R15)
↓
Extraction R15* et R16*
↓
Attaque sur 8 boîtes S → K16 (48 bits)
↓
Inversion PC-2 → 56 bits partiels
↓
Force brute 2^8 = 256 essais
↓
✅ Clé complète : FE 76 5D 01 D0 54 9E 20


## 📚 Algorithme DES

Le DES chiffre un bloc de **64 bits** avec une clé de **56 bits** sur **16 tours de Feistel**.

Chaque tour utilise une sous-clé de **48 bits** générée depuis la clé principale.

## 👨‍💻 Auteur

**Diaw Papa Amadou** — M2 Cryptographie et Algèbre Appliquée

Université de Versailles Saint-Quentin-en-Yvelines


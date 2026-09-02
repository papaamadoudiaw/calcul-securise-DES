# 🔐 Attaque par fautes sur le DES

Implémentation complète d'une **attaque par fautes** sur l'algorithme DES dans le cadre du cours de Calcul Sécurisé — M2 Cryptographie et Algèbre Appliquée.

## 🎯 Résultat obtenu

| Donnée | Valeur |
|--------|--------|
| Message clair | `86 67 A7 0B 08 E6 5B 61` |
| Chiffré juste | `61 D5 83 36 BF D4 83 B0` |
| **Clé trouvée** | **`FE 76 5D 01 D0 54 9E 20`** |

## 📁 Structure du projet

| Fichier | Description |
|---------|-------------|
| `src/des.py` | Implémentation complète du DES |
| `src/attaque.py` | Attaque par fautes sur les boîtes S |
| `src/retrouver_cle.py` | Retrouver la clé complète |
| `notebooks/analyse_DES.ipynb` | Notebook principal |
| `data/donnees.txt` | Message clair et chiffrés |

## 🚀 Utilisation

### Lancer l'attaque complète

```bash
python src/retrouver_cle.py
```

### Lancer le notebook

```bash
jupyter lab
```

## 📊 Principe de l'attaque

| Étape | Description |
|-------|-------------|
| 1 | Extraction de R15 et R16 depuis les chiffrés |
| 2 | Attaque sur les 8 boîtes S → K16 (48 bits) |
| 3 | Inversion PC-2 → 56 bits partiels |
| 4 | Force brute 2^8 = 256 essais |
| 5 | Clé complète : `FE 76 5D 01 D0 54 9E 20` ✅ |

## 🛠️ Prérequis

- Python 3.x
- Jupyter Lab

## 👨‍💻 Auteur

**Diaw Papa Amadou** — M2 Cryptographie et Algèbre Appliquée

Université de Versailles Saint-Quentin-en-Yvelines

[![GitHub](https://img.shields.io/badge/GitHub-papaamadoudiaw-black?logo=github)](https://github.com/papaamadoudiaw)
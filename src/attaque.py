# ===================================================
# attaque.py — Attaque par fautes sur le DES
# Auteur : Diaw Papa Amadou
# M2 Cryptographie — Calcul Sécurisé
# ===================================================

from des import (int_vers_bits, bits_vers_int, permuter,
                 hex_vers_bits, expansion_E, calculer_sortie_S,
                 IP, P, PC2)


def extraire_R15_R16(chiffre_hex):
    """
    Depuis un chiffré, extrait R15 et R16
    
    Structure du dernier tour :
        L16 = R15
        R16 = L15 ⊕ F(R15, K16)
        C   = IP_INV(R16 + L16)
    
    Donc IP(C) = R16 + L16
    → R16 = IP(C)[:32]
    → R15 = L16 = IP(C)[32:]
    """
    bits     = hex_vers_bits(chiffre_hex)
    apres_IP = permuter(bits, IP)
    R16      = apres_IP[:32]
    R15      = apres_IP[32:]
    return R15, R16


def attaque_une_boite_S(numero_S, R15, R15_etoile, R16, R16_etoile):
    """
    Attaque sur la boîte S numéro numero_S (0 à 7)
    
    Principe :
        R16 ⊕ R16* = F(R15, K16) ⊕ F(R15*, K16)
    
    Pour chaque candidat k (0 à 63) :
        - Calculer diff des sorties Si avec k
        - Comparer avec différence observée dans R16
        - Si différent → éliminer k
    
    Retourne : ensemble des candidats qui survivent
    """
    # Expansion de R15 et R15*
    R15_exp  = expansion_E(R15)
    R15e_exp = expansion_E(R15_etoile)

    # Extraire les 6 bits pour la boîte S i
    debut      = numero_S * 6
    R15_6bits  = R15_exp [debut : debut+6]
    R15e_6bits = R15e_exp[debut : debut+6]

    # Inverser P pour isoler la contribution de Si
    P_INV = [0] * 32
    for j in range(32):
        P_INV[P[j]-1] = j

    positions_Si = [P_INV[numero_S*4 + j] for j in range(4)]

    # Différence observée dans R16
    diff_R16 = [R16[j] ^ R16_etoile[j] for j in range(32)]
    diff_Si  = [diff_R16[positions_Si[j]] for j in range(4)]

    # Tester les 64 candidats
    candidats = set(range(64))

    for k in range(64):
        k_bits   = int_vers_bits(k, 6)
        entree_1 = [R15_6bits[j]  ^ k_bits[j] for j in range(6)]
        entree_2 = [R15e_6bits[j] ^ k_bits[j] for j in range(6)]

        sortie_1  = calculer_sortie_S(entree_1, numero_S)
        sortie_2  = calculer_sortie_S(entree_2, numero_S)
        diff_calc = [sortie_1[j] ^ sortie_2[j] for j in range(4)]

        if diff_calc != diff_Si:
            candidats.discard(k)

    return candidats


def attaque_complete(chiffre_juste, chiffres_faux):
    """
    Attaque par fautes complète sur les 8 boîtes S
    Retourne K16 (48 bits)
    """
    print("=== Attaque par fautes sur le DES ===\n")

    # Extraire R15 et R16 depuis le chiffré juste
    R15, R16 = extraire_R15_R16(chiffre_juste)

    # Initialiser candidats
    candidats = [set(range(64)) for _ in range(8)]

    # Pour chaque chiffré faux
    for idx, chiffre_faux in enumerate(chiffres_faux):
        R15_f, R16_f = extraire_R15_R16(chiffre_faux)

        # Ignorer les fautes nulles
        if R15_f == R15:
            continue

        # Attaquer chaque boîte S
        for i in range(8):
            nouveaux     = attaque_une_boite_S(i, R15, R15_f, R16, R16_f)
            candidats[i] = candidats[i] & nouveaux

        nb = [len(candidats[i]) for i in range(8)]
        print(f"Chiffré {idx+1:2d} : candidats = {nb}")

    # Résultats
    print("\n=== Résultats par boîte S ===")
    K16_bits    = []
    valeurs_K16 = []

    for i in range(8):
        valeur = list(candidats[i])
        print(f"S{i+1} : {len(candidats[i])} candidat(s) → {valeur}")
        v = valeur[0]
        valeurs_K16.append(v)
        K16_bits += int_vers_bits(v, 6)

    print(f"\n✅ K16 trouvé !")
    print(f"Valeurs : {valeurs_K16}")

    return K16_bits, valeurs_K16


if __name__ == "__main__":
    # Données
    chiffre_juste = [0x61, 0xD5, 0x83, 0x36, 0xBF, 0xD4, 0x83, 0xB0]
    chiffres_faux = [
        [0x61, 0x95, 0x97, 0x3E, 0xEF, 0xC4, 0x83, 0xB3],
        [0x21, 0xD5, 0xA3, 0x36, 0xBB, 0x94, 0x8A, 0xF1],
        [0x65, 0x55, 0xC2, 0x26, 0xBE, 0xF4, 0x83, 0xB0],
        [0x63, 0xD0, 0x83, 0x32, 0x3E, 0xD5, 0xC3, 0xA4],
        [0x61, 0xC5, 0x83, 0x71, 0xBF, 0xC4, 0x83, 0xB2],
        [0x21, 0xD5, 0x8B, 0x37, 0xBF, 0x90, 0x8B, 0xB1],
        [0x65, 0xF5, 0xC2, 0x36, 0xBF, 0xF4, 0x93, 0xF0],
        [0xF5, 0xD4, 0x83, 0x26, 0x3E, 0xD4, 0x87, 0xB4],
        [0x61, 0x84, 0x83, 0x74, 0xAF, 0xD5, 0x83, 0x24],
        [0x60, 0x95, 0x8F, 0x37, 0xAF, 0xD0, 0x81, 0xB0],
        [0x61, 0xF5, 0x93, 0x36, 0xBF, 0xDC, 0x93, 0xF1],
        [0xF1, 0xD5, 0x82, 0x26, 0x9B, 0xD4, 0xC6, 0xF0],
        [0x61, 0xD1, 0x83, 0xA2, 0xBE, 0xD5, 0x87, 0x20],
        [0x60, 0x85, 0x85, 0x76, 0xAF, 0xD4, 0x81, 0xB0],
        [0x61, 0xDD, 0x93, 0x37, 0xBF, 0xCC, 0x83, 0xB1],
        [0x05, 0xD5, 0xD3, 0x36, 0x9B, 0x94, 0x93, 0xB1],
        [0x75, 0xD4, 0xC3, 0xB6, 0xBF, 0xD4, 0x83, 0x84],
        [0x61, 0xC0, 0x81, 0x76, 0xBF, 0xD4, 0x03, 0xB4],
        [0x61, 0x9D, 0x87, 0x37, 0xBF, 0xC6, 0x83, 0xB0],
        [0x01, 0xD5, 0x83, 0x37, 0xB7, 0xD0, 0x92, 0xF1],
        [0x71, 0xD5, 0x82, 0x06, 0xBB, 0xD4, 0xC7, 0xD0],
        [0x61, 0xD0, 0x03, 0x26, 0xBF, 0xD4, 0x07, 0xB4],
        [0x61, 0x97, 0x87, 0x76, 0xBF, 0xD7, 0x83, 0xB0],
        [0x28, 0x95, 0x87, 0x36, 0xA7, 0x84, 0x83, 0xB0],
        [0x75, 0xD5, 0x93, 0x16, 0xBB, 0x94, 0x82, 0xB9],
        [0x75, 0xD5, 0x03, 0x26, 0xBF, 0xD4, 0xA7, 0xB0],
        [0x61, 0xD6, 0x83, 0x76, 0xBF, 0x55, 0x83, 0xA0],
        [0x69, 0x85, 0x87, 0x33, 0xFD, 0xD0, 0x83, 0xB0],
        [0x21, 0xD5, 0x93, 0x3F, 0xFB, 0x94, 0x93, 0xB8],
        [0x75, 0xD5, 0xA3, 0x36, 0xBB, 0xD4, 0xA2, 0xF0],
        [0x61, 0x54, 0x83, 0x26, 0xBE, 0x54, 0x83, 0xA0],
        [0x63, 0x84, 0x83, 0x76, 0xAD, 0xD4, 0x83, 0xB4]
    ]

    K16_bits, valeurs_K16 = attaque_complete(chiffre_juste, chiffres_faux)
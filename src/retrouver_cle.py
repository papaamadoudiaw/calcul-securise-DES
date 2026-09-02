# ===================================================
# retrouver_cle.py — Retrouver la clé complète
# Auteur : Diaw Papa Amadou
# M2 Cryptographie — Calcul Sécurisé
# ===================================================

from des import (int_vers_bits, bits_vers_int,
                 DES_chiffrer, PC1, PC2)


def inverser_PC2(K16_bits):
    """
    Retrouve les 56 bits partiels depuis K16 (48 bits)
    en inversant PC-2
    """
    cle_56 = [None] * 56
    for i, pos in enumerate(PC2):
        cle_56[pos-1] = K16_bits[i]
    positions_manquantes = [i+1 for i in range(56) if cle_56[i] is None]
    print(f"Bits connus      : {56 - len(positions_manquantes)}")
    print(f"Bits inconnus    : {len(positions_manquantes)}")
    print(f"Positions manquantes : {positions_manquantes}")
    return cle_56, positions_manquantes


def inverser_PC1(cle_56):
    """
    Reconstruit la clé 64 bits depuis 56 bits
    en inversant PC-1
    """
    cle_64_bits = [0] * 64
    for i, pos in enumerate(PC1):
        cle_64_bits[pos-1] = cle_56[i]
    cle_64_octets = []
    for i in range(8):
        octet_bits = cle_64_bits[i*8 : i*8+8]
        cle_64_octets.append(bits_vers_int(octet_bits))
    return cle_64_octets


def force_brute(cle_56_partielle, positions_manquantes, message, chiffre_juste):
    """
    Force brute sur les 8 bits manquants
    Teste 2^8 = 256 combinaisons
    """
    print("\n=== Force brute sur 8 bits manquants ===")
    print(f"Nombre de combinaisons : 2^8 = 256\n")
    for combinaison in range(256):
        bits_manquants = int_vers_bits(combinaison, 8)
        cle_56 = cle_56_partielle.copy()
        for i, pos in enumerate(positions_manquantes):
            cle_56[pos-1] = bits_manquants[i]
        cle_64 = inverser_PC1(cle_56)
        chiffre_test = DES_chiffrer(message, cle_64)
        if chiffre_test == chiffre_juste:
            print(f"✅ Clé trouvée ! (combinaison {combinaison})")
            return cle_56, cle_64
    print("❌ Aucune clé trouvée !")
    return None, None


def ajouter_parite(cle_64_octets):
    """
    Ajoute les bits de parité à la clé 64 bits
    Chaque octet doit avoir un nombre impair de 1
    """
    print("\n=== Ajout des bits de parité ===\n")
    cle_finale = []
    for i, octet in enumerate(cle_64_octets):
        bits_7     = int_vers_bits(octet, 8)[:7]
        nb_uns     = sum(bits_7)
        bit_parite = 0 if nb_uns % 2 == 1 else 1
        octet_final = bits_vers_int(bits_7 + [bit_parite])
        cle_finale.append(octet_final)
        print(f"Octet {i+1} : {bits_7} + [{bit_parite}] "
              f"= {hex(octet_final).upper()} "
              f"({nb_uns + bit_parite} uns → impair ✅)")
    return cle_finale


if __name__ == "__main__":
    from attaque import attaque_complete

    # Données
    message_clair = [0x86, 0x67, 0xA7, 0x0B, 0x08, 0xE6, 0x5B, 0x61]
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

    # Étape 1 : Attaque → K16
    K16_bits, valeurs_K16 = attaque_complete(chiffre_juste, chiffres_faux)

    # Étape 2 : Inverser PC-2
    print("\n=== Inversion PC-2 ===")
    cle_56_partielle, positions_manquantes = inverser_PC2(K16_bits)

    # Étape 3 : Force brute
    cle_56, cle_64 = force_brute(
        cle_56_partielle,
        positions_manquantes,
        message_clair,
        chiffre_juste
    )

    # Étape 4 : Ajouter parité
    cle_finale = ajouter_parite(cle_64)

    # Résultat final
    print(f"\n{'='*40}")
    print(f"CLÉ FINALE TROUVÉE :")
    print(f"{'='*40}")
    print(f"{' '.join([hex(x)[2:].upper().zfill(2) for x in cle_finale])}")
    print(f"{'='*40}")

    # Vérification
    chiffre_test = DES_chiffrer(message_clair, cle_finale)
    if chiffre_test == chiffre_juste:
        print(f"\n🎉 VÉRIFICATION : SUCCÈS !")
    else:
        print(f"\n❌ VÉRIFICATION : ERREUR !")
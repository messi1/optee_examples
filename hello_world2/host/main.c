/*------------------------------------------------------------*/
/* export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib/engines-3 */
/*------------------------------------------------------------*/

#include <stdio.h>
#include <libp11.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void print_error(const char *message) {
    fprintf(stderr, "%s: %s\n", message, ERR_reason_error_string(ERR_get_error()));
}

int main() {
    PKCS11_CTX *ctx;
    PKCS11_SLOT *slots, *slot;
    unsigned int nslots;

    PKCS11_KEY *keys = NULL;
    unsigned int nkeys;
    EVP_PKEY *pubkey = NULL;
    char *user_pin = "1234";
    char *so_pin = "12345678";  // Security Officer PIN
    char *token_label = "OP-TEE";
    
    int ret = 1;
    
    // PKCS11 Kontext erstellen
    ctx = PKCS11_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Fehler beim Erstellen des PKCS11-Kontexts\n");
        goto cleanup;
    }
    
    // libckteec als PKCS#11-Provider laden
    if (PKCS11_CTX_load(ctx, "/usr/lib/libckteec.so") < 0) {
        fprintf(stderr, "Fehler beim Laden des PKCS11-Moduls: %s\n", 
                ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }
    
    // Verfügbare Slots auflisten
    if (PKCS11_enumerate_slots(ctx, &slots, &nslots) < 0) {
        fprintf(stderr, "Fehler beim Auflisten der Slots: %s\n",
                ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }
    
    // Ersten Slot mit Token verwenden
    slot = PKCS11_find_token(ctx, slots, nslots);
    if (!slot || !slot->token) {
        fprintf(stderr, "Kein Token gefunden\n");
        goto cleanup;
    }
    
    printf("Token Label: %s\n", slot->token->label);
    printf("Token Manufacturer: %s\n", slot->token->manufacturer);
    printf("Token Model: %s\n", slot->token->model);
    printf("Token Serial: %s\n", slot->token->serialnr);
    printf("Token Label: %s\n", slot->token->label);
    
    // OP-TEE erfordert ein spezielles Vorgehen - wir müssen zuerst als SO einloggen
    // und dann den Token initialisieren

    // 1. Versuchen, zuerst als SO einzuloggen
    printf("\nVersuche Login als Security Officer...\n");
    if (PKCS11_login(slot, 1, so_pin) < 0) {
        print_error("SO-Login fehlgeschlagen");
        
        // Falls das SO-Login fehlschlägt, müssen wir möglicherweise den Token initialisieren
        printf("Versuche Token zu initialisieren...\n");
        
        // Zuerst alle Sessions schließen
        PKCS11_release_all_slots(ctx, slots, nslots);
        slots = NULL;
        
        // Slots neu auflisten und Token finden
        if (PKCS11_enumerate_slots(ctx, &slots, &nslots) < 0) {
            print_error("Fehler beim erneuten Auflisten der Slots");
            goto cleanup;
        }
        
        slot = PKCS11_find_token(ctx, slots, nslots);
        if (!slot || !slot->token) {
            fprintf(stderr, "Kein Token gefunden nach Session-Reset\n");
            goto cleanup;
        }
        
        // Token initialisieren mit vorgegebenem SO-PIN
        printf("Initialisiere Token mit SO-PIN...\n");
        if (PKCS11_init_token(slot->token, so_pin, token_label) < 0) {
            print_error("Token-Initialisierung fehlgeschlagen");
            goto cleanup;
        }
        
        // Erneut als SO einloggen
        if (PKCS11_login(slot, 1, so_pin) < 0) {
            print_error("SO-Login nach Token-Initialisierung fehlgeschlagen");
            print_error( "User-PIN-Initialisierung fehlgeschlagen");
            goto cleanup;
        }
    }
    
    printf("SO-Login erfolgreich\n");
    
    // 2. User PIN initialisieren
    printf("Initialisiere User-PIN...\n");
    if (PKCS11_init_pin(slot->token, user_pin) < 0) {
        print_error("User-PIN-Initialisierung fehlgeschlagen");
        // Wir versuchen trotzdem weiterzumachen, falls der PIN bereits gesetzt ist
    } else {
        printf("User-PIN erfolgreich gesetzt\n");
    }
    
    // 3. SO-Logout durchführen
    PKCS11_logout(slot);
    
    // 4. Sessions schließen und neu öffnen
    PKCS11_release_all_slots(ctx, slots, nslots);
    slots = NULL;
    
    if (PKCS11_enumerate_slots(ctx, &slots, &nslots) < 0) {
        print_error("Fehler beim erneuten Auflisten der Slots nach PIN-Initialisierung");
        goto cleanup;
    }
    
    slot = PKCS11_find_token(ctx, slots, nslots);
    if (!slot || !slot->token) {
    	print_error("Kein Token gefunden nach PIN-Initialisierung");
        goto cleanup;
    }
    
    // 5. Jetzt als User einloggen
    printf("\nVersuche Login als User...\n");
    if (PKCS11_login(slot, 0, user_pin) < 0) {
        print_error("User-Login fehlgeschlagen");
        goto cleanup;
    }
    
    printf("User-Login erfolgreich\n");
    
    // Jetzt könnten wir einen Schlüssel generieren
    // ... (hier Code für Schlüsselerzeugung einfügen) ...
    
    printf("\nToken erfolgreich initialisiert und User-Login getestet.\n");
    printf("Sie können nun Schlüssel erzeugen und verwenden.\n");
    
    // Erfolgreich
    ret = 0;
    
        // ID für den Schlüssel generieren
    char id[20];
    memset(id, 0, sizeof(id));
    strcpy((char*)id, "test-key-001");
    
    printf("\nErzeuge RSA-Schlüsselpaar...\n");
    
    // RSA-Schlüsselpaar generieren (Label und ID müssen unique sein)
    pubkey = PKCS11_generate_key(slot->token, 0, 2048, id, (size_t)sizeof(id), "RSA-Testkey");
    if (!pubkey) {
        print_error("Schlüsselgenerierung fehlgeschlagen");
        ret=1;
        goto cleanup;
    }
    
    printf("RSA-Schlüsselpaar erfolgreich erzeugt\n");
    
    // Öffentlichen Schlüssel extrahieren
    const RSA *rsa_key = EVP_PKEY_get0_RSA(pubkey);
    if (!rsa_key) {
        fprintf(stderr, "Konnte RSA-Schlüssel nicht extrahieren\n");
        goto cleanup;
    }
    
    // Öffentlichen Schlüssel exportieren
    BIO *bio = BIO_new(BIO_s_mem());
    	if (!bio) {
    	fprintf(stderr, "Fehler beim Erstellen des BIO-Objekts\n");
    	goto cleanup;
	}
	
    if (!PEM_write_bio_RSA_PUBKEY(bio, (RSA*)rsa_key)) {
        fprintf(stderr, "Fehler beim Exportieren des öffentlichen Schlüssels\n");
        BIO_free(bio);
        goto cleanup;
    }
    
    // Daten aus BIO auslesen
    char *pem_key = NULL;
    long pem_size = BIO_get_mem_data(bio, &pem_key);
    printf("\nÖffentlicher Schlüssel (PEM-Format):\n%.*s\n", (int)pem_size, pem_key);
    BIO_free(bio);
    
    // Nach allen Schlüsseln suchen
    if (PKCS11_enumerate_keys(slot->token, &keys, &nkeys) < 0) {
        print_error("Fehler beim Auflisten der Schlüssel");
        goto cleanup;
    }
    
    printf("\nGefundene Schlüssel: %d\n", nkeys);
    for (unsigned int i = 0; i < nkeys; i++) {
        printf("Schlüssel %d: %s (ID: ", i, keys[i].label);
        for (unsigned int j = 0; j < keys[i].id_len; j++)
            printf("%02X", keys[i].id[j]);
        printf(")\n");
    }
    
    // Erfolgreich
    ret = 0;
    
cleanup:
    // Aufräumen
    if (pubkey)
        EVP_PKEY_free(pubkey);
    if (slots)
        PKCS11_release_all_slots(ctx, slots, nslots);
    if (ctx) {
        PKCS11_CTX_unload(ctx);
        PKCS11_CTX_free(ctx);
    }
    
    return ret;
}

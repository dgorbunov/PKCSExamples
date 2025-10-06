#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pkcs11.h>

// Token User PIN
#define USER_PIN "0000"

// Slot number
#define SLOT 1973656586

// SoftHSM Module Path
#define MODULE_PATH "/opt/homebrew/opt/softhsm/lib/softhsm/libsofthsm2.so"

// Helper to print hex
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Load the PKCS#11 provider using dlopen
    void *handle = dlopen(MODULE_PATH, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen PKCS provider failed: %s\n", dlerror());
        return 1;
    }

    // PKCS only exposes a single symbol: C_GetFunctionList
    // Lookup C_GetFunctionList symbol, returns a function pointer to CK_FUNCTION_LIST struct
    CK_C_GetFunctionList pGetFunctionList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    if (!pGetFunctionList) {
        fprintf(stderr, "dlsym C_GetFunctionList failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    // CK_FUNCTION_LIST_PTR points to a struct with all PKCS#11 functions
    CK_FUNCTION_LIST_PTR p11;
    // Get the function list
    CK_RV rv = pGetFunctionList(&p11);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", rv);
        dlclose(handle);
        return 1;
    }

    // Initialize the module
    rv = p11->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize failed: 0x%lx\n", rv);
        dlclose(handle);
        return 1;
    }

    // Open a session on the specified slot
    CK_SESSION_HANDLE hSession;
    rv = p11->C_OpenSession(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_OpenSession failed: 0x%lx\n", rv);
        p11->C_Finalize(NULL);
        dlclose(handle);
        return 1;
    }

    // Login to token using the User PIN
    rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN));
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Login failed: 0x%lx\n", rv);
        p11->C_CloseSession(hSession);
        p11->C_Finalize(NULL);
        dlclose(handle);
        return 1;
    }

    // Read input text from stdin
    char inputText[4096];
    printf("Enter text to hash\n> ");
    if (!fgets(inputText, sizeof(inputText), stdin)) {
        fprintf(stderr, "Failed to read input\n");
        return 1;
    }

    // Strip newline
    inputText[strcspn(inputText, "\n")] = 0;

    // Select digest algorithm
    int selectedDigest;
    char inputDigest[10];
    printf("Select digest algorithm\n"
        "1: SHA-256\n"
        "2: SHA-512\n"
        "3: SHA-1\n"
        "4: MD5\n> ");

    // Read selection
    if (!fgets(inputDigest, sizeof(inputDigest), stdin)) {
        fprintf(stderr, "Failed to read digest selection\n");
        return 1;
    }

    // Parse selection
    if (sscanf(inputDigest, "%d", &selectedDigest) != 1) {
        fprintf(stderr, "Invalid input format\n");
        return 1;
    }

    // Set algorithm type based on selection
    CK_MECHANISM mech;
    switch (selectedDigest) {
        case 1:
            mech.mechanism = CKM_SHA256;
            break;
        case 2:
            mech.mechanism = CKM_SHA512;
            break;
        case 3:
            mech.mechanism = CKM_SHA_1;
            break;
        case 4:
            mech.mechanism = CKM_MD5;
            break;
        default:
            fprintf(stderr, "Invalid selection\n");
            return 1;
    }

    // Init digest
    rv = p11->C_DigestInit(hSession, &mech);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_DigestInit failed: 0x%lx\n", rv);
        return 1;
    }

    // Digest must be at least 64 bytes to hold SHA-512
    unsigned char digest[64];
    CK_ULONG digestLen = sizeof(digest);

    // Calculate digest using inputText and selected algorithm
    rv = p11->C_Digest(hSession, (CK_BYTE_PTR)inputText, strlen(inputText), digest, &digestLen);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Digest failed: 0x%lx\n", rv);
        return 1;
    }

    // Print digest
    printf("Digest: ");
    print_hex(digest, digestLen);

    // Cleanup
    p11->C_Logout(hSession);
    p11->C_CloseSession(hSession);
    p11->C_Finalize(NULL);
    dlclose(handle);

    return 0;
}

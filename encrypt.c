#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pkcs11.h>

// Token User PIN
#define USER_PIN "1234"

// Slot number
#define SLOT 1251417337

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


    // Generate AES secret key object 
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    // Generic key template
    CK_ATTRIBUTE keyTemplate[] = {
        { CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY}, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
        { CKA_VALUE_LEN, &(CK_ULONG){32}, sizeof(CK_ULONG) }, // 256-bit AES key
        { CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
        { CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
    };
    CK_OBJECT_HANDLE hKey;
    rv = p11->C_GenerateKey(hSession, &mech, keyTemplate, 5, &hKey);


    // Set up Initialization Vector
    CK_BYTE iv[16] = {0}; 
    CK_MECHANISM encMech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };

    
    // Initialize Encryption Operation
    rv = p11->C_EncryptInit(hSession, &encMech, hKey);
    if (rv != CKR_OK) { 
        fprintf(stderr, "C_EncryptInit failed: 0x%lx\n", rv);
        p11->C_CloseSession(hSession);
        p11->C_Finalize(NULL);
        dlclose(handle);
        return 1;
    }


    CK_BYTE plaintext[] = "Hello, world!";
    CK_BYTE ciphertext[256];
    CK_ULONG ciphertext_len = sizeof(ciphertext);

    rv = p11->C_Encrypt(hSession, plaintext, sizeof(plaintext)-1, ciphertext, &ciphertext_len);
    if (rv != CKR_OK) { 
        fprintf(stderr, "C_Encrypt failed: 0x%lx\n", rv);
        p11->C_CloseSession(hSession);
        p11->C_Finalize(NULL);
        dlclose(handle);
        return 1;
     }

    printf("Ciphertext: ");
    print_hex(ciphertext, ciphertext_len);


    // Cleanup
    p11->C_Logout(hSession);
    p11->C_CloseSession(hSession);
    p11->C_Finalize(NULL);
    dlclose(handle);

    return 0;

}
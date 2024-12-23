// UsbKeyManager.cpp : 정적 라이브러리를 위한 함수를 정의합니다.
//

#include "pch.h"
#include "framework.h"
#include "UsbKeyCryptoValidator.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <comdef.h>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <Wbemidl.h>
#include <chrono>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

const std::string encryptionKey = "zFqAbPwnfV7GTQOX38GDsg0fMLxFuj88rnSRcU1Z4ho=";
const std::string version = "1.00";

using namespace std::chrono;


/**
 * @brief 데이터를 Base64로 인코딩합니다.
 * @param input : 인코딩할 데이터를 담은 바이트 벡터
 * @return std::string : Base64로 인코딩된 문자열
 */
std::string Base64Encode(const std::vector<unsigned char>& input) {
    BIO* bio;
    BIO* b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 줄바꿈 제거
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string base64String(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return base64String;
}

/**
 * @brief Base64로 인코딩된 문자열을 디코딩합니다.
 * @param input : Base64로 인코딩된 문자열
 * @return std::vector<unsigned char> : 디코딩된 바이트 벡터
 */
std::vector<unsigned char> Base64Decode(const std::string& input) {
    BIO* bio, * b64;
    bio = BIO_new_mem_buf(input.data(), input.size());
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 줄바꿈 제거
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> decodedData(input.size());
    int decodedLength = BIO_read(bio, decodedData.data(), input.size());
    BIO_free_all(bio);

    if (decodedLength <= 0) {
        throw std::runtime_error("Base64 디코딩 실패");
    }

    decodedData.resize(decodedLength);
    return decodedData;
}

/**
 * @brief 복호화된 평문에서 시리얼 넘버, 만료 일자, 매칭 모듈, 암호화 버전 정보를 추출합니다.
 * @param plainText : 복호화된 평문 문자열.
 * - 형식: "시리얼넘버 + 만료일자(YYYYMMDD) + 매칭모듈정보".
 * @param extractedSerial : 추출된 시리얼 넘버가 저장될 참조 변수.
 * @param expireDate : 추출된 만료 일자(YYYYMMDD 형식)가 저장될 참조 변수.
 * @param moduleInfo : 추출된 매칭 모듈 정보가 저장될 참조 변수.
 * @param extractedVersion : 추출된 암호화 버전 정보가 저장될 참조 변수.
 * @return bool : 분할이 성공하면 true, 실패하면 false를 리턴
 */
static bool SplitPlainText(std::string& plainText, std::string& extractedSerial, std::string& expireDate, unsigned int& moduleInfo, std::string& extractedVersion)
{
    // 구분자를 사용하여 데이터 분리
    size_t firstDelim = plainText.find('|');
    size_t secondDelim = plainText.find('|', firstDelim + 1);
    size_t thirdDelim = plainText.find('|', secondDelim + 1);

    if (firstDelim == std::string::npos || secondDelim == std::string::npos || thirdDelim == std::string::npos) {
        return false;
    }

    // 각 필드 추출
    try {
        extractedSerial = plainText.substr(0, firstDelim);
        expireDate = plainText.substr(firstDelim + 1, secondDelim - firstDelim - 1);
        std::string moduleInfoStr = plainText.substr(secondDelim + 1, thirdDelim - secondDelim - 1);
        moduleInfo = static_cast<unsigned int>(stoul(moduleInfoStr));
        extractedVersion = plainText.substr(thirdDelim + 1);
    }
    catch (const std::exception&) {
        return false;
    }
    return true;
}


/**
 * @brief AES 알고리즘을 사용해 문자열을 암호화한 후 Base64로 인코딩합니다.
 * @param key : 암호화 키
 * @param data : 암호화할 데이터
 * @return std::string : 암호화된 데이터를 Base64로 인코딩한 문자열
 */
std::string EncryptAES(const std::string& key, const std::string& data) {
    EVP_CIPHER_CTX* ctx;
    unsigned char iv[16] = { 0 };  // IV는 0으로 초기화

    // 암호화를 관리하는 EVP_CIPHER_CTX 객체 초기화
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX 객체 생성 실패");
    }

    // AES 192-bit CBC 모드로 초기화
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.c_str()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES 초기화 실패");
    }

    // 암호화할 데이터를 저장할 버퍼  
    std::vector<unsigned char> encryptedData(data.size() + EVP_MAX_BLOCK_LENGTH);

    // 16바이트 단위로 데이터 암호화
    int outlen = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryptedData.data(), &outlen, reinterpret_cast<const unsigned char*>(data.c_str()), data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("암호화 실패");
    }

    // 남아 있는 16바이트 미만의 데이터는 패딩을 덧붙여 16바이트의 배수가 되도록 크기를 늘린 후 암호화
    int final_outlen = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, encryptedData.data() + outlen, &final_outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("암호화 마무리 실패");
    }

    // 데이터 길이만큼 버퍼의 크기 재조정
    outlen += final_outlen;
    encryptedData.resize(outlen);
    EVP_CIPHER_CTX_free(ctx);

    return Base64Encode(encryptedData);
}

/**
 * @brief Base64로 데이터를 디코딩한 후 AES 알고리즘을 사용해 복호화합니다.
 * @param key : 암호화 키
 * @param decodedData : 복호화할 데이터를 담은 바이트 배열
 * @return std::string : 복호화된 문자열
 */
std::string DecryptAES(const std::string& key, const std::vector<unsigned char>& decodedData) {
    EVP_CIPHER_CTX* ctx;
    unsigned char iv[16] = { 0 };  // IV는 0으로 초기화

    // 복호화를 관리하는 EVP_CIPHER_CTX 객체 초기화
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX 객체 생성 실패");
    }

    // AES 192-bit CBC 모드로 초기화
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.c_str()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES 초기화 실패");
    }

    // 복호화할 데이터를 저장할 버퍼
    std::vector<unsigned char> decryptedData(decodedData.size() + EVP_MAX_BLOCK_LENGTH);

    // 16바이트 단위로 데이터 복호화
    int outlen = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryptedData.data(), &outlen, decodedData.data(), decodedData.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("복호화 실패");
    }

    // 남아 있는 16바이트 미만의 데이터는 패딩을 제거한 후 복호화
    int final_outlen = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedData.data() + outlen, &final_outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("복호화 마무리 실패");
    }

    // 데이터 길이만큼 버퍼의 크기 재조정
    outlen += final_outlen;
    decryptedData.resize(outlen);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(decryptedData.begin(), decryptedData.end());
}


/**
 * @brief USB의 config.ini 파일에 암호화된 키를 저장합니다.
 * @param usbDrivePath : USB 드라이브 경로
 * @param encryptedKey : 저장할 암호화된 키
 * @return bool : 저장이 성공하면 true, 실패하면 false를 리턴
 */
bool SaveEncryptedKeyToIni(const std::string& usbDrivePath, const std::string& encryptedKey) {
    std::string configFilePath = usbDrivePath + "\\config.ini";
    std::ofstream configFile(configFilePath);
    if (!configFile.is_open()) {
        return false;
    }

    configFile << encryptedKey;
    configFile.close();

    return true;
}

/**
 * @brief USB의 config.ini 파일을 읽어 내용을 반환합니다.
 * @param filePath : 읽을 ini 파일의 경로
 * @return std::string : ini 파일의 내용을 담은 문자열. 파일이 없으면 빈 문자열을 반환
 */
std::string ReadIniFile(const std::string& filePath)
{
    std::ifstream iniFile(filePath);
    if (!iniFile.is_open()) {
        return "";
    }

    std::stringstream buffer;
    buffer << iniFile.rdbuf();
    return buffer.str();
}



/**
 * @brief 연결된 USB 장치의 시리얼 넘버와 드라이브 문자를 가져옵니다.
 * @return std::vector<UsbInfo> : 연결된 USB 장치의 정보를 담은 벡터
 * - 각 요소는 USB 시리얼 넘버와 드라이브 문자의 쌍
 */
std::vector<UsbInfo> UsbKeyCryptoValidator::GetUSBInfos() {
    HRESULT hres;

    std::vector<UsbInfo> usbInfoList;

    // COM 초기화
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        _com_error err(hres);
        MessageBox(NULL, err.ErrorMessage(), L"WMI Initialize Error", MB_OK);
        throw std::runtime_error("COM 라이브러리 초기화 실패");
    }

    // 보안 설정 초기화
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        _com_error err(hres);
        MessageBox(NULL, err.ErrorMessage(), L"WMI Initialize Security Error", MB_OK);
        CoUninitialize();
        throw std::runtime_error("보안 초기화 실패");
    }

    // COM 인스턴스 생성
    IWbemLocator* pLoc = NULL; // WMI와 상호작용하는 COM 객체 타입
    hres = CoCreateInstance(CLSID_WbemLocator, 0,
        CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        _com_error err(hres);
        MessageBox(NULL, err.ErrorMessage(), L"WMI Connection Error", MB_OK);
        CoUninitialize();
        throw std::runtime_error("WMI에 연결 실패");
    }

    // WMI 쿼리 실행을 위해 서버와 연결        
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),
        NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        _com_error err(hres);
        MessageBox(NULL, err.ErrorMessage(), L"WMI Server Connection Error", MB_OK);
        pLoc->Release();
        CoUninitialize();
        throw std::runtime_error("WMI 서버에 연결 실패");

    }

    // WMI 쿼리 실행 (연결된 USB 드라이브 조회)
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

    if (FAILED(hres)) {
        _com_error err(hres);
        MessageBox(NULL, err.ErrorMessage(), L"WMI Execute Query Error", MB_OK);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        throw std::runtime_error("WMI 쿼리 실행 실패");
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    std::string serialNumber;
    std::string drivePath;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);   // USB 정보들이 저장된 pEnumerator 순회
        if (FAILED(hr) || uReturn == 0) break;

        VARIANT vtProp;

        // 시리얼 넘버 가져오기
        hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            serialNumber = _bstr_t(vtProp.bstrVal);
            VariantClear(&vtProp);
        }

        // 디스크의 고유 식별자 정보 가져오기
        hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::string deviceID = (const char*)_bstr_t(vtProp.bstrVal);
            VariantClear(&vtProp);

            // DeviceID에 연결된 파티션 정보 쿼리
            IEnumWbemClassObject* pPartitionEnum = NULL;
            std::string query = "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + deviceID + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition";
            hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pPartitionEnum);

            if (SUCCEEDED(hres)) {
                IWbemClassObject* pPartitionObj = NULL;
                while (pPartitionEnum->Next(WBEM_INFINITE, 1, &pPartitionObj, &uReturn) == S_OK) { // 파티션 정보들이 저장된 pPartitionEnum 순회
                    VARIANT vtPartition;
                    hr = pPartitionObj->Get(L"DeviceID", 0, &vtPartition, 0, 0); // 파티션의 DeviceID 속성 Get
                    if (SUCCEEDED(hr)) {
                        std::string partitionID = (const char*)_bstr_t(vtPartition.bstrVal);
                        VariantClear(&vtPartition);

                        // 해당 파티션에 연결된 논리 디스크 탐색
                        IEnumWbemClassObject* pLogicalDiskEnum = NULL;
                        std::string partitionQuery = "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + partitionID + "'} WHERE AssocClass=Win32_LogicalDiskToPartition";
                        hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(partitionQuery.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pLogicalDiskEnum);

                        if (SUCCEEDED(hres)) {
                            IWbemClassObject* pLogicalDiskObj = NULL;
                            while (pLogicalDiskEnum->Next(WBEM_INFINITE, 1, &pLogicalDiskObj, &uReturn) == S_OK) { // 논리 디스크 정보들이 저장된 pLogicalDiskEnum 순회
                                VARIANT vtLogicalDisk;
                                hr = pLogicalDiskObj->Get(L"DeviceID", 0, &vtLogicalDisk, 0, 0); // 논리 디스크의 DeviceID에 드라이브 문자가 저장되어 있다.
                                if (SUCCEEDED(hr)) {
                                    drivePath = _bstr_t(vtLogicalDisk.bstrVal);
                                    VariantClear(&vtLogicalDisk);
                                    pLogicalDiskObj->Release();
                                    break;
                                }
                            }
                            pLogicalDiskEnum->Release();
                        }
                    }
                    pPartitionObj->Release();
                }
                pPartitionEnum->Release();
            }
        }
        pclsObj->Release();

        if (!serialNumber.empty() && !drivePath.empty()) {
            usbInfoList.push_back(UsbInfo(drivePath, serialNumber));
        }
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return usbInfoList;
}

/**
 * @brief 연결된 USB 장치의 시리얼 넘버와 만료 일자, 연결 가능한 모듈의 정보를 암호화 키로 암호화하여 USB에 저장합니다.
 * @param drivePath : 저장할 USB의 드라이브 경로
 * @param expireDate : 만료일자(YYYYMMDD)
 * @param moduleType : USB가 연결 가능한 모듈들을 표현하는 비트 값
 * @return EncryptResult: 암호화를 진행한 드라이브의 시리얼 넘버와 결과를 저장한 구조체
 */
EncryptResult UsbKeyCryptoValidator::UsbKeyEncrypt(const std::string drivePath, const std::string expireDate, const unsigned int moduleType)
{
    // 연결된 USB들의 시리얼 넘버와 드라이브 문자 가져오기
    std::vector<UsbInfo> usbInfos = GetUSBInfos();

    // 암호화할 USB 탐색
    auto iter = find_if(usbInfos.begin(), usbInfos.end(), [drivePath](const UsbInfo& usbInfo) {
        return usbInfo.drivePath == drivePath;
        });

    if (iter == usbInfos.end()) {
        return EncryptResult("", EncryptResult::ENCRYPT_ERROR_USB_NOT_FOUND);
    }

    const UsbInfo& targetUsbInfo = *iter;

    std::string usbDrivePath = targetUsbInfo.drivePath;
    std::string usbSerialNumber = targetUsbInfo.serialNumber;


    std::string plainText = usbSerialNumber + "|" + expireDate + "|" + std::to_string(moduleType) + "|" + version;
    std::string encryptedKey = EncryptAES(encryptionKey, plainText);


    if (SaveEncryptedKeyToIni(usbDrivePath, encryptedKey) == true) {
        return EncryptResult(usbSerialNumber, EncryptResult::ENCRYPT_SUCCESS);
    }
    else {
        return EncryptResult(usbSerialNumber, EncryptResult::ENCRYPT_ERROR_INI_SAVE_FAILED);
    }
}


std::vector<DecryptResult> UsbKeyCryptoValidator::UsbKeyDecrypt(const OptionType moduleType)
{
    // 연결된 USB들의 시리얼 넘버와 드라이브 문자 가져오기
    std::vector<UsbInfo> usbInfos = GetUSBInfos();
    std::vector<DecryptResult> DecryptResults;
    if (usbInfos.empty()) {
        return DecryptResults;
    }

    for (const UsbInfo& _usbInfo : usbInfos) {
        std::string usbSerialNumber = _usbInfo.serialNumber;
        std::string usbDrivePath = _usbInfo.drivePath;

        // USB 내부의 config.ini 파일에서 암호화된 키 읽기
        std::string configFilePath = usbDrivePath + "\\config.ini";
        std::string iniFile = ReadIniFile(configFilePath);
        if (iniFile.empty()) {
            DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_ERROR_KEYFILE_NOT_FOUND));
            continue;
        }

        std::vector<unsigned char> decodedData;
        // ini 파일에서 읽은 암호화된 값을 디코딩 후 복호화
        try {
            decodedData = Base64Decode(iniFile);
        }
        catch (const std::runtime_error& e) {
            DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_ERROR_KEYFILE_BROKEN));
            continue;
        }
        
        try {
            iniFile = DecryptAES(encryptionKey, decodedData);
        }
        catch (const std::runtime_error& e) {
            DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_ERROR_DECRYPTING_FAILED));
            continue;
        }

        // 시리얼넘버, 만료기간, 매칭모듈 정보 추출
        std::string extractedSerial, expireDate, extractedVersion;
        unsigned int moduleInfo;
        if (SplitPlainText(iniFile, extractedSerial, expireDate, moduleInfo, extractedVersion) == false) {
            DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_ERROR_KEYFILE_SPLIT_FAILED));
            continue;
        }

        auto today = format("{:%Y%m%d}", system_clock::now());
        // 만료기간 비교
        if (expireDate < today) {
            DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_ERROR_EXPIRED));
            continue;
        }
        // 버전 비교
        if (version != extractedVersion) {
            // DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_ERROR_VERSION_MISMATCH));
            continue;
        }
        // 모듈타입 비교
        if ((moduleInfo & static_cast<unsigned int>(moduleType)) == 0) {
            DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_ERROR_MODULE_MISMATCH));
            continue;
        }
        // USB 시리얼 넘버 비교
        if (extractedSerial != usbSerialNumber) {
            DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_ERROR_KEYFILE_MISMATCH));
        }
        else {
            DecryptResults.push_back(DecryptResult(usbDrivePath, DecryptResult::DECRYPT_SUCCESS)); // 검사 통과
        }
    }

    return DecryptResults;
}
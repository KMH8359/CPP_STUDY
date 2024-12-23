#pragma once

#include <string>
#include <vector>

// UsbInfo : USB의 드라이브 경로와 시리얼 넘버를 저장하는 구조체
struct UsbInfo
{
    std::string drivePath;                               // 'drivePath' : USB의 드라이브 경로 ex) "E:", "F:", "G:", "H:"
    std::string serialNumber;                            // 'serialNumber' : USB의 시리얼 넘버
};

// EncryptResult: 암호화를 진행한 드라이브의 시리얼 넘버와 결과를 저장한 구조체
struct EncryptResult {

    // ErrorCode: 암호화 결과를 나타내는 열거형 값
    enum ErrorCode {
        ENCRYPT_SUCCESS = 0,                             // 'ENCRYPT_SUCCESS' : 암호화 및 저장 성공.
        ENCRYPT_ERROR_USB_NOT_FOUND = -1,                //'ENCRYPT_ERROR_USB_NOT_FOUND' : 저장할 USB 장치를 찾을 수 없음.
        ENCRYPT_ERROR_INI_SAVE_FAILED = -2               //'ENCRYPT_ERROR_INI_SAVE_FAILED' : INI 파일 저장에 실패함.
    };
    std::string serialNumber;                                 // 'serialNumber' : USB의 시리얼 넘버 
    ErrorCode errorCode;
};

// DecryptResult: 검사를 진행한 드라이브의 경로와 결과를 저장한 구조체
struct DecryptResult {

    // ErrorCode: 복호화 결과를 나타내는 열거형 값
    enum ErrorCode {
        DECRYPT_SUCCESS = 0,                        // 'DECRYPT_SUCCESS' : 복호화 및 검증 성공.
        DECRYPT_ERROR_KEYFILE_NOT_FOUND = -1,       // 'DECRYPT_ERROR_KEYFILE_NOT_FOUND' : USB에서 암호화 파일을 찾을 수 없음.
        DECRYPT_ERROR_KEYFILE_BROKEN = -2,          // 'DECRYPT_ERROR_KEYFILE_BROKEN' : config.ini 파일의 암호화된 키가 손상됨.
        DECRYPT_ERROR_DECRYPTING_FAILED = -3,       // 'DECRYPT_ERROR_DECRYPTING_FAILED' : 키 파일 복호화 실패
        DECRYPT_ERROR_KEYFILE_MISMATCH = -4,       // 'DECRYPT_ERROR_KEYFILE_MISMATCH' : 복호화된 시리얼 넘버와 USB의 시리얼 넘버가 일치하지 않음.       
        DECRYPT_ERROR_KEYFILE_SPLIT_FAILED = -5,    // 'DECRYPT_ERROR_KEYFILE_SPLIT_FAILED' : 복호화된 평문에서 USB 정보, 만료기간, 연결 모듈 정보를 추출하는 것에 실패함.
        DECRYPT_ERROR_MODULE_MISMATCH = -6,         // 'DECRYPT_ERROR_MODULE_MISMATCH' : 복호화된 매칭 모듈 정보와 연결하려는 모듈의 정보가 일치하지 않음.
        DECRYPT_ERROR_EXPIRED = -7                  // 'DECRYPT_ERROR_EXPIRED' : 복호화된 키가 만료됨.
    };
    std::string drivePath;                               // 'drivePath' : USB의 드라이브 경로 ex) "E:", "F:", "G:", "H:"
    ErrorCode errorCode;
};

// OptionType: USB의 매칭 옵션을 나타내는 열거형 값, 둘 이상의 옵션을 USB에 설정하는 것도 가능
enum OptionType {
    OPTION_1 = 0x01,
    OPTION_2 = 0x02,
    OPTION_3 = 0x04,
    OPTION_4 = 0x08,
    OPTION_5 = 0x10,
    OPTION_6 = 0x20,
    OPTION_7 = 0x40,
    OPTION_8 = 0x80,
    OPTION_9 = 0x100,
    OPTION_10 = 0x200,
    OPTION_11 = 0x400,
    OPTION_12 = 0x800
};

namespace UsbKeyCryptoValidator {

    std::vector<UsbInfo> GetUSBInfos();


    EncryptResult UsbKeyEncrypt(const std::string drivePath, const std::string expireDate, const unsigned int moduleType);

    /**
     * @brief 연결된 USB 장치들에 저장된 암호화 파일을 읽고 복호화하여 유효성을 검증합니다.
     * @param moduleType : USB가 연결을 시도하는 모듈의 타입
     * @return std::vector<DecryptResult> : 연결된 모든 USB들의 검사 결과를 저장한 구조체 컨테이너
     * @note 연결된 모든 USB를 대상으로 검사를 수행하며 하나라도 성공할 경우 유효성이 검증된 것으로 간주합니다.
     */
    std::vector<DecryptResult> UsbKeyDecrypt(const OptionType moduleType);
};
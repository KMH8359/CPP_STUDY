#pragma once

#include <string>
#include <vector>

// UsbInfo : USB�� ����̺� ��ο� �ø��� �ѹ��� �����ϴ� ����ü
struct UsbInfo
{
    std::string drivePath;                               // 'drivePath' : USB�� ����̺� ��� ex) "E:", "F:", "G:", "H:"
    std::string serialNumber;                            // 'serialNumber' : USB�� �ø��� �ѹ�
};

// EncryptResult: ��ȣȭ�� ������ ����̺��� �ø��� �ѹ��� ����� ������ ����ü
struct EncryptResult {

    // ErrorCode: ��ȣȭ ����� ��Ÿ���� ������ ��
    enum ErrorCode {
        ENCRYPT_SUCCESS = 0,                             // 'ENCRYPT_SUCCESS' : ��ȣȭ �� ���� ����.
        ENCRYPT_ERROR_USB_NOT_FOUND = -1,                //'ENCRYPT_ERROR_USB_NOT_FOUND' : ������ USB ��ġ�� ã�� �� ����.
        ENCRYPT_ERROR_INI_SAVE_FAILED = -2               //'ENCRYPT_ERROR_INI_SAVE_FAILED' : INI ���� ���忡 ������.
    };
    std::string serialNumber;                                 // 'serialNumber' : USB�� �ø��� �ѹ� 
    ErrorCode errorCode;
};

// DecryptResult: �˻縦 ������ ����̺��� ��ο� ����� ������ ����ü
struct DecryptResult {

    // ErrorCode: ��ȣȭ ����� ��Ÿ���� ������ ��
    enum ErrorCode {
        DECRYPT_SUCCESS = 0,                        // 'DECRYPT_SUCCESS' : ��ȣȭ �� ���� ����.
        DECRYPT_ERROR_KEYFILE_NOT_FOUND = -1,       // 'DECRYPT_ERROR_KEYFILE_NOT_FOUND' : USB���� ��ȣȭ ������ ã�� �� ����.
        DECRYPT_ERROR_KEYFILE_BROKEN = -2,          // 'DECRYPT_ERROR_KEYFILE_BROKEN' : config.ini ������ ��ȣȭ�� Ű�� �ջ��.
        DECRYPT_ERROR_DECRYPTING_FAILED = -3,       // 'DECRYPT_ERROR_DECRYPTING_FAILED' : Ű ���� ��ȣȭ ����
        DECRYPT_ERROR_KEYFILE_MISMATCH = -4,       // 'DECRYPT_ERROR_KEYFILE_MISMATCH' : ��ȣȭ�� �ø��� �ѹ��� USB�� �ø��� �ѹ��� ��ġ���� ����.       
        DECRYPT_ERROR_KEYFILE_SPLIT_FAILED = -5,    // 'DECRYPT_ERROR_KEYFILE_SPLIT_FAILED' : ��ȣȭ�� �򹮿��� USB ����, ����Ⱓ, ���� ��� ������ �����ϴ� �Ϳ� ������.
        DECRYPT_ERROR_MODULE_MISMATCH = -6,         // 'DECRYPT_ERROR_MODULE_MISMATCH' : ��ȣȭ�� ��Ī ��� ������ �����Ϸ��� ����� ������ ��ġ���� ����.
        DECRYPT_ERROR_EXPIRED = -7                  // 'DECRYPT_ERROR_EXPIRED' : ��ȣȭ�� Ű�� �����.
    };
    std::string drivePath;                               // 'drivePath' : USB�� ����̺� ��� ex) "E:", "F:", "G:", "H:"
    ErrorCode errorCode;
};

// OptionType: USB�� ��Ī �ɼ��� ��Ÿ���� ������ ��, �� �̻��� �ɼ��� USB�� �����ϴ� �͵� ����
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
     * @brief ����� USB ��ġ�鿡 ����� ��ȣȭ ������ �а� ��ȣȭ�Ͽ� ��ȿ���� �����մϴ�.
     * @param moduleType : USB�� ������ �õ��ϴ� ����� Ÿ��
     * @return std::vector<DecryptResult> : ����� ��� USB���� �˻� ����� ������ ����ü �����̳�
     * @note ����� ��� USB�� ������� �˻縦 �����ϸ� �ϳ��� ������ ��� ��ȿ���� ������ ������ �����մϴ�.
     */
    std::vector<DecryptResult> UsbKeyDecrypt(const OptionType moduleType);
};
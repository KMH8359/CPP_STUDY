#include "UsbKeyCryptoValidator.h"
#include <unordered_map>
#include <iostream>

using namespace std;
using namespace UsbKeyCryptoValidator;

#pragma comment(lib, "UsbKeyCryptoValidator.lib")

unordered_map<DecryptResult::ErrorCode, string> errorCodeToString = {
	{DecryptResult::DECRYPT_SUCCESS, "DECRYPT_SUCCESS"},
	{DecryptResult::DECRYPT_ERROR_KEYFILE_NOT_FOUND, "DECRYPT_ERROR_KEYFILE_NOT_FOUND"},
	{DecryptResult::DECRYPT_ERROR_KEYFILE_BROKEN, "DECRYPT_ERROR_KEYFILE_BROKEN"},
	{DecryptResult::DECRYPT_ERROR_DECRYPTING_FAILED, "DECRYPT_ERROR_DECRYPTING_FAILED"},
	{DecryptResult::DECRYPT_ERROR_KEYFILE_MISMATCH, "DECRYPT_ERROR_KEYFILE_MISMATCH"},
	{DecryptResult::DECRYPT_ERROR_KEYFILE_SPLIT_FAILED, "DECRYPT_ERROR_KEYFILE_SPLIT_FAILED"},
	{DecryptResult::DECRYPT_ERROR_MODULE_MISMATCH, "DECRYPT_ERROR_MODULE_MISMATCH"},
	{DecryptResult::DECRYPT_ERROR_EXPIRED, "DECRYPT_ERROR_EXPIRED"}
};

int main()
{
	unsigned int _optionType;

	while (true) {

		cout << "검증할 옵션을 입력해주세요(옵션번호: 1~12 정수): ";
		cin >> _optionType;
		if ((_optionType < 1 || 12 < _optionType) || cin.fail()) {
			cin.clear(); 
			cin.ignore(INT_MAX, '\n');
			cout << "잘못된 입력입니다." << endl;
			continue;
		}
		cout << "현재 PC에 연결된 모든 USB 드라이브를 대상으로 유효성 검증을 시작합니다.\n";

		_optionType = 0x0001 << (_optionType - 1);

		vector<DecryptResult> DecryptResults = UsbKeyDecrypt(static_cast<OptionType>(_optionType));

		if (DecryptResults.empty()) {
			cout << "연결된 USB가 없습니다." << endl;
		}

		for (const DecryptResult& result : DecryptResults) {
			cout << result.drivePath << " - " << errorCodeToString[result.errorCode] << endl;

			if (result.errorCode == DecryptResult::DECRYPT_SUCCESS) {
				cout << "유효성 검증 성공" << endl;
			}
			else {
				cout << "유효성 검증 실패" << endl;
			}
		}

	}
}
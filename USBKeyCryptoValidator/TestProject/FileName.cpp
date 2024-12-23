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

		cout << "������ �ɼ��� �Է����ּ���(�ɼǹ�ȣ: 1~12 ����): ";
		cin >> _optionType;
		if ((_optionType < 1 || 12 < _optionType) || cin.fail()) {
			cin.clear(); 
			cin.ignore(INT_MAX, '\n');
			cout << "�߸��� �Է��Դϴ�." << endl;
			continue;
		}
		cout << "���� PC�� ����� ��� USB ����̺긦 ������� ��ȿ�� ������ �����մϴ�.\n";

		_optionType = 0x0001 << (_optionType - 1);

		vector<DecryptResult> DecryptResults = UsbKeyDecrypt(static_cast<OptionType>(_optionType));

		if (DecryptResults.empty()) {
			cout << "����� USB�� �����ϴ�." << endl;
		}

		for (const DecryptResult& result : DecryptResults) {
			cout << result.drivePath << " - " << errorCodeToString[result.errorCode] << endl;

			if (result.errorCode == DecryptResult::DECRYPT_SUCCESS) {
				cout << "��ȿ�� ���� ����" << endl;
			}
			else {
				cout << "��ȿ�� ���� ����" << endl;
			}
		}

	}
}